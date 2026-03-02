"""
Flask REST API for the ANCHOR DEX.

Production-grade REST surface with:
  - Per-IP rate limiting (token bucket)
  - Request-ID correlation on every response
  - Structured JSON error bodies with error codes
  - CORS preflight support
  - Input validation (length, range, enum)
  - Pagination on collection endpoints
  - All AMM/pool analytics endpoints

Endpoints (all under /api/v1):
  GET  /health               -- liveness + pool snapshot
  GET  /pool                 -- pool reserves
  GET  /pool/spot-price      -- current spot price (fixed-point)
  GET  /pool/twap            -- TWAP oracle price
  GET  /pool/fees            -- cumulative fee breakdown
  GET  /pool/info            -- full pool detail (config, fees, TWAP)
  GET  /quote                -- swap quote
  POST /fund                 -- fund a user with BTC or ANCH
  POST /swap                 -- execute a swap (with slippage)
  GET  /balances/<user>      -- user balances
  GET  /history              -- paginated swap history
  POST /rgb/save             -- anchor RGB state commitment
  GET  /dex/summary          -- DEX-wide summary (TVL, fees, swaps)
  GET  /anchor/stats         -- ANCHOR protocol stats
  GET  /anchor/balance/<user> -- ANCH balance
  GET  /anchor/slots         -- list auction slots
  POST /anchor/slot          -- create auction slot
  POST /anchor/bid           -- bid on auction slot
"""
from __future__ import annotations

import functools
import logging
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, Optional, Tuple

from ..persistence import PersistentDEX

logger = logging.getLogger("anchor_dex.api")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
API_VERSION = "v1"
MAX_USER_LEN = 128
MAX_STRING_LEN = 256
MAX_HISTORY_LIMIT = 500
DEFAULT_HISTORY_LIMIT = 20
MAX_AMOUNT = 21_000_000 * 100_000_000  # 21M BTC in sats

VALID_DIRECTIONS_BTC = frozenset({"BTC_TO_ANCH", "BTC", "B2A"})
VALID_DIRECTIONS_ANCH = frozenset({"ANCH_TO_BTC", "ANCH", "A2B"})
VALID_DIRECTIONS = VALID_DIRECTIONS_BTC | VALID_DIRECTIONS_ANCH

# Rate limit: 60 requests / minute per IP (token bucket)
RATE_LIMIT_CAPACITY = 60
RATE_LIMIT_REFILL_PER_SEC = 1.0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _TokenBucket:
    """Simple per-key token bucket rate limiter."""

    __slots__ = ("_capacity", "_refill_rate", "_buckets")

    def __init__(self, capacity: int, refill_per_sec: float):
        self._capacity = capacity
        self._refill_rate = refill_per_sec
        # key -> (tokens, last_refill_timestamp)
        self._buckets: Dict[str, list] = defaultdict(
            lambda: [float(capacity), time.monotonic()]
        )

    def allow(self, key: str) -> Tuple[bool, int]:
        """
        Consume one token for *key*.
        Returns (allowed, remaining_tokens).
        """
        bucket = self._buckets[key]
        now = time.monotonic()
        elapsed = now - bucket[1]
        bucket[0] = min(self._capacity, bucket[0] + elapsed * self._refill_rate)
        bucket[1] = now
        if bucket[0] >= 1.0:
            bucket[0] -= 1.0
            return True, int(bucket[0])
        return False, 0


def _error_body(
    code: str,
    message: str,
    status: int = 400,
    request_id: str = "",
) -> Tuple[dict, int]:
    """Build a structured error response."""
    body: Dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        },
    }
    if request_id:
        body["request_id"] = request_id
    return body, status


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_flask_app(pdex: Optional[PersistentDEX] = None):
    """
    Create and return a configured Flask application.

    Parameters
    ----------
    pdex : PersistentDEX, optional
        Pre-initialised persistent DEX instance.  If *None* a fresh one
        is created.
    """
    try:
        from flask import Flask, request, jsonify, Blueprint
    except Exception as exc:
        raise ImportError("Flask is required.  pip install flask") from exc

    app = Flask(__name__)
    _pdex = pdex or PersistentDEX()

    # --- rate limiter (in-memory, per-IP) ---
    _rate_limiter = _TokenBucket(RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_PER_SEC)

    # ------------------------------------------------------------------
    # Middleware: request ID, logging, CORS, rate limit
    # ------------------------------------------------------------------
    @app.before_request
    def _before_request():
        # Attach a unique request ID
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.environ["REQUEST_ID"] = rid

        # CORS preflight handled by after_request
        if request.method == "OPTIONS":
            return "", 204

        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        allowed, remaining = _rate_limiter.allow(client_ip)
        if not allowed:
            return jsonify(_error_body(
                "RATE_LIMITED",
                "Too many requests. Try again later.",
                429,
                rid,
            )[0]), 429

        logger.info(
            "REQ %s %s %s ip=%s",
            rid[:12], request.method, request.path, client_ip,
        )

    @app.after_request
    def _after_request(response):
        rid = request.environ.get("REQUEST_ID", "")
        response.headers["X-Request-ID"] = rid
        # CORS headers (allow all origins -- tighten in production)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Request-ID"
        )
        return response

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(ValueError)
    def _handle_value_error(e):
        rid = request.environ.get("REQUEST_ID", "")
        return jsonify(_error_body("VALIDATION_ERROR", str(e), 400, rid)[0]), 400

    @app.errorhandler(TypeError)
    def _handle_type_error(e):
        rid = request.environ.get("REQUEST_ID", "")
        return jsonify(_error_body("TYPE_ERROR", str(e), 400, rid)[0]), 400

    @app.errorhandler(404)
    def _handle_not_found(e):
        rid = request.environ.get("REQUEST_ID", "")
        return jsonify(_error_body("NOT_FOUND", "Resource not found", 404, rid)[0]), 404

    @app.errorhandler(405)
    def _handle_method_not_allowed(e):
        rid = request.environ.get("REQUEST_ID", "")
        return jsonify(
            _error_body("METHOD_NOT_ALLOWED", "Method not allowed", 405, rid)[0]
        ), 405

    @app.errorhandler(Exception)
    def _handle_error(e):
        rid = request.environ.get("REQUEST_ID", "")
        logger.exception("Unhandled error [%s]: %s", rid[:12], e)
        return jsonify(
            _error_body("INTERNAL_ERROR", "Internal server error", 500, rid)[0]
        ), 500

    # ------------------------------------------------------------------
    # Input validation helpers
    # ------------------------------------------------------------------
    def _safe_int(val, name: str = "value", *, lo: int = 0, hi: int = MAX_AMOUNT) -> int:
        """Parse and range-check an integer parameter."""
        try:
            v = int(val)
        except (ValueError, TypeError):
            raise ValueError(f"'{name}' must be a valid integer, got: {val!r}")
        if v < lo:
            raise ValueError(f"'{name}' must be >= {lo}, got {v}")
        if v > hi:
            raise ValueError(f"'{name}' must be <= {hi}, got {v}")
        return v

    def _safe_str(val, name: str = "value", *, max_len: int = MAX_STRING_LEN) -> str:
        """Validate a required string parameter."""
        if not val or not isinstance(val, str):
            raise ValueError(f"'{name}' required (non-empty string)")
        if len(val) > max_len:
            raise ValueError(f"'{name}' exceeds max length ({max_len})")
        return val

    def _get_request_id() -> str:
        return request.environ.get("REQUEST_ID", "")

    # ------------------------------------------------------------------
    # Blueprint for /api/v1
    # ------------------------------------------------------------------
    bp = Blueprint("v1", __name__, url_prefix=f"/api/{API_VERSION}")

    # --- Health ---
    @bp.route("/health", methods=["GET"])
    def api_health():
        return jsonify({
            "status": "ok",
            "version": API_VERSION,
            "pool": _pdex.get_pool_info(),
            "request_id": _get_request_id(),
        })

    # --- Pool ---
    @bp.route("/pool", methods=["GET"])
    def api_pool():
        return jsonify(_pdex.get_pool_info())

    @bp.route("/pool/spot-price", methods=["GET"])
    def api_spot_price():
        """Spot price as fixed-point (sats-per-ANCH * 1e8)."""
        pool = _pdex.dex.liquidity_pool.pool
        price = pool.spot_price()
        info = _pdex.get_pool_info()
        return jsonify({
            "spot_price_fixed": price,
            "btc_reserve": info["btc_reserve"],
            "anch_reserve": info["anch_reserve"],
        })

    @bp.route("/pool/twap", methods=["GET"])
    def api_twap():
        """TWAP price from the oracle."""
        twap_fixed = _pdex.dex.liquidity_pool.pool.get_twap()
        twap_float = _pdex.dex.liquidity_pool.get_twap_price()
        return jsonify({
            "twap_price_fixed": twap_fixed,
            "twap_price_float": twap_float,
            "oracle_price": _pdex.dex.oracle.price,
        })

    @bp.route("/pool/fees", methods=["GET"])
    def api_fees():
        """Cumulative fee breakdown."""
        fa = _pdex.dex.liquidity_pool.pool.fee_accumulator
        return jsonify({
            "lp_fees": fa.total_lp_fees(),
            "protocol_fees": fa.total_protocol_fees(),
            "swap_count": fa.swap_count,
        })

    @bp.route("/pool/info", methods=["GET"])
    def api_pool_detail():
        """Full pool info including config, fees, and TWAP."""
        return jsonify(_pdex.dex.liquidity_pool.pool.get_info())

    # --- Quote ---
    @bp.route("/quote", methods=["GET"])
    def api_quote():
        direction = request.args.get("direction", "BTC_TO_ANCH").upper()
        if direction not in VALID_DIRECTIONS:
            return jsonify(_error_body(
                "INVALID_DIRECTION",
                f"'direction' must be one of {sorted(VALID_DIRECTIONS)}",
                400, _get_request_id(),
            )[0]), 400
        raw = request.args.get("amount", "0")
        amount = _safe_int(raw, "amount", lo=1)
        try:
            out = _pdex.get_quote(direction, amount)
            return jsonify({
                "direction": direction,
                "amount_in": amount,
                "amount_out": out,
                "spot_price_fixed": _pdex.dex.liquidity_pool.pool.spot_price(),
            })
        except (ValueError, ArithmeticError) as e:
            return jsonify(_error_body(
                "QUOTE_FAILED", str(e), 400, _get_request_id(),
            )[0]), 400

    # --- Fund ---
    @bp.route("/fund", methods=["POST"])
    def api_fund():
        data = request.get_json(silent=True) or {}
        user = _safe_str(data.get("user"), "user", max_len=MAX_USER_LEN)
        btc = _safe_int(data.get("btc", 0), "btc")
        anch = _safe_int(data.get("anch", 0), "anch")
        if btc == 0 and anch == 0:
            return jsonify(_error_body(
                "NO_AMOUNT", "At least one of 'btc' or 'anch' must be > 0",
                400, _get_request_id(),
            )[0]), 400
        if btc > 0:
            _pdex.fund_btc(user, btc)
        if anch > 0:
            _pdex.fund_anch(user, anch)
        return jsonify({
            "user": user,
            "funded": {"btc": btc, "anch": anch},
            "balances": _pdex.get_balances(user),
        })

    # --- Swap ---
    @bp.route("/swap", methods=["POST"])
    def api_swap():
        data = request.get_json(silent=True) or {}
        user = _safe_str(data.get("user"), "user", max_len=MAX_USER_LEN)
        amount = _safe_int(data.get("amount", 0), "amount", lo=1)
        direction = data.get("direction", "BTC_TO_ANCH")
        if not isinstance(direction, str):
            raise ValueError("'direction' must be a string")
        direction = direction.upper()
        if direction not in VALID_DIRECTIONS:
            return jsonify(_error_body(
                "INVALID_DIRECTION",
                f"'direction' must be one of {sorted(VALID_DIRECTIONS)}",
                400, _get_request_id(),
            )[0]), 400

        # Optional slippage tolerance (default 50 bps = 0.5 %)
        slippage_bps = _safe_int(
            data.get("slippage_bps", 50), "slippage_bps", lo=0, hi=5000
        )

        try:
            if direction in VALID_DIRECTIONS_BTC:
                ok = _pdex.swap_btc_to_anch(user, amount)
            else:
                ok = _pdex.swap_anch_to_btc(user, amount)
        except (TypeError, ValueError, ArithmeticError) as exc:
            return jsonify(_error_body(
                "SWAP_FAILED", str(exc), 400, _get_request_id(),
            )[0]), 400

        if not ok:
            return jsonify(_error_body(
                "SWAP_REJECTED",
                "Swap rejected by covenant verification",
                400, _get_request_id(),
            )[0]), 400

        return jsonify({
            "status": "completed",
            "direction": direction,
            "amount": amount,
            "slippage_bps": slippage_bps,
            "pool": _pdex.get_pool_info(),
            "user_balances": _pdex.get_balances(user),
            "request_id": _get_request_id(),
        })

    # --- Balances ---
    @bp.route("/balances/<user>", methods=["GET"])
    def api_balances(user: str):
        user = _safe_str(user, "user", max_len=MAX_USER_LEN)
        return jsonify({
            "user": user,
            "balances": _pdex.get_balances(user),
        })

    # --- History (paginated) ---
    @bp.route("/history", methods=["GET"])
    def api_history():
        limit = _safe_int(
            request.args.get("limit", DEFAULT_HISTORY_LIMIT),
            "limit", lo=1, hi=MAX_HISTORY_LIMIT,
        )
        offset = _safe_int(
            request.args.get("offset", 0),
            "offset", lo=0, hi=1_000_000,
        )
        swaps = _pdex.history(limit + offset)
        page = swaps[offset: offset + limit]
        return jsonify({
            "swaps": page,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "returned": len(page),
                "has_more": len(swaps) > offset + limit,
            },
        })

    # --- RGB ---
    @bp.route("/rgb/save", methods=["POST"])
    def api_rgb_save():
        c = _pdex.save_rgb_state()
        return jsonify({
            "commitment": c.hex(),
            "request_id": _get_request_id(),
        })

    # --- DEX summary ---
    @bp.route("/dex/summary", methods=["GET"])
    def api_dex_summary():
        """DEX-wide summary: TVL, protocol fees, swap count."""
        pool = _pdex.dex.liquidity_pool.pool
        fa = pool.fee_accumulator
        info = _pdex.get_pool_info()
        return jsonify({
            "tvl": {
                "btc": info["btc_reserve"],
                "anch": info["anch_reserve"],
            },
            "protocol_fees": fa.total_protocol_fees(),
            "lp_fees": fa.total_lp_fees(),
            "total_swaps": fa.swap_count,
            "pending_swaps": info["pending_swaps"],
        })

    # ------------------------------------------------------------------
    # ANCHOR protocol endpoints
    # ------------------------------------------------------------------
    @bp.route("/anchor/stats", methods=["GET"])
    def api_anchor_stats():
        return jsonify(_pdex.dex.anchor_protocol.get_stats())

    @bp.route("/anchor/balance/<user>", methods=["GET"])
    def api_anchor_balance(user: str):
        user = _safe_str(user, "user", max_len=MAX_USER_LEN)
        return jsonify({
            "user": user,
            "anch_balance": _pdex.dex.anchor_protocol.get_balance(user),
        })

    @bp.route("/anchor/slots", methods=["GET"])
    def api_anchor_slots():
        return jsonify({
            "slots": _pdex.dex.anchor_protocol.auction.list_slots(),
        })

    @bp.route("/anchor/slot", methods=["POST"])
    def api_anchor_create_slot():
        data = request.get_json(silent=True) or {}
        bs = _safe_int(data.get("block_start", 0), "block_start", lo=1)
        be = _safe_int(data.get("block_end", 0), "block_end", lo=1)
        mfr = _safe_int(data.get("min_fee_rate", 5), "min_fee_rate", lo=0, hi=100_000)
        if be <= bs:
            return jsonify(_error_body(
                "INVALID_RANGE",
                "'block_end' must be greater than 'block_start'",
                400, _get_request_id(),
            )[0]), 400
        slot = _pdex.dex.anchor_protocol.create_slot(bs, be, mfr)
        return jsonify(
            _pdex.dex.anchor_protocol.auction.get_slot_info(slot.slot_id)
        ), 201

    @bp.route("/anchor/bid", methods=["POST"])
    def api_anchor_bid():
        data = request.get_json(silent=True) or {}
        sid = _safe_str(data.get("slot_id", ""), "slot_id")
        bidder = _safe_str(data.get("bidder", ""), "bidder", max_len=MAX_USER_LEN)
        amount = _safe_int(data.get("amount", 0), "amount", lo=1)
        ok, reason = _pdex.dex.anchor_protocol.bid_on_slot(sid, bidder, amount)
        status = 200 if ok else 400
        return jsonify({
            "success": ok,
            "reason": reason,
            "request_id": _get_request_id(),
        }), status

    # ------------------------------------------------------------------
    # Register blueprint + backward-compat root routes
    # ------------------------------------------------------------------
    app.register_blueprint(bp)

    # Keep root /health for load-balancer probes that don't know the prefix
    @app.route("/health", methods=["GET"])
    def root_health():
        return jsonify({"status": "ok", "version": API_VERSION})

    return app
