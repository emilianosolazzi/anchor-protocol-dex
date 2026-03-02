"""
Flask REST API for the ANCHOR DEX.

Endpoints:
  POST /swap         -- execute a swap
  POST /fund         -- fund a user with BTC or ANCH
  GET  /pool         -- pool reserves
  GET  /quote        -- get a swap quote
  GET  /balances/<u> -- user balances
  GET  /history      -- swap history
  POST /rgb/save     -- anchor RGB state
  GET  /health       -- liveness check
  GET  /anchor/stats -- ANCHOR protocol stats
  GET  /anchor/slots -- list auction slots
  POST /anchor/slot  -- create slot
  POST /anchor/bid   -- bid on slot
"""
from __future__ import annotations

from typing import Optional

from ..persistence import PersistentDEX


def create_flask_app(pdex: Optional[PersistentDEX] = None):
    try:
        from flask import Flask, request, jsonify
    except Exception as exc:
        raise ImportError("Flask is required.  pip install flask") from exc

    app = Flask(__name__)
    _pdex = pdex or PersistentDEX()

    @app.errorhandler(ValueError)
    def handle_value_error(e):
        return jsonify({"error": str(e)}), 400

    @app.errorhandler(TypeError)
    def handle_type_error(e):
        return jsonify({"error": str(e)}), 400

    @app.errorhandler(Exception)
    def handle_error(e):
        return jsonify({"error": str(e)}), 500

    def _safe_int(val, name: str = "value") -> int:
        try:
            return int(val)
        except (ValueError, TypeError):
            raise ValueError(f"'{name}' must be a valid integer, got: {val!r}")

    @app.route('/health', methods=['GET'])
    def api_health():
        return jsonify({"status": "ok", "pool": _pdex.get_pool_info()})

    @app.route('/pool', methods=['GET'])
    def api_pool():
        return jsonify(_pdex.get_pool_info())

    @app.route('/quote', methods=['GET'])
    def api_quote():
        direction = request.args.get('direction', 'BTC_TO_ANCH')
        amount = _safe_int(request.args.get('amount', 0), 'amount')
        if amount <= 0:
            return jsonify({"error": "amount must be positive"}), 400
        try:
            out = _pdex.get_quote(direction, amount)
            return jsonify({"direction": direction, "amount_in": amount,
                            "amount_out": out})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route('/fund', methods=['POST'])
    def api_fund():
        data = request.get_json(silent=True) or {}
        user = data.get('user')
        btc = _safe_int(data.get('btc', 0), 'btc')
        anch = _safe_int(data.get('anch', 0), 'anch')
        if not user or not isinstance(user, str):
            return jsonify({"error": "'user' required (string)"}), 400
        if btc < 0 or anch < 0:
            return jsonify({"error": "amounts must be non-negative"}), 400
        if btc > 0:
            _pdex.fund_btc(user, btc)
        if anch > 0:
            _pdex.fund_anch(user, anch)
        return jsonify({"user": user, "balances": _pdex.get_balances(user)})

    @app.route('/swap', methods=['POST'])
    def api_swap():
        data = request.get_json(silent=True) or {}
        user = data.get('user')
        amount = _safe_int(data.get('amount', 0), 'amount')
        direction = data.get('direction', 'BTC_TO_ANCH')
        if not isinstance(direction, str):
            return jsonify({"error": "'direction' must be a string"}), 400
        direction = direction.upper()

        if not user or not isinstance(user, str):
            return jsonify({"error": "'user' required (string)"}), 400
        if amount <= 0:
            return jsonify({"error": "'amount' must be positive"}), 400

        try:
            if direction in ("BTC_TO_ANCH", "BTC", "B2A"):
                ok = _pdex.swap_btc_to_anch(user, amount)
            else:
                ok = _pdex.swap_anch_to_btc(user, amount)
        except (TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

        if not ok:
            return jsonify({"error": "Swap rejected by covenant"}), 400

        return jsonify({
            "status": "completed",
            "direction": direction,
            "amount": amount,
            "pool": _pdex.get_pool_info(),
            "user_balances": _pdex.get_balances(user),
        })

    @app.route('/balances/<user>', methods=['GET'])
    def api_balances(user: str):
        return jsonify(_pdex.get_balances(user))

    @app.route('/history', methods=['GET'])
    def api_history():
        limit = int(request.args.get('limit', 20))
        return jsonify({"swaps": _pdex.history(limit)})

    @app.route('/rgb/save', methods=['POST'])
    def api_rgb_save():
        c = _pdex.save_rgb_state()
        return jsonify({"commitment": c.hex()})

    # -- ANCHOR protocol endpoints --

    @app.route('/anchor/stats', methods=['GET'])
    def api_anchor_stats():
        return jsonify(_pdex.dex.anchor_protocol.get_stats())

    @app.route('/anchor/balance/<user>', methods=['GET'])
    def api_anchor_balance(user: str):
        return jsonify({
            "user": user,
            "anch_balance": _pdex.dex.anchor_protocol.get_balance(user),
        })

    @app.route('/anchor/slots', methods=['GET'])
    def api_anchor_slots():
        return jsonify({"slots": _pdex.dex.anchor_protocol.auction.list_slots()})

    @app.route('/anchor/slot', methods=['POST'])
    def api_anchor_create_slot():
        data = request.get_json(silent=True) or {}
        bs = _safe_int(data.get('block_start', 0), 'block_start')
        be = _safe_int(data.get('block_end', 0), 'block_end')
        mfr = _safe_int(data.get('min_fee_rate', 5), 'min_fee_rate')
        if bs <= 0 or be <= bs:
            return jsonify({"error": "invalid block range"}), 400
        if mfr < 0:
            return jsonify({"error": "min_fee_rate must be non-negative"}), 400
        slot = _pdex.dex.anchor_protocol.create_slot(bs, be, mfr)
        return jsonify(_pdex.dex.anchor_protocol.auction.get_slot_info(slot.slot_id))

    @app.route('/anchor/bid', methods=['POST'])
    def api_anchor_bid():
        data = request.get_json(silent=True) or {}
        sid = data.get('slot_id', '')
        bidder = data.get('bidder', '')
        amount = _safe_int(data.get('amount', 0), 'amount')
        if not sid or not isinstance(sid, str):
            return jsonify({"error": "'slot_id' required (string)"}), 400
        if not bidder or not isinstance(bidder, str):
            return jsonify({"error": "'bidder' required (string)"}), 400
        if amount <= 0:
            return jsonify({"error": "'amount' must be positive"}), 400
        ok, reason = _pdex.dex.anchor_protocol.bid_on_slot(sid, bidder, amount)
        return jsonify({"success": ok, "reason": reason})

    return app
