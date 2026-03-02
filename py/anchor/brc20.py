"""
BRC-20 inscription builder for on-chain ANCHOR protocol operations.

Follows the BRC-20 standard for deploy / mint / transfer plus
ANCHOR-specific operations (proof / bid / claim / genesis / burn / delegate).

Validation rules (BRC-20 spec):
  - tick: 4-byte UTF-8 ticker
  - amt / max / lim: stringified positive integers
  - op: one of deploy | mint | transfer (BRC-20), or proof | bid | claim |
        genesis | burn | delegate (ANCH extensions)
  - All fields are strings except structured sub-objects

Security:
  - Input sanitisation on every builder (length, type, range)
  - Deterministic JSON key ordering for content-hash reproducibility
  - Immutable inscription dicts (returned as plain dicts -- callers should
    treat them as read-only)
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .truc import AnchorProof


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_TICK_LEN = 4          # BRC-20 spec: 4-byte ticker
MAX_ADDR_LEN = 256        # generous upper bound for address strings
MAX_SUPPLY_CAP = 21_000_000_000_000  # 21 T absolute ceiling
MIN_MINT_LIMIT = 1


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------
def _require_str(val, name: str, *, max_len: int = MAX_ADDR_LEN) -> str:
    if not isinstance(val, str) or not val:
        raise ValueError(f"BRC-20: '{name}' must be a non-empty string")
    if len(val) > max_len:
        raise ValueError(
            f"BRC-20: '{name}' exceeds max length ({max_len})")
    return val


def _require_pos_int(val, name: str, *, hi: int = MAX_SUPPLY_CAP) -> int:
    if not isinstance(val, int) or val <= 0:
        raise ValueError(f"BRC-20: '{name}' must be a positive integer")
    if val > hi:
        raise ValueError(f"BRC-20: '{name}' exceeds maximum ({hi})")
    return val


def _require_non_neg_int(val, name: str, *, hi: int = MAX_SUPPLY_CAP) -> int:
    if not isinstance(val, int) or val < 0:
        raise ValueError(f"BRC-20: '{name}' must be a non-negative integer")
    if val > hi:
        raise ValueError(f"BRC-20: '{name}' exceeds maximum ({hi})")
    return val


def _validate_tick(tick: str) -> str:
    tick = _require_str(tick, "tick", max_len=MAX_TICK_LEN)
    if len(tick.encode("utf-8")) > MAX_TICK_LEN:
        raise ValueError(
            f"BRC-20: tick must be <= {MAX_TICK_LEN} UTF-8 bytes, "
            f"got {len(tick.encode('utf-8'))}"
        )
    return tick


# ---------------------------------------------------------------------------
# Content hash helper
# ---------------------------------------------------------------------------
def inscription_content_id(inscription: dict) -> str:
    """
    SHA-256 of the canonical JSON serialisation.

    This serves as a deterministic content-addressed identifier so that
    identical inscriptions always produce the same hash regardless of
    dict iteration order.
    """
    payload = json.dumps(inscription, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# BRC-20 Inscription builder
# ---------------------------------------------------------------------------
class BRC20Inscription:
    """
    BRC-20 inscription builder for on-chain ANCHOR protocol operations.

    Generates deterministic JSON inscriptions following the BRC-20 standard
    (deploy / mint / transfer) plus ANCHOR-specific operations
    (proof / bid / claim / genesis / burn / delegate).

    Every method validates inputs and returns a plain dict that can be
    JSON-serialised into an Ordinal inscription envelope.
    """

    # ------------------------------------------------------------------
    # Standard BRC-20 ops
    # ------------------------------------------------------------------
    @staticmethod
    def deploy(
        tick: str = "ANCH",
        max_supply: int = 21_000_000,
        mint_limit: int = 1_000,
        *,
        decimals: int = 0,
    ) -> dict:
        """Deploy a new BRC-20 token."""
        tick = _validate_tick(tick)
        _require_pos_int(max_supply, "max_supply")
        _require_pos_int(mint_limit, "mint_limit")
        _require_non_neg_int(decimals, "decimals", hi=18)
        if mint_limit > max_supply:
            raise ValueError("BRC-20: mint_limit cannot exceed max_supply")
        out: dict = {
            "p": "brc-20",
            "op": "deploy",
            "tick": tick,
            "max": str(max_supply),
            "lim": str(mint_limit),
        }
        if decimals > 0:
            out["dec"] = str(decimals)
        return out

    @staticmethod
    def mint(tick: str, to: str, amount: int) -> dict:
        """Mint tokens to an address."""
        tick = _validate_tick(tick)
        _require_str(to, "to")
        _require_pos_int(amount, "amount")
        return {
            "p": "brc-20",
            "op": "mint",
            "tick": tick,
            "amt": str(amount),
            "to": to,
        }

    @staticmethod
    def transfer(tick: str, from_addr: str, to_addr: str, amount: int) -> dict:
        """Transfer tokens between addresses."""
        tick = _validate_tick(tick)
        _require_str(from_addr, "from_addr")
        _require_str(to_addr, "to_addr")
        _require_pos_int(amount, "amount")
        if from_addr == to_addr:
            raise ValueError("BRC-20: self-transfers are not allowed")
        return {
            "p": "brc-20",
            "op": "transfer",
            "tick": tick,
            "amt": str(amount),
            "from": from_addr,
            "to": to_addr,
        }

    # ------------------------------------------------------------------
    # ANCHOR-specific ops
    # ------------------------------------------------------------------
    @staticmethod
    def proof(proof_obj: 'AnchorProof') -> dict:
        """Inscription for a verified anchor proof."""
        if not proof_obj:
            raise ValueError("BRC-20: proof_obj is required")
        return {
            "p": "ANCH",
            "op": "proof",
            "proof_id": proof_obj.proof_id[:16],
            "txid": proof_obj.parent_txid,
            "child": proof_obj.child_txid,
            "block": proof_obj.block_height,
            "creator": proof_obj.creator,
            "sig": proof_obj.signature.hex()[:32],
        }

    @staticmethod
    def bid(
        slot_id: str,
        bidder: str,
        amount: int,
        fee_rate: int,
        *,
        nonce: Optional[str] = None,
    ) -> dict:
        """
        Inscription for a slot auction bid.

        A nonce can be supplied for sealed-bid auctions.
        """
        _require_str(slot_id, "slot_id")
        _require_str(bidder, "bidder")
        _require_pos_int(amount, "amount")
        _require_non_neg_int(fee_rate, "fee_rate", hi=10_000_000)
        out: dict = {
            "p": "ANCH",
            "op": "bid",
            "slot": slot_id[:16],
            "bidder": bidder,
            "amount": str(amount),
            "feerate": str(fee_rate),
        }
        if nonce is not None:
            out["nonce"] = _require_str(nonce, "nonce", max_len=64)
        return out

    @staticmethod
    def claim(proof_id: str, reward: int) -> dict:
        """Inscription for a reward claim against a verified proof."""
        _require_str(proof_id, "proof_id")
        _require_pos_int(reward, "reward")
        return {
            "p": "ANCH",
            "op": "claim",
            "proof_id": proof_id[:16],
            "reward": str(reward),
        }

    @staticmethod
    def genesis(bonus: int, until_block: int) -> dict:
        """Genesis bonus inscription."""
        _require_pos_int(bonus, "bonus")
        _require_pos_int(until_block, "until_block")
        return {
            "p": "ANCH",
            "op": "genesis",
            "bonus": str(bonus),
            "until_block": str(until_block),
        }

    @staticmethod
    def burn(tick: str, from_addr: str, amount: int, *, reason: str = "") -> dict:
        """
        Burn inscription -- permanently destroy tokens.

        Not part of the original BRC-20 spec but widely adopted by
        extensions that need deflationary mechanics.
        """
        tick = _validate_tick(tick)
        _require_str(from_addr, "from_addr")
        _require_pos_int(amount, "amount")
        out: dict = {
            "p": "brc-20",
            "op": "burn",
            "tick": tick,
            "amt": str(amount),
            "from": from_addr,
        }
        if reason:
            out["memo"] = _require_str(reason, "reason", max_len=128)
        return out

    @staticmethod
    def delegate(
        tick: str,
        from_addr: str,
        delegate_addr: str,
        amount: int,
        *,
        expiry_block: int = 0,
    ) -> dict:
        """
        Delegation inscription -- grant spending authority without transfer.

        Useful for DeFi composability (e.g. allowing a pool contract
        to spend tokens on behalf of a user).
        """
        tick = _validate_tick(tick)
        _require_str(from_addr, "from_addr")
        _require_str(delegate_addr, "delegate_addr")
        _require_pos_int(amount, "amount")
        if from_addr == delegate_addr:
            raise ValueError("BRC-20: cannot delegate to self")
        out: dict = {
            "p": "ANCH",
            "op": "delegate",
            "tick": tick,
            "amt": str(amount),
            "from": from_addr,
            "to": delegate_addr,
        }
        if expiry_block > 0:
            out["expiry"] = str(expiry_block)
        return out
