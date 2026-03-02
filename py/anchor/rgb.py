"""
RGB client-side validated assets: SingleUseSeal, RGBTransfer, RGBAsset.

FIX #6: single-use seals prevent RGB history double-spend.

Hardening:
  - Input validation on all public methods (amounts, addresses, lengths)
  - Balance overflow protection (MAX_BALANCE ceiling)
  - Transfer amount limits (dust threshold enforcement)
  - Seal state machine: Open -> Closed (one-way, enforced)
  - Escrow tracking: pending_escrow() shows amounts in-flight
  - History is append-only and capped (ring buffer above MAX_HISTORY)
  - Total supply tracking independent of balance summation
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bitcoin.core import COutPoint

from ..crypto.keys import KEYSTORE
from ..crypto.transactions import RealTransactionBuilder


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_BALANCE = 21_000_000_000_000  # absolute ceiling per address
MAX_HISTORY = 50_000              # cap history entries (oldest dropped)
MAX_ADDR_LEN = 256                # max address length
MIN_TRANSFER_AMOUNT = 1           # dust floor for transfers


# ---------------------------------------------------------------------------
# SingleUseSeal
# ---------------------------------------------------------------------------
@dataclass
class SingleUseSeal:
    """
    FIX #6 -- simulates an RGB single-use seal.
    A single-use seal is a Bitcoin UTXO that can be spent exactly once.

    State machine: Open -> Closed (irreversible).
    """
    seal_id: str
    outpoint: str
    closed: bool = False
    seal_txid: Optional[str] = None

    def close(self, closing_txid: str) -> bool:
        if self.closed:
            logger.info(f"  [RGB] Double-spend attempt on seal {self.seal_id[:12]}... "
                  f"(already closed by {self.seal_txid[:12]}...)")
            return False
        if not closing_txid:
            raise ValueError("closing_txid is required")
        self.closed = True
        self.seal_txid = closing_txid
        return True


# ---------------------------------------------------------------------------
# RGBTransfer
# ---------------------------------------------------------------------------
@dataclass
class RGBTransfer:
    """
    Simulates an RGB asset state transition (off-chain, client-validated).
    FIX #6 -- each transfer is associated with a single-use seal.

    The transfer is in "pending" state until ``reveal()`` is called with
    the correct HTLC secret, which also closes the underlying seal.
    """
    transfer_id: str
    asset_id: str
    from_addr: str
    to_addr: str
    amount: int
    condition: str
    seal: Optional[SingleUseSeal] = None
    revealed_secret: Optional[bytes] = None
    finalized: bool = False

    def reveal(self, secret: bytes) -> bool:
        """
        Reveal the HTLC secret and close the seal.

        Returns True on success, False if the secret doesn't match
        or the seal was already closed.
        """
        if self.finalized:
            return False
        secret_hash = hashlib.sha256(secret).hexdigest()
        # Condition format: "OP_HASH256 <hex> OP_EQUAL"
        parts = self.condition.split()
        if len(parts) < 2:
            return False
        expected_hash = parts[1]
        if secret_hash != expected_hash:
            return False
        if self.seal is not None:
            closing_txid = hashlib.sha256(
                f"settle:{self.transfer_id}:{secret_hash}".encode()
            ).hexdigest()
            if not self.seal.close(closing_txid):
                return False
        self.revealed_secret = secret
        self.finalized = True
        return True


# ---------------------------------------------------------------------------
# RGBAsset
# ---------------------------------------------------------------------------
class RGBAsset:
    """
    Simulates an RGB asset (e.g. ANCH token) using client-side validation.
    FIX #6: single-use seals prevent RGB history double-spend.

    Additional hardening:
      - All amounts validated (positive, within ceiling)
      - Addresses validated (non-empty, length-bounded)
      - Total supply tracked independently
      - Pending escrow queryable
    """

    def __init__(self, ticker: str):
        if not ticker or len(ticker) > 8:
            raise ValueError(f"ticker must be 1-8 chars, got {ticker!r}")
        self.ticker = ticker
        self.asset_id = hashlib.sha256(ticker.encode()).hexdigest()
        self.balances: Dict[str, int] = {}
        self.transfers: Dict[str, RGBTransfer] = {}
        self._seals: Dict[str, str] = {}
        self._history: List[dict] = []
        self._issue_seq: int = 0
        self._total_supply: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _validate_addr(self, addr: str, name: str = "address") -> str:
        if not addr or not isinstance(addr, str):
            raise ValueError(f"[RGB] {name} must be a non-empty string")
        if len(addr) > MAX_ADDR_LEN:
            raise ValueError(
                f"[RGB] {name} exceeds max length ({MAX_ADDR_LEN})"
            )
        return addr

    def _validate_amount(self, amount: int, name: str = "amount") -> int:
        if not isinstance(amount, int) or amount <= 0:
            raise ValueError(f"[RGB] {name} must be a positive integer")
        if amount > MAX_BALANCE:
            raise ValueError(
                f"[RGB] {name} exceeds ceiling ({MAX_BALANCE})"
            )
        return amount

    def _append_history(self, entry: dict):
        self._history.append(entry)
        if len(self._history) > MAX_HISTORY:
            self._history = self._history[-MAX_HISTORY:]

    def _next_outpoint(self, context: str) -> str:
        self._issue_seq += 1
        txid = hashlib.sha256(f"{context}:{self._issue_seq}".encode()).hexdigest()
        return f"{txid}:0"

    def _register_seal(self, outpoint: str, transfer_id: str):
        if outpoint in self._seals:
            raise ValueError(
                f"[RGB] UTXO {outpoint[:20]}... already used as seal "
                f"by transfer {self._seals[outpoint][:12]}..."
            )
        self._seals[outpoint] = transfer_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def total_supply(self) -> int:
        """Total tokens ever minted (does not subtract burns)."""
        return self._total_supply

    @property
    def pending_escrow(self) -> int:
        """Sum of tokens currently locked in pending transfers."""
        return sum(t.amount for t in self.transfers.values())

    def mint(self, to_addr: str, amount: int):
        """Mint new tokens to *to_addr*."""
        self._validate_addr(to_addr, "to_addr")
        self._validate_amount(amount, "mint_amount")
        new_balance = self.balances.get(to_addr, 0) + amount
        if new_balance > MAX_BALANCE:
            raise ValueError(
                f"[RGB] mint would exceed balance ceiling for {to_addr[:12]}..."
            )
        self.balances[to_addr] = new_balance
        self._total_supply += amount
        self._append_history({
            "type": "mint", "to": to_addr, "amount": amount,
            "total_supply": self._total_supply,
            "ts": time.time(), "seq": self._issue_seq,
        })
        logger.info(f"  [RGB] Minted {amount:,} {self.ticker} to {to_addr[:12]}...")

    def balance_of(self, addr: str) -> int:
        return self.balances.get(addr, 0)

    def save_rgb_state(self):
        """Commit the current balance snapshot to an OP_RETURN transaction."""
        payload = json.dumps(self.balances, sort_keys=True).encode()
        commitment = hashlib.sha256(payload).digest()

        mock_outpoint = COutPoint(
            hashlib.sha256(f"rgb-anchor:{self._issue_seq}".encode()).digest(), 0
        )
        change_spk = KEYSTORE.p2wpkh_scriptpubkey("rgb_anchor_wallet")
        op_return_tx = RealTransactionBuilder.build_op_return_tx(
            funding_outpoint=mock_outpoint,
            data=commitment,
            change_scriptpubkey=change_spk,
            change_amount=546,
        )
        op_return_txid = RealTransactionBuilder.txid_hex(op_return_tx)
        op_return_hex = RealTransactionBuilder.serialize_hex(op_return_tx)

        self._append_history({
            "type": "state_commitment",
            "commitment": commitment.hex(),
            "op_return_txid": op_return_txid,
            "op_return_tx": op_return_hex,
            "total_supply": self._total_supply,
            "ts": time.time(),
        })
        logger.info(f"  [RGB] State commitment anchored: {commitment.hex()[:32]}...")
        logger.info(f"         OP_RETURN TXID: {op_return_txid}")
        logger.info(f"         OP_RETURN TX:   {op_return_hex[:80]}...")
        return commitment

    def create_transfer(
        self,
        from_addr: str,
        to_addr: str,
        amount: int,
        condition: str,
    ) -> RGBTransfer:
        """
        Create a new pending RGB transfer with a single-use seal.

        The sender's balance is immediately escrowed; it is credited to
        the recipient on ``settle_transfer()`` or returned on
        ``refund_transfer()``.
        """
        self._validate_addr(from_addr, "from_addr")
        self._validate_addr(to_addr, "to_addr")
        self._validate_amount(amount, "transfer_amount")
        if not condition or not isinstance(condition, str):
            raise ValueError("[RGB] condition must be a non-empty string")

        if self.balances.get(from_addr, 0) < amount:
            raise ValueError(
                f"Insufficient {self.ticker}: "
                f"{self.balances.get(from_addr, 0):,} < {amount:,}"
            )

        transfer_id = hashlib.sha256(
            f"{from_addr}{to_addr}{amount}{time.time()}".encode()
        ).hexdigest()
        outpoint = self._next_outpoint(f"{from_addr}:{transfer_id}")
        seal = SingleUseSeal(
            seal_id=hashlib.sha256(outpoint.encode()).hexdigest(),
            outpoint=outpoint,
        )
        self._register_seal(outpoint, transfer_id)
        self.balances[from_addr] -= amount  # escrow

        t = RGBTransfer(
            transfer_id=transfer_id,
            asset_id=self.asset_id,
            from_addr=from_addr,
            to_addr=to_addr,
            amount=amount,
            condition=condition,
            seal=seal,
        )
        self.transfers[transfer_id] = t
        self._append_history({
            "type": "transfer_pending", "id": transfer_id[:16],
            "from": from_addr, "to": to_addr, "amount": amount,
            "seal": outpoint[:20], "ts": time.time(),
        })
        logger.info(f"  [RGB] Pending transfer {transfer_id[:16]}... "
              f"{amount:,} {self.ticker} {from_addr[:12]}... -> {to_addr[:12]}... "
              f"[seal: {outpoint[:20]}...]")
        return t

    def settle_transfer(self, transfer_id: str, secret: bytes) -> bool:
        """
        Settle a pending transfer by revealing the HTLC secret.

        This closes the single-use seal and credits the recipient.
        """
        t = self.transfers.get(transfer_id)
        if t is None:
            logger.info(f"  [RGB] Unknown transfer {transfer_id[:16]}...")
            return False
        if t.finalized:
            logger.info(f"  [RGB] Transfer {transfer_id[:16]}... already settled")
            return False
        if t.reveal(secret):
            new_balance = self.balances.get(t.to_addr, 0) + t.amount
            if new_balance > MAX_BALANCE:
                # Should never happen in practice, but guard anyway
                logger.info(f"  [RGB] Settlement would exceed balance ceiling")
                return False
            self.balances[t.to_addr] = new_balance
            del self.transfers[transfer_id]
            self._append_history({
                "type": "transfer_settled", "id": transfer_id[:16],
                "to": t.to_addr, "amount": t.amount, "ts": time.time(),
            })
            seal_info = t.seal.seal_txid[:16] if t.seal and t.seal.seal_txid else 'n/a'
            logger.info(f"  [RGB] Transfer {transfer_id[:16]}... settled "
                  f"({t.amount:,} {self.ticker} -> {t.to_addr[:12]}...) "
                  f"[seal closed: {seal_info}...]")
            return True
        logger.info(f"  [RGB] Wrong secret for transfer {transfer_id[:16]}...")
        return False

    def refund_transfer(self, transfer_id: str) -> bool:
        """
        Refund a pending transfer back to the sender.

        Frees the escrow and releases the seal reservation.
        """
        t = self.transfers.get(transfer_id)
        if t is None or t.finalized:
            return False
        self.balances[t.from_addr] = self.balances.get(t.from_addr, 0) + t.amount
        del self.transfers[transfer_id]
        if t.seal and t.seal.outpoint in self._seals:
            del self._seals[t.seal.outpoint]
        self._append_history({
            "type": "transfer_refunded", "id": transfer_id[:16],
            "from": t.from_addr, "amount": t.amount, "ts": time.time(),
        })
        logger.info(f"  [RGB] Transfer {transfer_id[:16]}... refunded to {t.from_addr[:12]}...")
        return True

    def get_history(self, *, limit: int = 100) -> List[dict]:
        """Return most recent history entries (newest first)."""
        return list(reversed(self._history[-limit:]))

    def summary(self) -> dict:
        """Asset-wide summary."""
        return {
            "ticker": self.ticker,
            "asset_id": self.asset_id[:16],
            "total_supply": self._total_supply,
            "holders": len(self.balances),
            "pending_transfers": len(self.transfers),
            "pending_escrow": self.pending_escrow,
            "seals_used": len(self._seals),
        }
