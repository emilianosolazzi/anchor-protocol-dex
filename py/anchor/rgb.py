"""
RGB client-side validated assets: SingleUseSeal, RGBTransfer, RGBAsset.

FIX #6: single-use seals prevent RGB history double-spend.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bitcoin.core import COutPoint

from ..crypto.keys import KEYSTORE
from ..crypto.transactions import RealTransactionBuilder


@dataclass
class SingleUseSeal:
    """
    FIX #6 -- simulates an RGB single-use seal.
    A single-use seal is a Bitcoin UTXO that can be spent exactly once.
    """
    seal_id: str
    outpoint: str
    closed: bool = False
    seal_txid: Optional[str] = None

    def close(self, closing_txid: str) -> bool:
        if self.closed:
            print(f"  [RGB] Double-spend attempt on seal {self.seal_id[:12]}... "
                  f"(already closed by {self.seal_txid[:12]}...)")
            return False
        self.closed = True
        self.seal_txid = closing_txid
        return True


@dataclass
class RGBTransfer:
    """
    Simulates an RGB asset state transition (off-chain, client-validated).
    FIX #6 -- each transfer is associated with a single-use seal.
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
        secret_hash = hashlib.sha256(secret).hexdigest()
        expected_hash = self.condition.split()[1]
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


class RGBAsset:
    """
    Simulates an RGB asset (e.g. ANCH token) using client-side validation.
    FIX #6: single-use seals prevent RGB history double-spend.
    """

    def __init__(self, ticker: str):
        self.ticker = ticker
        self.asset_id = hashlib.sha256(ticker.encode()).hexdigest()
        self.balances: Dict[str, int] = {}
        self.transfers: Dict[str, RGBTransfer] = {}
        self._seals: Dict[str, str] = {}
        self._history: List[dict] = []
        self._issue_seq: int = 0

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

    def mint(self, to_addr: str, amount: int):
        self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
        self._history.append({
            "type": "mint", "to": to_addr, "amount": amount,
            "ts": time.time(), "seq": self._issue_seq,
        })
        print(f"  [RGB] Minted {amount:,} {self.ticker} to {to_addr[:12]}...")

    def balance_of(self, addr: str) -> int:
        return self.balances.get(addr, 0)

    def save_rgb_state(self):
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

        self._history.append({
            "type": "state_commitment",
            "commitment": commitment.hex(),
            "op_return_txid": op_return_txid,
            "op_return_tx": op_return_hex,
            "ts": time.time(),
        })
        print(f"  [RGB] State commitment anchored: {commitment.hex()[:32]}...")
        print(f"         OP_RETURN TXID: {op_return_txid}")
        print(f"         OP_RETURN TX:   {op_return_hex[:80]}...")
        return commitment

    def create_transfer(
        self,
        from_addr: str,
        to_addr: str,
        amount: int,
        condition: str,
    ) -> RGBTransfer:
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
        self._history.append({
            "type": "transfer_pending", "id": transfer_id[:16],
            "from": from_addr, "to": to_addr, "amount": amount,
            "seal": outpoint[:20], "ts": time.time(),
        })
        print(f"  [RGB] Pending transfer {transfer_id[:16]}... "
              f"{amount:,} {self.ticker} {from_addr[:12]}... -> {to_addr[:12]}... "
              f"[seal: {outpoint[:20]}...]")
        return t

    def settle_transfer(self, transfer_id: str, secret: bytes) -> bool:
        t = self.transfers.get(transfer_id)
        if t is None:
            print(f"  [RGB] Unknown transfer {transfer_id[:16]}...")
            return False
        if t.finalized:
            print(f"  [RGB] Transfer {transfer_id[:16]}... already settled")
            return False
        if t.reveal(secret):
            self.balances[t.to_addr] = self.balances.get(t.to_addr, 0) + t.amount
            del self.transfers[transfer_id]
            self._history.append({
                "type": "transfer_settled", "id": transfer_id[:16],
                "to": t.to_addr, "amount": t.amount, "ts": time.time(),
            })
            seal_info = t.seal.seal_txid[:16] if t.seal else 'n/a'
            print(f"  [RGB] Transfer {transfer_id[:16]}... settled "
                  f"({t.amount:,} {self.ticker} -> {t.to_addr[:12]}...) "
                  f"[seal closed: {seal_info}...]")
            return True
        print(f"  [RGB] Wrong secret for transfer {transfer_id[:16]}...")
        return False

    def refund_transfer(self, transfer_id: str) -> bool:
        t = self.transfers.get(transfer_id)
        if t is None or t.finalized:
            return False
        self.balances[t.from_addr] = self.balances.get(t.from_addr, 0) + t.amount
        del self.transfers[transfer_id]
        if t.seal and t.seal.outpoint in self._seals:
            del self._seals[t.seal.outpoint]
        self._history.append({
            "type": "transfer_refunded", "id": transfer_id[:16], "ts": time.time()
        })
        print(f"  [RGB] Transfer {transfer_id[:16]}... refunded to {t.from_addr[:12]}...")
        return True

    def get_history(self) -> List[dict]:
        return list(self._history)
