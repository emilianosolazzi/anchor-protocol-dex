"""
Slot auction -- fee-market for anchor-right reservations.

Lifecycle: OPEN -> WON -> CONSUMED | EXPIRED
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .truc import AnchorProof
from .verifier import ClaimRegistry

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rgb import RGBAsset


class SlotState(Enum):
    OPEN = "open"
    WON = "won"
    CONSUMED = "consumed"
    EXPIRED = "expired"


@dataclass
class AnchorSlot:
    slot_id: str
    block_start: int
    block_end: int
    min_fee_rate: int
    state: SlotState = SlotState.OPEN
    highest_bid: int = 0
    winner: Optional[str] = None
    proof_id: Optional[str] = None
    bids: List[dict] = field(default_factory=list)
    created_at: float = 0.0


class SlotAuction:
    """
    Fee-market for anchor-right reservations.

    Lifecycle:
      1. OPEN     -- operator creates slot for a block range; users bid ANCH
      2. WON      -- bidding closes; highest bidder wins the slot
      3. CONSUMED -- winner submits AnchorProof; slot fulfilled; bid returned
      4. EXPIRED  -- deadline passes with no proof; bid forfeited to protocol
    """
    PROTOCOL_ADDRESS = "anchor_protocol_treasury"

    def __init__(self, anch_asset: 'RGBAsset', claim_registry: ClaimRegistry):
        self.slots: Dict[str, AnchorSlot] = {}
        self.anch = anch_asset
        self.registry = claim_registry
        self._slot_seq = 0

    def create_slot(
        self,
        block_start: int,
        block_end: int,
        min_fee_rate: int = 5,
    ) -> AnchorSlot:
        self._slot_seq += 1
        slot_id = hashlib.sha256(
            f"slot:{block_start}:{block_end}:{self._slot_seq}".encode()
        ).hexdigest()
        slot = AnchorSlot(
            slot_id=slot_id,
            block_start=block_start,
            block_end=block_end,
            min_fee_rate=min_fee_rate,
            state=SlotState.OPEN,
            created_at=time.time(),
        )
        self.slots[slot_id] = slot
        print(f"  [SLOT] Created slot {slot_id[:16]}... "
              f"blocks {block_start}-{block_end} min_fee={min_fee_rate} sat/vB")
        return slot

    def place_bid(
        self,
        slot_id: str,
        bidder: str,
        anch_amount: int,
    ) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}, not open"
        if anch_amount <= slot.highest_bid:
            return False, f"bid {anch_amount:,} <= current {slot.highest_bid:,}"
        if self.anch.balance_of(bidder) < anch_amount:
            return False, "insufficient ANCH balance"

        # Refund previous winner
        if slot.winner is not None:
            self.anch.balances[slot.winner] = (
                self.anch.balances.get(slot.winner, 0) + slot.highest_bid
            )
            print(f"  [SLOT] Refunded {slot.highest_bid:,} ANCH to {slot.winner[:12]}...")

        # Escrow new bid
        self.anch.balances[bidder] -= anch_amount
        slot.highest_bid = anch_amount
        slot.winner = bidder
        slot.bids.append({
            "bidder": bidder, "amount": anch_amount, "ts": time.time(),
        })
        print(f"  [SLOT] Bid {anch_amount:,} ANCH by {bidder[:12]}... "
              f"on slot {slot_id[:16]}...")
        return True, "bid accepted"

    def close_bidding(self, slot_id: str) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}"
        if slot.winner is None:
            slot.state = SlotState.EXPIRED
            print(f"  [SLOT] Slot {slot_id[:16]}... expired (no bids)")
            return True, "expired (no bids)"
        slot.state = SlotState.WON
        print(f"  [SLOT] Slot {slot_id[:16]}... won by {slot.winner[:12]}... "
              f"for {slot.highest_bid:,} ANCH")
        return True, "closed"

    def consume_slot(
        self,
        slot_id: str,
        proof: AnchorProof,
    ) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.WON:
            return False, f"slot is {slot.state.value}, not won"
        if proof.creator != slot.winner:
            return False, f"proof creator {proof.creator} != winner {slot.winner}"
        if not (slot.block_start <= proof.block_height <= slot.block_end):
            return False, (f"block {proof.block_height} outside range "
                           f"[{slot.block_start}, {slot.block_end}]")
        if proof.fee_rate < slot.min_fee_rate:
            return False, (f"fee_rate {proof.fee_rate} < min {slot.min_fee_rate}")
        if not proof.verified:
            return False, "proof not verified"

        reward = slot.highest_bid // 10
        ok, reason = self.registry.register_claim(proof, reward_amount=reward)
        if not ok:
            return False, f"claim registration failed: {reason}"

        refund = slot.highest_bid + reward
        self.anch.balances[slot.winner] = (
            self.anch.balances.get(slot.winner, 0) + refund
        )
        slot.state = SlotState.CONSUMED
        slot.proof_id = proof.proof_id
        print(f"  [SLOT] Slot {slot_id[:16]}... consumed by {slot.winner[:12]}...")
        print(f"         Refund: {slot.highest_bid:,} + bonus {reward:,} = "
              f"{refund:,} ANCH")
        return True, "consumed"

    def expire_slot(self, slot_id: str) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.WON:
            return False, f"slot is {slot.state.value}"
        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + slot.highest_bid
        )
        slot.state = SlotState.EXPIRED
        print(f"  [SLOT] Slot {slot_id[:16]}... expired. "
              f"{slot.highest_bid:,} ANCH forfeited to protocol treasury.")
        return True, "expired"

    def get_slot_info(self, slot_id: str) -> Optional[dict]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return None
        return {
            "slot_id": slot.slot_id[:16],
            "blocks": f"{slot.block_start}-{slot.block_end}",
            "state": slot.state.value,
            "highest_bid": slot.highest_bid,
            "winner": slot.winner[:12] if slot.winner else None,
            "min_fee_rate": slot.min_fee_rate,
            "num_bids": len(slot.bids),
        }

    def list_slots(self) -> List[dict]:
        return [self.get_slot_info(sid) for sid in self.slots]
