"""
AnchorProtocol -- orchestrator for the full ANCHOR protocol.

Combines all layers into one clean API:
  - RGBAsset (ANCH token ledger)
  - ClaimRegistry (anti-replay)
  - ProofOfAnchorMinter (proof -> mint pipeline)
  - SlotAuction (fee-market for anchor rights)
  - BRC20Inscription (inscription builder)
"""
from __future__ import annotations

from typing import Optional, Tuple

from bitcoin.core import CTransaction

from .rgb import RGBAsset
from .truc import AnchorProof
from .verifier import AnchorVerifier, ClaimRegistry
from .brc20 import BRC20Inscription
from .minter import ProofOfAnchorMinter
from .auction import SlotAuction, AnchorSlot


class AnchorProtocol:
    """Main entry point for external callers."""

    def __init__(self, anch_asset: Optional[RGBAsset] = None):
        self.anch = anch_asset or RGBAsset("ANCH")
        self.registry = ClaimRegistry()
        self.minter = ProofOfAnchorMinter(
            self.anch, self.registry,
            genesis_bonus=500, genesis_count=100,
        )
        self.auction = SlotAuction(self.anch, self.registry)
        self.deploy_inscription = BRC20Inscription.deploy()

    def submit_anchor_proof(
        self,
        parent_tx: CTransaction,
        child_tx: CTransaction,
        anchor_vout: int,
        block_height: int,
        creator: str,
        fee_rate: int = 0,
    ) -> Tuple[bool, str, int]:
        proof = AnchorProof.create(
            parent_tx=parent_tx,
            child_tx=child_tx,
            anchor_vout=anchor_vout,
            block_height=block_height,
            creator=creator,
            fee_rate=fee_rate,
        )
        return self.minter.submit_proof(proof, parent_tx, child_tx)

    def create_slot(self, block_start: int, block_end: int,
                    min_fee_rate: int = 5) -> AnchorSlot:
        return self.auction.create_slot(block_start, block_end, min_fee_rate)

    def bid_on_slot(self, slot_id: str, bidder: str,
                    anch_amount: int) -> Tuple[bool, str]:
        return self.auction.place_bid(slot_id, bidder, anch_amount)

    def close_slot(self, slot_id: str) -> Tuple[bool, str]:
        return self.auction.close_bidding(slot_id)

    def consume_slot(
        self,
        slot_id: str,
        parent_tx: CTransaction,
        child_tx: CTransaction,
        anchor_vout: int,
        block_height: int,
        creator: str,
        fee_rate: int = 0,
    ) -> Tuple[bool, str]:
        proof = AnchorProof.create(
            parent_tx=parent_tx, child_tx=child_tx,
            anchor_vout=anchor_vout, block_height=block_height,
            creator=creator, fee_rate=fee_rate,
        )
        valid, reason = AnchorVerifier.verify(
            proof, parent_tx, child_tx, None
        )
        if not valid:
            return False, reason
        return self.auction.consume_slot(slot_id, proof)

    def expire_slot(self, slot_id: str) -> Tuple[bool, str]:
        return self.auction.expire_slot(slot_id)

    def get_stats(self) -> dict:
        return {
            "minter": self.minter.get_stats(),
            "total_claims": self.registry.total_claims(),
            "active_slots": len(self.auction.slots),
            "deploy_inscription": self.deploy_inscription,
        }

    def get_balance(self, user: str) -> int:
        return self.anch.balance_of(user)
