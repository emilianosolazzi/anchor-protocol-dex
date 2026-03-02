"""
AnchorProtocol -- orchestrator for the full ANCHOR protocol.

Combines all layers into one clean API:
  - RGBAsset (ANCH token ledger)
  - ClaimRegistry (anti-replay)
  - ProofOfAnchorMinter (proof -> mint pipeline)
  - SlotAuction (fee-market for anchor rights)
  - BRC20Inscription (inscription builder)

Hardening:
  - Unified error handling with structured (ok, reason) returns
  - Registry/minter/auction wired with consistent config
  - Slot lifecycle management: create -> bid -> close -> consume | expire
  - Protocol-wide summary with deep stats
  - Thread-safety note: external callers must serialise mutations
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from typing import Dict, List, Optional, Tuple

from bitcoin.core import CTransaction

from .rgb import RGBAsset
from .truc import AnchorProof
from .verifier import AnchorVerifier, ClaimRegistry
from .brc20 import BRC20Inscription
from .minter import ProofOfAnchorMinter
from .auction import SlotAuction, AnchorSlot, AuctionType, AuctionConfig


class AnchorProtocol:
    """
    Main entry point for external callers.

    Provides a unified facade over the 4-layer ANCHOR stack:

    1. **RGB** -- client-side validated ANCH token ledger
    2. **HTLC** -- atomic swap engine (managed by ProductionDEX)
    3. **Minter** -- proof-of-anchor reward pipeline
    4. **Auction** -- fee-market for anchor slot rights
    """

    def __init__(
        self,
        anch_asset: Optional[RGBAsset] = None,
        auction_config: Optional[AuctionConfig] = None,
        *,
        genesis_bonus: int = 500,
        genesis_count: int = 100,
        max_per_creator: int = 5_000_000,
        cooldown_sec: float = 0.0,
    ):
        self.anch = anch_asset or RGBAsset("ANCH")
        self.registry = ClaimRegistry()
        self.minter = ProofOfAnchorMinter(
            self.anch,
            self.registry,
            genesis_bonus=genesis_bonus,
            genesis_count=genesis_count,
            max_per_creator=max_per_creator,
            cooldown_sec=cooldown_sec,
        )
        self.auction = SlotAuction(self.anch, self.registry, auction_config)
        self.deploy_inscription = BRC20Inscription.deploy()

    # ------------------------------------------------------------------
    # Proof submission
    # ------------------------------------------------------------------
    def submit_anchor_proof(
        self,
        parent_tx: CTransaction,
        child_tx: CTransaction,
        anchor_vout: int,
        block_height: int,
        creator: str,
        fee_rate: int = 0,
    ) -> Tuple[bool, str, int]:
        """
        Submit an anchor proof for verification and minting.

        Returns (success, reason, reward_amount).
        """
        proof = AnchorProof.create(
            parent_tx=parent_tx,
            child_tx=child_tx,
            anchor_vout=anchor_vout,
            block_height=block_height,
            creator=creator,
            fee_rate=fee_rate,
        )
        return self.minter.submit_proof(proof, parent_tx, child_tx)

    # ------------------------------------------------------------------
    # Auction lifecycle
    # ------------------------------------------------------------------
    def create_slot(
        self,
        block_start: int,
        block_end: int,
        min_fee_rate: int = 5,
        auction_type: AuctionType = AuctionType.ENGLISH,
        duration: float = 600.0,
    ) -> AnchorSlot:
        """Create a new auction slot for a block range."""
        return self.auction.create_slot(
            block_start, block_end, min_fee_rate,
            auction_type=auction_type, duration=duration,
        )

    def bid_on_slot(
        self, slot_id: str, bidder: str, anch_amount: int,
    ) -> Tuple[bool, str]:
        """Place a bid on an existing auction slot."""
        return self.auction.place_bid(slot_id, bidder, anch_amount)

    def close_slot(self, slot_id: str) -> Tuple[bool, str]:
        """Close bidding on a slot (winner determined)."""
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
        """
        Consume a slot by providing a valid anchor proof.

        The proof is verified independently of the minter (no reward).
        """
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
        """Expire a slot that has passed its deadline."""
        return self.auction.expire_slot(slot_id)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_balance(self, user: str) -> int:
        """ANCH balance for *user*."""
        return self.anch.balance_of(user)

    def creator_stats(self, creator: str) -> dict:
        """Per-creator minting and claim statistics."""
        return {
            "minting": self.minter.creator_stats(creator),
            "rewards": self.registry.get_rewards(creator),
            "claims": self.registry.creator_claim_count(creator),
        }

    def get_stats(self) -> dict:
        """Protocol-wide summary."""
        return {
            "minter": self.minter.get_stats(),
            "registry": self.registry.summary(),
            "total_claims": self.registry.total_claims(),
            "active_slots": len(self.auction.slots),
            "asset": self.anch.summary(),
            "deploy_inscription": self.deploy_inscription,
        }
