"""
ProofOfAnchorMinter -- mint ANCH tokens for valid anchor proofs.

Tokenomics:
  - Max supply:       21,000,000 ANCH
  - Per-proof reward:  1,000 ANCH
  - Halving:          every 5,250 proofs
  - Genesis bonus:    first 100 proofs get extra tokens
"""
from __future__ import annotations

import time
from typing import List, Tuple, TYPE_CHECKING

from bitcoin.core import CTransaction

from .truc import AnchorProof
from .verifier import AnchorVerifier, ClaimRegistry
from .brc20 import BRC20Inscription

if TYPE_CHECKING:
    from .rgb import RGBAsset


class ProofOfAnchorMinter:
    MAX_SUPPLY = 21_000_000
    BASE_REWARD = 1_000
    HALVING_INTERVAL = 5_250

    def __init__(
        self,
        anch_asset: 'RGBAsset',
        claim_registry: ClaimRegistry,
        genesis_bonus: int = 500,
        genesis_count: int = 100,
    ):
        self.anch = anch_asset
        self.registry = claim_registry
        self.total_minted: int = 0
        self.proofs_accepted: int = 0
        self.genesis_bonus = genesis_bonus
        self.genesis_count = genesis_count
        self._mint_history: List[dict] = []

    @property
    def remaining_supply(self) -> int:
        return max(0, self.MAX_SUPPLY - self.total_minted)

    @property
    def current_reward(self) -> int:
        era = self.proofs_accepted // self.HALVING_INTERVAL
        reward = self.BASE_REWARD >> era
        return max(1, reward)

    def _compute_reward(self) -> int:
        base = self.current_reward
        if self.proofs_accepted < self.genesis_count:
            base += self.genesis_bonus
        return min(base, self.remaining_supply)

    def submit_proof(
        self,
        proof: AnchorProof,
        parent_tx: CTransaction,
        child_tx: CTransaction,
    ) -> Tuple[bool, str, int]:
        if self.remaining_supply == 0:
            return False, "max supply reached (21M ANCH)", 0

        valid, reason = AnchorVerifier.verify(
            proof, parent_tx, child_tx, self.registry
        )
        if not valid:
            return False, reason, 0

        reward = self._compute_reward()

        ok, claim_reason = self.registry.register_claim(proof, reward_amount=reward)
        if not ok:
            return False, f"claim failed: {claim_reason}", 0

        self.anch.balances[proof.creator] = (
            self.anch.balances.get(proof.creator, 0) + reward
        )
        self.total_minted += reward
        self.proofs_accepted += 1

        inscription = BRC20Inscription.mint("ANCH", proof.creator, reward)

        self._mint_history.append({
            "proof_id": proof.proof_id[:16],
            "creator": proof.creator,
            "reward": reward,
            "total_minted": self.total_minted,
            "proofs_accepted": self.proofs_accepted,
            "inscription": inscription,
            "ts": time.time(),
        })

        print(f"  [PoA] Proof {proof.proof_id[:16]}... verified")
        print(f"         Creator: {proof.creator}")
        print(f"         Reward:  {reward:,} ANCH "
              f"(era {self.proofs_accepted // self.HALVING_INTERVAL}, "
              f"{'GENESIS BONUS' if self.proofs_accepted <= self.genesis_count else 'standard'})")
        print(f"         Minted:  {self.total_minted:,} / {self.MAX_SUPPLY:,} ANCH")
        return True, "minted", reward

    def get_stats(self) -> dict:
        return {
            "max_supply": self.MAX_SUPPLY,
            "total_minted": self.total_minted,
            "remaining": self.remaining_supply,
            "proofs_accepted": self.proofs_accepted,
            "current_reward": self.current_reward,
            "genesis_bonus_remaining": max(0, self.genesis_count - self.proofs_accepted),
            "era": self.proofs_accepted // self.HALVING_INTERVAL,
        }
