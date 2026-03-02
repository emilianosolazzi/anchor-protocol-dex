"""
ProofOfAnchorMinter -- mint ANCH tokens for valid anchor proofs.

Tokenomics:
  - Max supply:       21,000,000 ANCH
  - Per-proof reward:  1,000 ANCH (configurable)
  - Halving:          every 5,250 proofs (configurable)
  - Genesis bonus:    first 100 proofs get extra tokens

Hardening:
  - Overflow-safe reward computation (clamped to remaining supply)
  - Per-creator minting cap (anti-whale)
  - Cooldown between consecutive proofs from same creator
  - Halving floor: reward never drops below 1 ANCH
  - All state mutations are atomic (no partial mints)
  - Mint history capped to prevent unbounded growth
"""
from __future__ import annotations

import time
from typing import Dict, List, Tuple, TYPE_CHECKING

from bitcoin.core import CTransaction

from .truc import AnchorProof
from .verifier import AnchorVerifier, ClaimRegistry
from .brc20 import BRC20Inscription

if TYPE_CHECKING:
    from .rgb import RGBAsset


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_HISTORY = 10_000                  # cap mint history
DEFAULT_MAX_PER_CREATOR = 5_000_000   # no single creator can accumulate > this
DEFAULT_COOLDOWN_SEC = 0.0            # minimum seconds between proofs (same creator)


class ProofOfAnchorMinter:
    """
    Proof-of-Anchor minting engine.

    For every valid AnchorProof the creator receives a token reward that
    halves on a configurable schedule, following Bitcoin's halving model.
    """

    MAX_SUPPLY = 21_000_000
    BASE_REWARD = 1_000
    HALVING_INTERVAL = 5_250

    def __init__(
        self,
        anch_asset: 'RGBAsset',
        claim_registry: ClaimRegistry,
        genesis_bonus: int = 500,
        genesis_count: int = 100,
        *,
        max_per_creator: int = DEFAULT_MAX_PER_CREATOR,
        cooldown_sec: float = DEFAULT_COOLDOWN_SEC,
    ):
        if genesis_bonus < 0:
            raise ValueError("genesis_bonus must be non-negative")
        if genesis_count < 0:
            raise ValueError("genesis_count must be non-negative")

        self.anch = anch_asset
        self.registry = claim_registry
        self.total_minted: int = 0
        self.proofs_accepted: int = 0
        self.genesis_bonus = genesis_bonus
        self.genesis_count = genesis_count
        self._max_per_creator = max_per_creator
        self._cooldown_sec = cooldown_sec
        self._mint_history: List[dict] = []
        self._creator_minted: Dict[str, int] = {}
        self._creator_last_ts: Dict[str, float] = {}

    @property
    def remaining_supply(self) -> int:
        return max(0, self.MAX_SUPPLY - self.total_minted)

    @property
    def current_era(self) -> int:
        return self.proofs_accepted // self.HALVING_INTERVAL

    @property
    def current_reward(self) -> int:
        era = self.current_era
        reward = self.BASE_REWARD >> era
        return max(1, reward)

    @property
    def proofs_until_halving(self) -> int:
        """Number of proofs remaining until the next halving."""
        return self.HALVING_INTERVAL - (self.proofs_accepted % self.HALVING_INTERVAL)

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
        """
        Validate an anchor proof and mint the reward.

        Returns (success, reason, reward_amount).
        """
        if self.remaining_supply == 0:
            return False, "max supply reached (21M ANCH)", 0

        # Per-creator cooldown
        now = time.time()
        last_ts = self._creator_last_ts.get(proof.creator, 0.0)
        if self._cooldown_sec > 0 and (now - last_ts) < self._cooldown_sec:
            return False, (
                f"cooldown: {self._cooldown_sec - (now - last_ts):.1f}s remaining"
            ), 0

        valid, reason = AnchorVerifier.verify(
            proof, parent_tx, child_tx, self.registry
        )
        if not valid:
            return False, reason, 0

        reward = self._compute_reward()

        # Per-creator cap
        creator_total = self._creator_minted.get(proof.creator, 0)
        if creator_total + reward > self._max_per_creator:
            allowed = self._max_per_creator - creator_total
            if allowed <= 0:
                return False, (
                    f"creator {proof.creator[:16]}... reached minting cap "
                    f"({self._max_per_creator:,} ANCH)"
                ), 0
            reward = allowed  # reduce to fit within cap

        ok, claim_reason = self.registry.register_claim(proof, reward_amount=reward)
        if not ok:
            return False, f"claim failed: {claim_reason}", 0

        # Mint atomically
        self.anch.balances[proof.creator] = (
            self.anch.balances.get(proof.creator, 0) + reward
        )
        self.total_minted += reward
        self.proofs_accepted += 1
        self._creator_minted[proof.creator] = creator_total + reward
        self._creator_last_ts[proof.creator] = now

        inscription = BRC20Inscription.mint("ANCH", proof.creator, reward)

        is_genesis = self.proofs_accepted <= self.genesis_count
        self._mint_history.append({
            "proof_id": proof.proof_id[:16],
            "creator": proof.creator,
            "reward": reward,
            "total_minted": self.total_minted,
            "proofs_accepted": self.proofs_accepted,
            "era": self.current_era,
            "genesis": is_genesis,
            "inscription": inscription,
            "ts": now,
        })
        # Cap history length
        if len(self._mint_history) > MAX_HISTORY:
            self._mint_history = self._mint_history[-MAX_HISTORY:]

        print(f"  [PoA] Proof {proof.proof_id[:16]}... verified")
        print(f"         Creator: {proof.creator}")
        print(f"         Reward:  {reward:,} ANCH "
              f"(era {self.current_era}, "
              f"{'GENESIS BONUS' if is_genesis else 'standard'})")
        print(f"         Minted:  {self.total_minted:,} / {self.MAX_SUPPLY:,} ANCH")
        return True, "minted", reward

    def creator_stats(self, creator: str) -> dict:
        """Per-creator minting statistics."""
        return {
            "creator": creator,
            "total_minted": self._creator_minted.get(creator, 0),
            "cap": self._max_per_creator,
            "remaining": max(
                0,
                self._max_per_creator - self._creator_minted.get(creator, 0),
            ),
            "claims": self.registry.creator_claim_count(creator),
        }

    def get_stats(self) -> dict:
        era = self.current_era
        return {
            "max_supply": self.MAX_SUPPLY,
            "total_minted": self.total_minted,
            "remaining": self.remaining_supply,
            "proofs_accepted": self.proofs_accepted,
            "current_reward": self.current_reward,
            "era": era,                    # backward-compat alias
            "current_era": era,
            "proofs_until_halving": self.proofs_until_halving,
            "genesis_bonus_remaining": max(
                0, self.genesis_count - self.proofs_accepted
            ),
            "unique_creators": len(self._creator_minted),
        }

    def get_mint_history(self, *, limit: int = 50) -> List[dict]:
        """Return most recent mint records (newest first)."""
        return list(reversed(self._mint_history[-limit:]))
