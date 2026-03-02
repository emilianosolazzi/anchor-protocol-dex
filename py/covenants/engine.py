"""
Hybrid Covenant Engine -- auto-selects the best strategy per network.

Strategies (in preference order):
  1. CTV + CAT  -- strongest (Inquisition Signet)
  2. APO + CAT  -- rebindable state transitions (Inquisition Signet)
  3. CAT + CSFS -- Liquid / Elements
  4. CTV only   -- BIP-119 on Signet
  5. CAT only   -- BIP-347 on Signet / Liquid
  6. Pre-signed -- works on mainnet today (fallback)

Strategy selection is automatic based on network capabilities,
but can be overridden for testing.  The engine enforces AMM
swap invariants using the selected strategy's covenant primitives.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import hashlib
import struct
from typing import Dict, Optional

from bitcoin.core import COutPoint, lx

from .opcodes import CovenantNetwork, sha256
from .ctv import CTVTemplate
from .cat import CATCovenant
from .apo import APOCovenant
from .csfs import CSFSCovenant
from .presigned import PreSignedTree
from ..crypto.keys import KEYSTORE
from ..amm.state import PoolState, SwapType
from ..amm.covenant_amm import CovenantAMMScript


class HybridCovenantEngine:
    """
    Automatically selects the best covenant strategy for the
    target network and enforces AMM swaps using that strategy.

    The engine deduplicates swap verification logic and supports
    all 6 strategies including APO-based rebindable state machines.
    """

    STRATEGIES = [
        "ctv_cat",       # OP_CTV + OP_CAT (strongest)
        "apo_cat",       # APO + OP_CAT (rebindable + state verification)
        "cat_csfs",      # OP_CAT + OP_CSFS (Liquid)
        "ctv_only",      # OP_CTV alone
        "cat_only",      # OP_CAT alone
        "presigned",     # Pre-signed tx tree (universal fallback)
    ]

    def __init__(
        self,
        network: CovenantNetwork = CovenantNetwork.REGTEST,
        strategy_override: Optional[str] = None,
    ):
        self.network = network
        if strategy_override:
            if strategy_override not in self.STRATEGIES:
                raise ValueError(
                    f"Unknown strategy '{strategy_override}'. "
                    f"Choose from: {self.STRATEGIES}"
                )
            self.strategy = strategy_override
        else:
            self.strategy = self._select_strategy()

    def _select_strategy(self) -> str:
        """
        Auto-select the strongest available strategy.

        Preference order:
          1. CTV + CAT: Full template lock + state verification
          2. APO + CAT: Rebindable signatures + state verification
          3. CAT + CSFS: State verification + operator attestation (Liquid)
          4. CTV only: Template lock without state verification
          5. CAT only: State verification without template lock
          6. Pre-signed: Universal fallback (no new opcodes)
        """
        n = self.network
        if n.has_op_ctv and n.has_op_cat:
            return "ctv_cat"
        if n.has_apo and n.has_op_cat:
            return "apo_cat"
        if n.has_op_cat and n.has_csfs:
            return "cat_csfs"
        if n.has_op_ctv:
            return "ctv_only"
        if n.has_op_cat:
            return "cat_only"
        return "presigned"

    # ------------------------------------------------------------------
    # Shared AMM verification (extracted from individual strategies)
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_state_hashes(
        old_state: PoolState,
        new_state: PoolState,
    ) -> tuple:
        """Compute serialized data and hashes for old/new pool states."""
        old_data = struct.pack('<QQ', old_state.btc_reserve, old_state.anch_reserve)
        new_data = struct.pack('<QQ', new_state.btc_reserve, new_state.anch_reserve)
        old_hash = sha256(old_data)
        new_hash = sha256(new_data)
        return old_data, new_data, old_hash, new_hash

    @staticmethod
    def _verify_swap_invariant(
        old_state: PoolState,
        new_state: PoolState,
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
    ) -> bool:
        """
        Verify the AMM swap invariant (x*y >= k).

        Dispatches to the correct verification function based on
        swap direction.  This is the single source of truth for
        swap validity — all strategies delegate here.
        """
        if swap_type == SwapType.BTC_TO_ANCH:
            return CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            return CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
            )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def enforce_swap(
        self,
        old_state: PoolState,
        new_state: PoolState,
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
    ) -> Dict:
        """Enforce a swap using the selected strategy."""
        dispatchers = {
            "ctv_cat": self._enforce_ctv_cat,
            "apo_cat": self._enforce_apo_cat,
            "cat_csfs": self._enforce_cat_csfs,
            "ctv_only": self._enforce_ctv_only,
            "cat_only": self._enforce_cat_only,
            "presigned": self._enforce_presigned,
        }
        return dispatchers[self.strategy](
            old_state, new_state, swap_type, amount_in, amount_out
        )

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    def _enforce_ctv_cat(self, old_state, new_state, swap_type,
                         amount_in, amount_out) -> Dict:
        """CTV + CAT: Template lock + state commitment verification."""
        old_data, new_data, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        ctv_hash = sha256(
            struct.pack('<QQQ', new_state.btc_reserve,
                        new_state.anch_reserve, new_state.lp_total)
        )
        hybrid_script = CATCovenant.build_cat_ctv_hybrid_script(
            sha256(old_hash + new_hash), ctv_hash
        )
        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "ctv_cat",
            "mechanism": "OP_CAT state verification + OP_CTV template lock",
            "cat_script": cat_script.hex(),
            "hybrid_script": hybrid_script.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "template_hash": ctv_hash.hex(),
            "valid": valid,
        }

    def _enforce_apo_cat(self, old_state, new_state, swap_type,
                         amount_in, amount_out) -> Dict:
        """
        APO + CAT: Rebindable signatures + state commitment.

        Uses SIGHASH_ANYPREVOUT so the pool update transaction
        can be rebound to any prior state UTXO (LN-Symmetry style
        latest-state-wins).  OP_CAT verifies the state transition
        is valid by checking the hash of old || new reserves.

        This combination is powerful for pool state channels:
          - APO: Any later state can spend any earlier state
          - CAT: Ensures the state transition preserves the invariant
        """
        old_data, new_data, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        # CAT state commitment
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)

        # APO pool script with state hash
        operator_key = KEYSTORE.pubkey("pool_operator")
        apo_script = APOCovenant.build_apo_pool_script(
            operator_key, sha256(new_data)
        )
        # LN-Symmetry style update script
        ln_sym_script = APOCovenant.build_ln_symmetry_script(
            operator_key,
            state_number=new_state.btc_reserve,  # monotonic state counter
            settlement_delay=144,
        )

        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "apo_cat",
            "mechanism": "APO rebindable signatures + OP_CAT state verification",
            "cat_script": cat_script.hex(),
            "apo_script": apo_script.hex(),
            "ln_symmetry_script": ln_sym_script.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "valid": valid,
        }

    def _enforce_cat_csfs(self, old_state, new_state, swap_type,
                          amount_in, amount_out) -> Dict:
        """CAT + CSFS: State verification + operator attestation (Liquid)."""
        old_data, new_data, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        operator_key = KEYSTORE.pubkey("pool_operator")
        csfs_sig = CSFSCovenant.sign_state_transition("pool_operator", new_data)
        csfs_script = CSFSCovenant.build_csfs_covenant_script(
            operator_key, sha256(new_data)
        )
        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "cat_csfs",
            "mechanism": "OP_CAT state + OP_CHECKSIGFROMSTACK operator attestation",
            "cat_script": cat_script.hex(),
            "csfs_script": csfs_script.hex(),
            "csfs_signature": csfs_sig.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "valid": valid,
        }

    def _enforce_ctv_only(self, old_state, new_state, swap_type,
                          amount_in, amount_out) -> Dict:
        """CTV only: Template hash locks spending transaction shape."""
        _, _, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        ctv_hash = sha256(
            struct.pack('<QQQ', new_state.btc_reserve,
                        new_state.anch_reserve, new_state.lp_total)
        )
        ctv_script = CTVTemplate.build_ctv_script(ctv_hash)
        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "ctv_only",
            "mechanism": "OP_CTV template hash locks spending transaction",
            "ctv_script": ctv_script.hex(),
            "template_hash": ctv_hash.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "valid": valid,
        }

    def _enforce_cat_only(self, old_state, new_state, swap_type,
                          amount_in, amount_out) -> Dict:
        """CAT only: State commitment verification."""
        _, _, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "cat_only",
            "mechanism": "OP_CAT state commitment verification",
            "cat_script": cat_script.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "valid": valid,
        }

    def _enforce_presigned(self, old_state, new_state, swap_type,
                           amount_in, amount_out) -> Dict:
        """Pre-signed: Transaction tree with no new opcodes."""
        _, _, old_hash, new_hash = self._compute_state_hashes(
            old_state, new_state
        )
        tree = PreSignedTree(signers=["operator"], n_of_n=True)
        funding_outpoint = COutPoint(sha256(b"presigned_root"), 0)
        root = tree.build_swap_tree(
            funding_outpoint, old_state, swap_type, [amount_in],
        )
        valid = self._verify_swap_invariant(
            old_state, new_state, swap_type, amount_in, amount_out
        )
        return {
            "strategy": "presigned",
            "mechanism": "Pre-signed transaction tree (no new opcodes)",
            "tree_nodes": tree.info()["total_nodes"],
            "root_txid": root.txid[:32] if root else "N/A",
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "valid": valid,
        }

    # ------------------------------------------------------------------
    # Capabilities & migration
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict:
        """Report the engine's capabilities for the configured network."""
        return {
            "network": self.network.value,
            "selected_strategy": self.strategy,
            "available_mechanisms": {
                "op_cat": self.network.has_op_cat,
                "op_ctv": self.network.has_op_ctv,
                "apo": self.network.has_apo,
                "csfs": self.network.has_csfs,
                "presigned_trees": self.network.has_presigned_trees,
            },
            "all_strategies": self.STRATEGIES,
            "strategy_index": self.STRATEGIES.index(self.strategy),
        }

    def can_upgrade_to(self, target_strategy: str) -> bool:
        """
        Check if the engine can upgrade to a stronger strategy.

        This is useful for soft-fork activation planning: when a new
        opcode activates on the network, the engine can upgrade to
        a stronger strategy without redeploying the pool.
        """
        if target_strategy not in self.STRATEGIES:
            return False
        target_idx = self.STRATEGIES.index(target_strategy)
        current_idx = self.STRATEGIES.index(self.strategy)
        # Lower index = stronger strategy
        return target_idx < current_idx

    def upgrade_strategy(self, target_strategy: str) -> bool:
        """
        Attempt to upgrade to a stronger strategy.

        Returns True if the upgrade succeeded, False if the
        target strategy requires opcodes not available on the
        current network.
        """
        if not self.can_upgrade_to(target_strategy):
            return False
        # Verify network supports the target
        n = self.network
        requirements = {
            "ctv_cat": n.has_op_ctv and n.has_op_cat,
            "apo_cat": n.has_apo and n.has_op_cat,
            "cat_csfs": n.has_op_cat and n.has_csfs,
            "ctv_only": n.has_op_ctv,
            "cat_only": n.has_op_cat,
            "presigned": True,
        }
        if requirements.get(target_strategy, False):
            self.strategy = target_strategy
            return True
        return False
