"""
Hybrid Covenant Engine -- auto-selects the best strategy per network.

Strategies (in preference order):
  1. CTV + CAT  -- strongest (Inquisition Signet)
  2. CAT + CSFS -- Liquid / Elements
  3. CTV only   -- BIP-119 on Signet
  4. CAT only   -- BIP-347 on Signet / Liquid
  5. Pre-signed -- works on mainnet today (fallback)
"""
from __future__ import annotations

import hashlib
import struct
from typing import Dict

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
    """

    STRATEGIES = [
        "ctv_cat",       # OP_CTV + OP_CAT (strongest)
        "cat_csfs",      # OP_CAT + OP_CSFS (Liquid)
        "ctv_only",      # OP_CTV alone
        "cat_only",      # OP_CAT alone
        "presigned",     # Pre-signed tx tree (universal fallback)
    ]

    def __init__(self, network: CovenantNetwork = CovenantNetwork.REGTEST):
        self.network = network
        self.strategy = self._select_strategy()

    def _select_strategy(self) -> str:
        n = self.network
        if n.has_op_ctv and n.has_op_cat:
            return "ctv_cat"
        if n.has_op_cat and n.has_csfs:
            return "cat_csfs"
        if n.has_op_ctv:
            return "ctv_only"
        if n.has_op_cat:
            return "cat_only"
        return "presigned"

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
            "cat_csfs": self._enforce_cat_csfs,
            "ctv_only": self._enforce_ctv_only,
            "cat_only": self._enforce_cat_only,
            "presigned": self._enforce_presigned,
        }
        return dispatchers[self.strategy](
            old_state, new_state, swap_type, amount_in, amount_out
        )

    def _enforce_ctv_cat(self, old_state, new_state, swap_type,
                         amount_in, amount_out) -> Dict:
        old_data = struct.pack('<QQ', old_state.btc_reserve, old_state.anch_reserve)
        new_data = struct.pack('<QQ', new_state.btc_reserve, new_state.anch_reserve)
        old_hash = sha256(old_data)
        new_hash = sha256(new_data)
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        ctv_hash = sha256(
            struct.pack('<QQQ', new_state.btc_reserve,
                        new_state.anch_reserve, new_state.lp_total)
        )
        hybrid_script = CATCovenant.build_cat_ctv_hybrid_script(
            sha256(old_hash + new_hash), ctv_hash
        )
        if swap_type == SwapType.BTC_TO_ANCH:
            valid = CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
            )
        return {
            "strategy": "ctv_cat",
            "mechanism": f"OP_CAT state verification + OP_CTV template lock",
            "cat_script": cat_script.hex(),
            "hybrid_script": hybrid_script.hex(),
            "old_state_hash": old_hash.hex(),
            "new_state_hash": new_hash.hex(),
            "template_hash": ctv_hash.hex(),
            "valid": valid,
        }

    def _enforce_cat_csfs(self, old_state, new_state, swap_type,
                          amount_in, amount_out) -> Dict:
        old_data = struct.pack('<QQ', old_state.btc_reserve, old_state.anch_reserve)
        new_data = struct.pack('<QQ', new_state.btc_reserve, new_state.anch_reserve)
        old_hash = sha256(old_data)
        new_hash = sha256(new_data)
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        operator_key = KEYSTORE.pubkey("pool_operator")
        csfs_sig = CSFSCovenant.sign_state_transition("pool_operator", new_data)
        csfs_script = CSFSCovenant.build_csfs_covenant_script(
            operator_key, sha256(new_data)
        )
        if swap_type == SwapType.BTC_TO_ANCH:
            valid = CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
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
        ctv_hash = sha256(
            struct.pack('<QQQ', new_state.btc_reserve,
                        new_state.anch_reserve, new_state.lp_total)
        )
        ctv_script = CTVTemplate.build_ctv_script(ctv_hash)
        old_hash = sha256(struct.pack('<QQ', old_state.btc_reserve,
                                      old_state.anch_reserve))
        new_hash = sha256(struct.pack('<QQ', new_state.btc_reserve,
                                      new_state.anch_reserve))
        if swap_type == SwapType.BTC_TO_ANCH:
            valid = CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
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
        old_data = struct.pack('<QQ', old_state.btc_reserve, old_state.anch_reserve)
        new_data = struct.pack('<QQ', new_state.btc_reserve, new_state.anch_reserve)
        old_hash = sha256(old_data)
        new_hash = sha256(new_data)
        cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
        if swap_type == SwapType.BTC_TO_ANCH:
            valid = CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
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
        tree = PreSignedTree(signers=["operator"], n_of_n=True)
        funding_outpoint = COutPoint(sha256(b"presigned_root"), 0)
        root = tree.build_swap_tree(
            funding_outpoint, old_state, swap_type, [amount_in],
        )
        old_hash = sha256(struct.pack('<QQ', old_state.btc_reserve,
                                      old_state.anch_reserve))
        new_hash = sha256(struct.pack('<QQ', new_state.btc_reserve,
                                      new_state.anch_reserve))
        if swap_type == SwapType.BTC_TO_ANCH:
            valid = CovenantAMMScript.verify_swap(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
            )
        else:
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old_state.btc_reserve, old_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
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

    def get_capabilities(self) -> Dict:
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
        }
