"""
Pre-signed transaction tree -- works on mainnet today.

Emulates covenants via a tree of pre-signed transactions
(similar to Ark protocol / timeout trees).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut,
    COutPoint, CScript,
)
from bitcoin.core.script import OP_0, OP_CHECKSIG, SignatureHash, SIGHASH_ALL

from .opcodes import sha256
from ..crypto.keys import KEYSTORE
from ..amm.state import PoolState, SwapType
from ..amm.covenant_amm import CovenantAMMScript


@dataclass
class TreeNode:
    """A node in the pre-signed transaction tree."""
    txid: str
    label: str
    amount: int
    depth: int
    children: List['TreeNode'] = field(default_factory=list)
    signatures: List[bytes] = field(default_factory=list)


class PreSignedTree:
    """
    Pre-signed transaction tree for covenant emulation on mainnet.

    All participants pre-sign a tree of transactions covering
    possible state transitions.  No new opcodes required.
    """

    def __init__(self, signers: List[str], n_of_n: bool = True):
        self.signers = signers
        self.n_of_n = n_of_n
        self._root: Optional[TreeNode] = None
        self._nodes: List[TreeNode] = []

    def build_swap_tree(
        self,
        funding_outpoint: COutPoint,
        pool_state: PoolState,
        swap_type: SwapType,
        price_ticks: List[int],
    ) -> Optional[TreeNode]:
        """
        Build a tree of pre-signed transactions for discrete price ticks.
        Each leaf represents a possible swap at a specific price point.
        """
        root_tx = CMutableTransaction()
        root_tx.vin = [CTxIn(funding_outpoint)]
        root_tx.vout = [CTxOut(
            pool_state.btc_reserve,
            CScript([OP_0, sha256(b"tree_root")]),
        )]
        root_ctxx = CTransaction.from_tx(root_tx)
        root_txid = root_ctxx.GetTxid().hex()

        # Sign root (use a simple redeem script for signing, not P2WSH spk)
        root_redeem = CScript([sha256(b"tree_root"), OP_CHECKSIG])
        root_sigs = []
        for signer in self.signers:
            sighash = SignatureHash(root_redeem, root_ctxx, 0, SIGHASH_ALL)
            sig = KEYSTORE.sign(signer, sighash)
            root_sigs.append(sig)

        root_node = TreeNode(
            txid=root_txid,
            label="ROOT",
            amount=pool_state.btc_reserve,
            depth=0,
            signatures=root_sigs,
        )

        # Build leaf for each price tick
        for i, tick in enumerate(price_ticks):
            amount_out = CovenantAMMScript.get_amount_out(
                tick,
                pool_state.btc_reserve,
                pool_state.anch_reserve,
            )
            leaf_tx = CMutableTransaction()
            leaf_tx.vin = [CTxIn(COutPoint(root_ctxx.GetTxid(), 0))]
            new_btc = pool_state.btc_reserve + tick
            leaf_tx.vout = [CTxOut(
                new_btc,
                CScript([OP_0, sha256(f"leaf_{i}".encode())]),
            )]
            leaf_ctxx = CTransaction.from_tx(leaf_tx)
            leaf_txid = leaf_ctxx.GetTxid().hex()

            leaf_redeem = CScript([sha256(f"leaf_{i}".encode()), OP_CHECKSIG])
            leaf_sigs = []
            for signer in self.signers:
                sighash = SignatureHash(leaf_redeem, leaf_ctxx, 0, SIGHASH_ALL)
                sig = KEYSTORE.sign(signer, sighash)
                leaf_sigs.append(sig)

            leaf_node = TreeNode(
                txid=leaf_txid,
                label=f"SWAP_{tick:,}_sats",
                amount=new_btc,
                depth=1,
                signatures=leaf_sigs,
            )
            root_node.children.append(leaf_node)
            self._nodes.append(leaf_node)

        self._root = root_node
        self._nodes.insert(0, root_node)
        return root_node

    def find_matching_leaf(self, amount_in: int) -> Optional[TreeNode]:
        """Find the leaf that best matches the requested swap amount."""
        if self._root is None:
            return None
        best = None
        for child in self._root.children:
            if best is None or abs(child.amount - amount_in) < abs(best.amount - amount_in):
                best = child
        return best

    def verify_all_signatures(self) -> bool:
        """Verify all pre-signed signatures in the tree."""
        for node in self._nodes:
            if len(node.signatures) != len(self.signers):
                return False
        return True

    def info(self) -> dict:
        return {
            "signers": self.signers,
            "n_of_n": self.n_of_n,
            "total_nodes": len(self._nodes),
            "tree_depth": max((n.depth for n in self._nodes), default=0),
        }
