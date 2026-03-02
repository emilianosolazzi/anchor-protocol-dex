"""
AnchorVerifier and ClaimRegistry -- deterministic proof validation + anti-replay.
"""
from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional, Tuple

from ..crypto.keys import KEYSTORE
from .truc import AnchorProof, TRUCTransactionBuilder

from bitcoin.core import CTransaction


class AnchorVerifier:
    """
    Deterministic verifier for AnchorProof objects.

    Checks:
      1. Parent is TRUC (nVersion == 3)
      2. Parent has exactly one OP_TRUE 0-sat output (ephemeral anchor)
      3. Child spends the anchor output (input references parent:anchor_vout)
      4. Creator's signature is valid against the proof message
      5. No duplicate proof_id in the claim registry
    """

    @staticmethod
    def verify(
        proof: AnchorProof,
        parent_tx: CTransaction,
        child_tx: CTransaction,
        registry: Optional['ClaimRegistry'] = None,
    ) -> Tuple[bool, str]:
        # 1. Parent must be TRUC v3
        if not TRUCTransactionBuilder.is_truc(parent_tx):
            return False, f"parent nVersion={parent_tx.nVersion}, expected 3 (TRUC)"

        # 2. Parent must have an OP_TRUE 0-sat anchor at the claimed vout
        anchor_vout = TRUCTransactionBuilder.find_anchor_output(parent_tx)
        if anchor_vout is None:
            return False, "no OP_TRUE 0-sat output found in parent"
        if anchor_vout != proof.anchor_vout:
            return False, f"anchor at vout={anchor_vout}, proof claims vout={proof.anchor_vout}"

        # 3. Child must spend parent's anchor output
        parent_txid_bytes = parent_tx.GetTxid()
        child_spends_anchor = False
        for vin in child_tx.vin:
            if vin.prevout.hash == parent_txid_bytes and vin.prevout.n == anchor_vout:
                child_spends_anchor = True
                break
        if not child_spends_anchor:
            return False, "child does not spend parent's anchor output"

        # 4. Verify creator's signature
        msg = hashlib.sha256(
            f"ANCHOR_PROOF:{proof.proof_id}:{proof.block_height}".encode()
        ).digest()
        try:
            sig_valid = KEYSTORE.verify(proof.creator, proof.signature, msg)
        except Exception:
            sig_valid = False
        if not sig_valid:
            return False, "invalid creator signature"

        # 5. Check claim registry for duplicates
        if registry is not None:
            if registry.is_claimed(proof.proof_id):
                return False, f"anchor already claimed (proof_id={proof.proof_id[:16]}...)"

        proof.verified = True
        return True, "valid"


class ClaimRegistry:
    """
    Anti-replay registry for anchor proof claims.

    Enforces:
      - Each proof_id can only be claimed once
      - Each parent_txid:anchor_vout can only be claimed once
      - Each child_txid can only appear in one claim
    """

    def __init__(self):
        self._claims: Dict[str, AnchorProof] = {}
        self._anchor_outpoints: Dict[str, str] = {}
        self._child_txids: Dict[str, str] = {}
        self._rewards: Dict[str, int] = {}
        self._history: List[dict] = []

    def is_claimed(self, proof_id: str) -> bool:
        return proof_id in self._claims

    def is_outpoint_claimed(self, parent_txid: str, vout: int) -> bool:
        return f"{parent_txid}:{vout}" in self._anchor_outpoints

    def is_child_claimed(self, child_txid: str) -> bool:
        return child_txid in self._child_txids

    def register_claim(
        self,
        proof: AnchorProof,
        reward_amount: int = 0,
    ) -> Tuple[bool, str]:
        if not proof.verified:
            return False, "proof not verified"

        if self.is_claimed(proof.proof_id):
            return False, f"duplicate proof_id {proof.proof_id[:16]}..."

        outpoint_key = f"{proof.parent_txid}:{proof.anchor_vout}"
        if outpoint_key in self._anchor_outpoints:
            existing = self._anchor_outpoints[outpoint_key]
            return False, f"outpoint already claimed by {existing[:16]}..."

        if proof.child_txid in self._child_txids:
            existing = self._child_txids[proof.child_txid]
            return False, f"child_txid already in claim {existing[:16]}..."

        self._claims[proof.proof_id] = proof
        self._anchor_outpoints[outpoint_key] = proof.proof_id
        self._child_txids[proof.child_txid] = proof.proof_id
        self._rewards[proof.creator] = self._rewards.get(proof.creator, 0) + reward_amount

        self._history.append({
            "type": "claim",
            "proof_id": proof.proof_id[:16],
            "creator": proof.creator,
            "reward": reward_amount,
            "block": proof.block_height,
            "ts": time.time(),
        })
        return True, "claimed"

    def get_rewards(self, creator: str) -> int:
        return self._rewards.get(creator, 0)

    def total_claims(self) -> int:
        return len(self._claims)

    def get_history(self) -> List[dict]:
        return list(self._history)
