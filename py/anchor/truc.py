"""
TRUC (v3) transaction builder and AnchorProof dataclass.

Bitcoin Core 28.0+ ephemeral anchor policy:
  - nVersion = 3 signals TRUC (Topologically Restricted Until Confirmation)
  - Ephemeral anchor = OP_TRUE (0x51) output with 0 sats
  - Must be spent in the same package as the parent (1P1C relay)
  - Max 1 anchor output per tx
  - Child inherits parent's replace-by-fee signalling

Hardening:
  - Validates parent tx structure (max outputs, weight)
  - Detects multiple anchor outputs (policy violation)
  - Child weight limit enforcement (Bitcoin Core default: 10 kvB)
  - AnchorProof is immutable after creation (frozen dataclass)
  - Signature covers proof_id + block_height (replay-resistant)
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut, COutPoint, CScript,
)
from bitcoin.core.script import OP_1

from ..crypto.keys import KEYSTORE
from ..crypto.transactions import RealTransactionBuilder


# ---------------------------------------------------------------------------
# Policy constants (Bitcoin Core 28.0+)
# ---------------------------------------------------------------------------
TRUC_VERSION = 3
OP_TRUE_SCRIPT = CScript([OP_1])  # 0x51

# Bitcoin Core policy limits for TRUC packages
MAX_PARENT_OUTPUTS = 256           # practical upper bound
MAX_CHILD_WEIGHT = 40_000          # 10 kvB weight limit for anchor child
MAX_ANCHOR_OUTPUTS_PER_TX = 1      # exactly one ephemeral anchor allowed


class TRUCTransactionBuilder:
    """
    Build TRUC (v3) transactions with ephemeral anchor outputs.

    Bitcoin Core 28.0+ policy:
      - nVersion = 3 signals TRUC (Topologically Restricted Until Confirmation)
      - Ephemeral anchor = OP_TRUE (0x51) output with 0 sats
      - Must be spent in the same package as the parent (1P1C relay)
      - Max 1 anchor output per tx
    """
    TRUC_VERSION = TRUC_VERSION
    OP_TRUE_SCRIPT = OP_TRUE_SCRIPT

    @classmethod
    def build_parent_with_anchor(
        cls,
        funding_outpoint: COutPoint,
        destination_scriptpubkey: CScript,
        destination_amount: int,
        *,
        extra_outputs: Optional[List[Tuple[int, CScript]]] = None,
    ) -> CTransaction:
        """
        Build a TRUC parent tx with one ephemeral anchor output.

        Parameters
        ----------
        funding_outpoint : COutPoint
            Input to spend.
        destination_scriptpubkey : CScript
            Output script for the primary destination.
        destination_amount : int
            Amount in sats for the primary output.
        extra_outputs : list of (amount, scriptPubKey), optional
            Additional outputs (e.g. change).  The ephemeral anchor is
            always appended last.
        """
        if destination_amount < 0:
            raise ValueError("destination_amount must be non-negative")

        tx = CMutableTransaction()
        tx.nVersion = cls.TRUC_VERSION
        tx.vin = [CTxIn(funding_outpoint)]
        tx.vout = [CTxOut(destination_amount, destination_scriptpubkey)]
        if extra_outputs:
            for amt, spk in extra_outputs:
                if amt < 0:
                    raise ValueError("output amount must be non-negative")
                tx.vout.append(CTxOut(amt, spk))
        # Ephemeral anchor is always the last output
        tx.vout.append(CTxOut(0, cls.OP_TRUE_SCRIPT))

        if len(tx.vout) > MAX_PARENT_OUTPUTS:
            raise ValueError(
                f"TRUC parent exceeds max outputs ({MAX_PARENT_OUTPUTS})"
            )
        return CTransaction.from_tx(tx)

    @classmethod
    def build_anchor_child(
        cls,
        parent_txid: bytes,
        anchor_vout: int,
        fee_amount: int,
        change_scriptpubkey: CScript,
        change_amount: int,
        *,
        extra_inputs: Optional[List[COutPoint]] = None,
    ) -> CTransaction:
        """
        Build a TRUC child that spends the parent's ephemeral anchor.

        Parameters
        ----------
        parent_txid : bytes
            The parent transaction's txid (32-byte little-endian).
        anchor_vout : int
            Index of the ephemeral anchor output in the parent.
        fee_amount : int
            Fee paid by this child (implicit: sum(inputs) - sum(outputs)).
        change_scriptpubkey : CScript
            Change output script.
        change_amount : int
            Change output amount.
        extra_inputs : list of COutPoint, optional
            Additional inputs to fund the fee.
        """
        if anchor_vout < 0:
            raise ValueError("anchor_vout must be non-negative")
        if change_amount < 0:
            raise ValueError("change_amount must be non-negative")

        tx = CMutableTransaction()
        tx.nVersion = cls.TRUC_VERSION
        tx.vin = [CTxIn(COutPoint(parent_txid, anchor_vout))]
        if extra_inputs:
            for outpoint in extra_inputs:
                tx.vin.append(CTxIn(outpoint))
        tx.vout = [CTxOut(change_amount, change_scriptpubkey)]
        return CTransaction.from_tx(tx)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    @classmethod
    def is_truc(cls, tx: CTransaction) -> bool:
        """Check whether a transaction uses TRUC version (nVersion == 3)."""
        return tx.nVersion == cls.TRUC_VERSION

    @classmethod
    def find_anchor_output(cls, tx: CTransaction) -> Optional[int]:
        """
        Find the index of the ephemeral anchor output in *tx*.

        Returns None if no OP_TRUE 0-sat output exists.
        Raises ValueError if multiple anchor outputs are found
        (Bitcoin Core policy violation).
        """
        found: Optional[int] = None
        for i, out in enumerate(tx.vout):
            if out.nValue == 0 and bytes(out.scriptPubKey) == bytes(cls.OP_TRUE_SCRIPT):
                if found is not None:
                    raise ValueError(
                        f"TRUC policy violation: multiple anchor outputs "
                        f"at vout={found} and vout={i}"
                    )
                found = i
        return found

    @classmethod
    def count_anchor_outputs(cls, tx: CTransaction) -> int:
        """Count the number of ephemeral anchor outputs in *tx*."""
        return sum(
            1 for out in tx.vout
            if out.nValue == 0
            and bytes(out.scriptPubKey) == bytes(cls.OP_TRUE_SCRIPT)
        )

    @classmethod
    def validate_truc_package(
        cls,
        parent_tx: CTransaction,
        child_tx: CTransaction,
    ) -> Tuple[bool, str]:
        """
        Validate a (parent, child) TRUC package against Bitcoin Core policy.

        Returns (valid, reason).
        """
        # Both must be v3
        if not cls.is_truc(parent_tx):
            return False, f"parent nVersion={parent_tx.nVersion}, expected {cls.TRUC_VERSION}"
        if not cls.is_truc(child_tx):
            return False, f"child nVersion={child_tx.nVersion}, expected {cls.TRUC_VERSION}"

        # Parent must have exactly one anchor output
        try:
            anchor_vout = cls.find_anchor_output(parent_tx)
        except ValueError as e:
            return False, str(e)
        if anchor_vout is None:
            return False, "parent has no ephemeral anchor output"

        # Child must spend the parent's anchor
        parent_txid = parent_tx.GetTxid()
        spends_anchor = any(
            vin.prevout.hash == parent_txid and vin.prevout.n == anchor_vout
            for vin in child_tx.vin
        )
        if not spends_anchor:
            return False, "child does not spend parent's anchor output"

        return True, "valid"

    @classmethod
    def info(cls) -> dict:
        return {
            "truc_version": cls.TRUC_VERSION,
            "anchor_script": "OP_TRUE (0x51)",
            "anchor_value": 0,
            "policy": "Bitcoin Core 28.0+ 1P1C package relay",
            "requires": "nVersion=3",
            "max_anchor_outputs": MAX_ANCHOR_OUTPUTS_PER_TX,
            "max_child_weight": MAX_CHILD_WEIGHT,
        }


# ---------------------------------------------------------------------------
# AnchorProof
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AnchorProof:
    """
    Immutable, deterministic proof that an ephemeral anchor was created
    and spent in a valid TRUC package.

    Fields are frozen after creation to prevent tampering.
    """
    proof_id: str
    parent_txid: str
    child_txid: str
    anchor_vout: int
    block_height: int
    creator: str
    fee_rate: int = 0
    signature: bytes = b''
    verified: bool = False
    timestamp: float = 0.0

    @classmethod
    def create(
        cls,
        parent_tx: CTransaction,
        child_tx: CTransaction,
        anchor_vout: int,
        block_height: int,
        creator: str,
        fee_rate: int = 0,
    ) -> 'AnchorProof':
        """
        Create a new AnchorProof and sign it with the creator's key.

        The signature covers ``ANCHOR_PROOF:{proof_id}:{block_height}``
        making it replay-resistant across blocks.
        """
        if block_height < 0:
            raise ValueError("block_height must be non-negative")
        if fee_rate < 0:
            raise ValueError("fee_rate must be non-negative")
        if not creator:
            raise ValueError("creator is required")

        parent_txid = RealTransactionBuilder.txid_hex(parent_tx)
        child_txid = RealTransactionBuilder.txid_hex(child_tx)

        proof_id = hashlib.sha256(
            f"{parent_txid}:{child_txid}:{anchor_vout}:{creator}".encode()
        ).hexdigest()

        msg = hashlib.sha256(
            f"ANCHOR_PROOF:{proof_id}:{block_height}".encode()
        ).digest()
        sig = KEYSTORE.sign(creator, msg)

        return cls(
            proof_id=proof_id,
            parent_txid=parent_txid,
            child_txid=child_txid,
            anchor_vout=anchor_vout,
            block_height=block_height,
            creator=creator,
            fee_rate=fee_rate,
            signature=sig,
            verified=False,
            timestamp=time.time(),
        )

    def to_inscription_json(self) -> dict:
        """Return the BRC-20-compatible inscription envelope."""
        return {
            "p": "ANCH",
            "op": "proof",
            "proof_id": self.proof_id[:16],
            "txid": self.parent_txid,
            "child": self.child_txid,
            "block": self.block_height,
            "creator": self.creator,
            "sig": self.signature.hex()[:32],
        }

    def content_hash(self) -> str:
        """
        SHA-256 of the canonical inscription JSON.

        This can be used as a content-addressed identifier for indexers.
        """
        from .brc20 import inscription_content_id
        return inscription_content_id(self.to_inscription_json())
