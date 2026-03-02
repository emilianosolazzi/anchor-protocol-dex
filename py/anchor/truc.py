"""
TRUC (v3) transaction builder and AnchorProof dataclass.

Bitcoin Core 28.0+ ephemeral anchor policy: nVersion=3, OP_TRUE 0-sat output.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut, COutPoint, CScript,
)
from bitcoin.core.script import OP_1

from ..crypto.keys import KEYSTORE
from ..crypto.transactions import RealTransactionBuilder


class TRUCTransactionBuilder:
    """
    Build TRUC (v3) transactions with ephemeral anchor outputs.

    Bitcoin Core 28.0+ policy:
      - nVersion = 3 signals TRUC (Topologically Restricted Until Confirmation)
      - Ephemeral anchor = OP_TRUE (0x51) output with 0 sats
      - Must be spent in the same package as the parent (1P1C relay)
      - Max 1 anchor output per tx
    """
    TRUC_VERSION = 3
    OP_TRUE_SCRIPT = CScript([OP_1])  # 0x51 = OP_TRUE

    @classmethod
    def build_parent_with_anchor(
        cls,
        funding_outpoint: COutPoint,
        destination_scriptpubkey: CScript,
        destination_amount: int,
    ) -> CTransaction:
        tx = CMutableTransaction()
        tx.nVersion = cls.TRUC_VERSION
        tx.vin = [CTxIn(funding_outpoint)]
        tx.vout = [
            CTxOut(destination_amount, destination_scriptpubkey),
            CTxOut(0, cls.OP_TRUE_SCRIPT),  # ephemeral anchor
        ]
        return CTransaction.from_tx(tx)

    @classmethod
    def build_anchor_child(
        cls,
        parent_txid: bytes,
        anchor_vout: int,
        fee_amount: int,
        change_scriptpubkey: CScript,
        change_amount: int,
    ) -> CTransaction:
        tx = CMutableTransaction()
        tx.nVersion = cls.TRUC_VERSION
        tx.vin = [CTxIn(COutPoint(parent_txid, anchor_vout))]
        tx.vout = [CTxOut(change_amount, change_scriptpubkey)]
        return CTransaction.from_tx(tx)

    @classmethod
    def is_truc(cls, tx: CTransaction) -> bool:
        return tx.nVersion == cls.TRUC_VERSION

    @classmethod
    def find_anchor_output(cls, tx: CTransaction) -> Optional[int]:
        for i, out in enumerate(tx.vout):
            if out.nValue == 0 and bytes(out.scriptPubKey) == bytes(cls.OP_TRUE_SCRIPT):
                return i
        return None

    @classmethod
    def info(cls) -> dict:
        return {
            "truc_version": cls.TRUC_VERSION,
            "anchor_script": "OP_TRUE (0x51)",
            "anchor_value": 0,
            "policy": "Bitcoin Core 28.0+ 1P1C package relay",
            "requires": "nVersion=3",
        }


@dataclass
class AnchorProof:
    """
    Deterministic proof that an ephemeral anchor was created and spent.
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
        """Create a new AnchorProof and sign it with the creator's key."""
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
        return {
            "p": "ANCH",
            "op": "proof",
            "proof_id": self.proof_id[:16],
            "txid": self.parent_txid,
            "child": self.child_txid,
            "block": self.block_height,
            "sig": self.signature.hex()[:32],
        }
