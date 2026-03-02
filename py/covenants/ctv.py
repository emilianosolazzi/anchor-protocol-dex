"""
OP_CHECKTEMPLATEVERIFY (BIP-119) implementation.

Computes the CTV template hash that commits to the spending
transaction's shape -- nVersion, nLockTime, scriptSigs hash,
input count, sequences hash, output count, outputs hash, and
the input index.
"""
from __future__ import annotations

import hashlib
import struct
from typing import List

from bitcoin.core import CTransaction, CScript

from .opcodes import OpCode, sha256


class CTVTemplate:
    """Full BIP-119 OP_CHECKTEMPLATEVERIFY implementation."""

    @staticmethod
    def compute_sequences_hash(tx: CTransaction) -> bytes:
        sequences = b''.join(
            struct.pack('<I', inp.nSequence) for inp in tx.vin
        )
        return hashlib.sha256(sequences).digest()

    @staticmethod
    def compute_outputs_hash(tx: CTransaction) -> bytes:
        outputs = b''.join(
            struct.pack('<q', out.nValue) + bytes(out.scriptPubKey)
            for out in tx.vout
        )
        return hashlib.sha256(outputs).digest()

    @staticmethod
    def compute_scriptsigs_hash(tx: CTransaction) -> bytes:
        scriptsigs = b''.join(bytes(inp.scriptSig) for inp in tx.vin)
        return hashlib.sha256(scriptsigs).digest()

    @classmethod
    def compute_template_hash(
        cls,
        tx: CTransaction,
        input_index: int = 0,
    ) -> bytes:
        """
        Compute the BIP-119 template hash for a transaction.
        This is what OP_CTV checks against.
        """
        data = b''
        data += struct.pack('<i', tx.nVersion)
        data += struct.pack('<I', tx.nLockTime)
        data += cls.compute_scriptsigs_hash(tx)
        data += struct.pack('<I', len(tx.vin))
        data += cls.compute_sequences_hash(tx)
        data += struct.pack('<I', len(tx.vout))
        data += cls.compute_outputs_hash(tx)
        data += struct.pack('<I', input_index)
        return hashlib.sha256(data).digest()

    @classmethod
    def from_transaction(
        cls,
        tx: CTransaction,
        input_index: int = 0,
    ) -> bytes:
        """Convenience wrapper for compute_template_hash."""
        return cls.compute_template_hash(tx, input_index)

    @staticmethod
    def build_ctv_script(template_hash: bytes) -> CScript:
        """Build: <hash> OP_CTV"""
        return CScript(template_hash + bytes([OpCode.OP_CTV]))

    @staticmethod
    def build_ctv_tapleaf(template_hash: bytes) -> bytes:
        """Build a Taproot leaf containing a CTV check."""
        script = CScript(template_hash + bytes([OpCode.OP_CTV]))
        leaf_version = 0xc0
        return hashlib.sha256(
            bytes([leaf_version]) + struct.pack('<H', len(script)) + script
        ).digest()

    @staticmethod
    def info() -> dict:
        return {
            "bip": "BIP-119",
            "opcode": f"0x{OpCode.OP_CTV:02x}",
            "status": "Active on Bitcoin Inquisition Signet",
            "commits_to": [
                "nVersion", "nLockTime", "scriptSigsHash",
                "inputCount", "sequencesHash",
                "outputCount", "outputsHash", "inputIndex",
            ],
        }
