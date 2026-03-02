"""
OP_CHECKTEMPLATEVERIFY (BIP-119) implementation.

Computes the CTV template hash that commits to the spending
transaction's shape -- nVersion, nLockTime, scriptSigs hash,
input count, sequences hash, output count, outputs hash, and
the input index.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
"""
from __future__ import annotations

import hashlib
import struct
from typing import List

from bitcoin.core import CTransaction, CScript

from .opcodes import OpCode, sha256, tagged_hash, compact_size, tapleaf_hash


class CTVTemplate:
    """
    Full BIP-119 OP_CHECKTEMPLATEVERIFY implementation.

    The template hash commits to the spending transaction's shape
    without committing to the input outpoints, enabling recursive
    covenants and vaults.
    """

    @staticmethod
    def compute_sequences_hash(tx: CTransaction) -> bytes:
        """SHA256 of all input nSequence values (uint32 LE each)."""
        sequences = b''.join(
            struct.pack('<I', inp.nSequence) for inp in tx.vin
        )
        return hashlib.sha256(sequences).digest()

    @staticmethod
    def compute_outputs_hash(tx: CTransaction) -> bytes:
        """
        SHA256 of all serialized CTxOut.

        Each output is serialized as:
          int64_t  nValue           (8 bytes, little-endian)
          CompactSize scriptPubKeyLen
          bytes    scriptPubKey

        This matches the canonical CTxOut wire format.
        WARNING: the scriptPubKey length prefix is required --
        omitting it produces an incorrect template hash that
        will fail OP_CTV verification on-chain.
        """
        outputs = b''.join(
            struct.pack('<q', out.nValue)
            + compact_size(len(out.scriptPubKey))
            + bytes(out.scriptPubKey)
            for out in tx.vout
        )
        return hashlib.sha256(outputs).digest()

    @staticmethod
    def compute_scriptsigs_hash(tx: CTransaction) -> bytes:
        """
        SHA256 of all input scriptSigs.

        For SegWit inputs (which have empty scriptSigs), this is
        SHA256(b'') repeated per input.  BIP-119 includes this to
        prevent txid malleation in legacy inputs.
        """
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

        DefaultCheckTemplateVerifyHash:
          SHA256(
            nVersion          (4 bytes, int32 LE)
            nLockTime         (4 bytes, uint32 LE)
            scriptSigsHash    (32 bytes)
            numInputs         (4 bytes, uint32 LE)
            sequencesHash     (32 bytes)
            numOutputs        (4 bytes, uint32 LE)
            outputsHash       (32 bytes)
            inputIndex        (4 bytes, uint32 LE)
          )

        This is what OP_CTV checks against the top stack element.
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
        """
        Build a BIP-341 Taproot leaf containing a CTV check.

        Uses the proper tagged hash:
          tagged_hash("TapLeaf",
            leaf_version || compact_size(len(script)) || script)
        """
        script = bytes(CScript(template_hash + bytes([OpCode.OP_CTV])))
        return tapleaf_hash(script, leaf_version=OpCode.TAPSCRIPT_LEAF_VERSION)

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
