"""
SIGHASH_ANYPREVOUT (BIP-118) covenant.

Enables signatures that don't commit to the input outpoint,
allowing floating transactions and LN-Symmetry.
"""
from __future__ import annotations

import hashlib

from bitcoin.core import CScript
from coincurve import PrivateKey, PublicKey

from .opcodes import OpCode, sha256


class APOCovenant:
    """
    BIP-118 SIGHASH_ANYPREVOUT implementation.
    Signatures don't commit to the input outpoint, enabling
    rebindable transactions.
    """

    @staticmethod
    def build_apo_update_script(update_key: bytes) -> CScript:
        """
        Simple APO script: <update_key> OP_CHECKSIG
        With SIGHASH_ANYPREVOUT the sig is valid for any input.
        """
        return CScript(update_key + bytes([0xac]))  # OP_CHECKSIG

    @staticmethod
    def build_apo_pool_script(
        update_key: bytes,
        state_hash: bytes,
    ) -> CScript:
        """
        Pool update script:
          <state_hash> OP_DROP <update_key> OP_CHECKSIG

        State hash is committed but not checked -- it's for indexer
        verification, not consensus.
        """
        return CScript(
            state_hash
            + bytes([0x75])  # OP_DROP
            + update_key
            + bytes([0xac])  # OP_CHECKSIG
        )

    @staticmethod
    def create_apo_signature(
        private_key: PrivateKey,
        tx_data: bytes,
    ) -> bytes:
        """
        Create a simulated APO signature.
        In real BIP-118, the sighash would exclude the outpoint.
        """
        sighash = sha256(b"APO_SIGHASH:" + tx_data)
        sig = private_key.sign(sighash, hasher=None)
        return sig + bytes([OpCode.SIGHASH_ANYPREVOUT])

    @staticmethod
    def verify_apo_signature(
        pubkey: bytes,
        signature: bytes,
        tx_data: bytes,
    ) -> bool:
        """Verify an APO-style signature."""
        sig_body = signature[:-1]  # strip sighash byte
        sighash = sha256(b"APO_SIGHASH:" + tx_data)
        try:
            pub = PublicKey(pubkey)
            return pub.verify(sig_body, sighash, hasher=None)
        except Exception:
            return False

    @staticmethod
    def info() -> dict:
        return {
            "bip": "BIP-118",
            "sighash_types": {
                "ANYPREVOUT": f"0x{OpCode.SIGHASH_ANYPREVOUT:02x}",
                "ANYPREVOUTANYSCRIPT": f"0x{OpCode.SIGHASH_ANYPREVOUTANYSCRIPT:02x}",
            },
            "status": "Active on Bitcoin Inquisition Signet",
            "enables": [
                "Floating transactions",
                "LN-Symmetry (eltoo)",
                "Rebindable HTLCs",
                "Efficient channel factories",
            ],
        }
