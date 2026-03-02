"""
OP_CHECKSIGFROMSTACK (Elements / Liquid) covenant.

Verifies a signature against an arbitrary stack message rather
than the transaction itself.
"""
from __future__ import annotations

from bitcoin.core import CScript

from .opcodes import OpCode, sha256
from ..crypto.keys import KEYSTORE


class CSFSCovenant:
    """
    Elements-style OP_CHECKSIGFROMSTACK covenant.
    Allows signature verification against an arbitrary message
    (not the spending transaction).
    """

    @staticmethod
    def build_csfs_covenant_script(
        operator_key: bytes,
        expected_state_hash: bytes,
    ) -> CScript:
        """
        Script:
          <expected_state_hash> OP_SHA256 OP_EQUALVERIFY
          <operator_key> OP_CHECKSIGFROMSTACK

        Verifies that the state hash matches and the operator signed it.
        """
        return CScript(
            expected_state_hash
            + bytes([0xa8])  # OP_SHA256
            + sha256(expected_state_hash)
            + bytes([0x88])  # OP_EQUALVERIFY
            + operator_key
            + bytes([OpCode.OP_CHECKSIGFROMSTACK])
        )

    @staticmethod
    def sign_state_transition(
        operator_alias: str,
        state_data: bytes,
    ) -> bytes:
        """Sign an arbitrary state transition message with CSFS."""
        msg_hash = sha256(b"CSFS_STATE:" + state_data)
        return KEYSTORE.sign(operator_alias, msg_hash)

    @staticmethod
    def verify_state_signature(
        operator_alias: str,
        signature: bytes,
        state_data: bytes,
    ) -> bool:
        """Verify a CSFS state signature."""
        msg_hash = sha256(b"CSFS_STATE:" + state_data)
        return KEYSTORE.verify(operator_alias, signature, msg_hash)

    @staticmethod
    def info() -> dict:
        return {
            "opcode": f"0x{OpCode.OP_CHECKSIGFROMSTACK:02x}",
            "status": "Active on Liquid (Blockstream Elements)",
            "networks": ["liquid", "regtest"],
            "enables": [
                "Arbitrary message signature verification",
                "Oracle-attested state transitions",
                "Delegation covenants",
            ],
        }
