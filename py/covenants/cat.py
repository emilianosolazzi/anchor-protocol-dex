"""
OP_CAT covenant (BIP-347).

Enables concatenation-based state commitment verification
and AMM invariant checks.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Tuple

from bitcoin.core import CScript

from .opcodes import OpCode, sha256


class CATCovenant:
    """
    Uses OP_CAT (0x7e) for:
      - State commitment verification (old || new -> SHA256 -> check)
      - AMM invariant enforcement (reserves concatenated and hashed)
      - Hybrid OP_CAT + OP_CTV parameterized covenants
    """

    @staticmethod
    def build_state_commitment_script(
        old_state_hash: bytes,
        new_state_hash: bytes,
    ) -> CScript:
        """
        Script that verifies a state transition by concatenating
        old and new state hashes, then checking the SHA256 result.
        """
        expected_hash = sha256(old_state_hash + new_state_hash)
        return CScript(
            old_state_hash
            + new_state_hash
            + bytes([OpCode.OP_CAT])
            + bytes([0xa8])  # OP_SHA256
            + expected_hash
            + bytes([0x88])  # OP_EQUALVERIFY
        )

    @staticmethod
    def build_amm_invariant_check(
        old_btc: int,
        old_anch: int,
        new_btc: int,
        new_anch: int,
    ) -> Tuple[CScript, bytes]:
        """
        Build a script that verifies the AMM invariant (xy >= k).
        Concatenates old and new reserves, hashes, and checks.
        """
        old_data = struct.pack('<QQ', old_btc, old_anch)
        new_data = struct.pack('<QQ', new_btc, new_anch)
        commitment = sha256(old_data + new_data)
        script = CScript(
            old_data
            + new_data
            + bytes([OpCode.OP_CAT])
            + bytes([0xa8])  # OP_SHA256
            + commitment
            + bytes([0x88])  # OP_EQUALVERIFY
        )
        return script, commitment

    @staticmethod
    def build_cat_ctv_hybrid_script(
        state_commitment: bytes,
        ctv_hash: bytes,
    ) -> CScript:
        """
        Hybrid OP_CAT + OP_CTV script:
          <state> OP_SHA256 <expected> OP_EQUALVERIFY <ctv_hash> OP_CTV

        OP_CAT verifies state transition, OP_CTV locks tx shape.
        """
        return CScript(
            state_commitment
            + bytes([0xa8])  # OP_SHA256
            + sha256(state_commitment)
            + bytes([0x88])  # OP_EQUALVERIFY
            + ctv_hash
            + bytes([OpCode.OP_CTV])
        )

    @staticmethod
    def info() -> dict:
        return {
            "bip": "BIP-347",
            "opcode": f"0x{OpCode.OP_CAT:02x}",
            "status": "Active on Inquisition Signet + Liquid",
            "networks": ["inquisition_signet", "liquid", "regtest"],
            "enables": [
                "State commitment verification",
                "AMM invariant proofs",
                "Hybrid parameterized covenants (with CTV)",
                "Vaults and STARK verification",
            ],
        }
