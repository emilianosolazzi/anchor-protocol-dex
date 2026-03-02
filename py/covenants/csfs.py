"""
OP_CHECKSIGFROMSTACK / OP_CHECKSIGFROMSTACKVERIFY covenant.

Verifies a Schnorr signature against an **arbitrary** stack message
rather than the spending transaction's sighash.  This decouples
"what was signed" from "how the UTXO is spent", unlocking powerful
covenant patterns like oracle attestation, delegation, and
vault-style protections.

Availability:
  - Active on Liquid / Elements (opcodes 0xc1 / 0xc2 in Elements).
  - Proposed for Bitcoin in various soft-fork discussions (no
    assigned opcode yet; 0xc1 is tentative but collides with the
    Tapscript leaf version reserved byte — different namespace).
  - For Bitcoin proposals, see BIP-348 (draft).

NOTE: The opcode byte 0xc1 in Elements is OP_CHECKSIGFROMSTACK.
In BIP-118, 0xc1 is SIGHASH_ANYPREVOUTANYSCRIPT.  These are in
entirely separate namespaces (script opcode vs sighash flag byte)
and never conflict.

Reference: https://github.com/ElementsProject/elements/blob/master/doc/opcodes.md
"""
from __future__ import annotations

from typing import Optional

from bitcoin.core import CScript

from .opcodes import OpCode, sha256
from ..crypto.keys import KEYSTORE


# Domain separator for CSFS state messages (versioned to prevent
# cross-protocol signature reuse).
_CSFS_DOMAIN = b"CSFS_STATE_v1:"


class CSFSCovenant:
    """
    Elements-style OP_CHECKSIGFROMSTACK covenant.

    Unlike OP_CHECKSIG (which verifies against the transaction
    sighash), OP_CHECKSIGFROMSTACK pops a message, signature,
    and pubkey from the stack and verifies the signature against
    the arbitrary message.  This enables:

      - Oracle-attested state transitions (oracle signs a message
        confirming off-chain state; script verifies on-chain).
      - Delegation covenants (owner pre-signs a permission message
        that a delegate can present to spend).
      - Combined CSFS + CTV: CSFS verifies operator approval,
        CTV locks the spending transaction template.
    """

    @staticmethod
    def build_csfs_covenant_script(
        operator_key: bytes,
        expected_state_hash: bytes,
    ) -> CScript:
        """
        Witness: <signature> <state_data>
        Script:
          <expected_hash> OP_SHA256 <sha256(expected)> OP_EQUALVERIFY
          <operator_key> OP_CHECKSIGFROMSTACKVERIFY

        The script verifies two things:
          1. The provided state_data hashes to the expected value.
          2. The operator signed the state_data.

        Uses OP_CHECKSIGFROMSTACKVERIFY (not OP_CHECKSIGFROMSTACK)
        so that execution continues and additional conditions can
        be composed (e.g., a subsequent OP_CTV).
        """
        return CScript(
            expected_state_hash
            + bytes([OpCode.OP_SHA256])
            + sha256(expected_state_hash)
            + bytes([OpCode.OP_EQUALVERIFY])
            + operator_key
            + bytes([OpCode.OP_CHECKSIGFROMSTACKVERIFY])
        )

    @staticmethod
    def build_csfs_ctv_combined_script(
        operator_key: bytes,
        expected_state_hash: bytes,
        ctv_hash: bytes,
    ) -> CScript:
        """
        Combined CSFS + CTV script for maximum covenant strength:

        Witness: <signature> <state_data>
        Script:
          -- Step 1: Verify state commitment
          <expected_hash> OP_SHA256 <sha256(expected)> OP_EQUALVERIFY
          -- Step 2: Verify operator attestation
          <operator_key> OP_CHECKSIGFROMSTACKVERIFY
          -- Step 3: Lock spending transaction shape
          <ctv_hash> OP_CTV

        This combines three protections:
          - State integrity (SHA256 hash check)
          - Operator approval (CSFS signature)
          - Transaction shape lock (CTV template)
        """
        return CScript(
            expected_state_hash
            + bytes([OpCode.OP_SHA256])
            + sha256(expected_state_hash)
            + bytes([OpCode.OP_EQUALVERIFY])
            + operator_key
            + bytes([OpCode.OP_CHECKSIGFROMSTACKVERIFY])
            + ctv_hash
            + bytes([OpCode.OP_CTV])
        )

    @staticmethod
    def build_delegation_script(
        owner_key: bytes,
        delegate_key: bytes,
    ) -> CScript:
        """
        Delegation covenant script:

        Path 1 — Owner spends directly:
          OP_IF <owner_key> OP_CHECKSIG

        Path 2 — Delegate spends with owner's CSFS authorization:
          OP_ELSE
            <delegate_key> OP_CHECKSIGFROMSTACKVERIFY
            <owner_key> OP_CHECKSIG
          OP_ENDIF

        The delegate must provide:
          a) The owner's CSFS signature over the delegation message
          b) A valid signature from the delegate key
        """
        return CScript(
            bytes([OpCode.OP_IF])
            + owner_key
            + bytes([OpCode.OP_CHECKSIG])
            + bytes([OpCode.OP_ELSE])
            + delegate_key
            + bytes([OpCode.OP_CHECKSIGFROMSTACKVERIFY])
            + owner_key
            + bytes([OpCode.OP_CHECKSIG])
            + bytes([OpCode.OP_ENDIF])
        )

    @staticmethod
    def sign_state_transition(
        operator_alias: str,
        state_data: bytes,
    ) -> bytes:
        """
        Sign an arbitrary state transition message with CSFS.

        Uses a versioned domain separator to prevent cross-protocol
        signature reuse (e.g., a CSFS signature can never be
        mistaken for a BIP-118 APO signature).
        """
        msg_hash = sha256(_CSFS_DOMAIN + state_data)
        return KEYSTORE.sign(operator_alias, msg_hash)

    @staticmethod
    def verify_state_signature(
        operator_alias: str,
        signature: bytes,
        state_data: bytes,
    ) -> bool:
        """Verify a CSFS state signature."""
        msg_hash = sha256(_CSFS_DOMAIN + state_data)
        return KEYSTORE.verify(operator_alias, signature, msg_hash)

    @staticmethod
    def info() -> dict:
        return {
            "opcode_elements": f"0x{OpCode.OP_CHECKSIGFROMSTACK:02x}",
            "opcode_verify_elements": f"0x{OpCode.OP_CHECKSIGFROMSTACKVERIFY:02x}",
            "status": "Active on Liquid (Blockstream Elements)",
            "bitcoin_proposal": "BIP-348 (draft)",
            "networks": ["liquid", "elements", "regtest"],
            "namespace_note": (
                "Opcode 0xc1 in Elements is CSFS; in BIP-118 0xc1 is "
                "SIGHASH_ANYPREVOUTANYSCRIPT — these are different "
                "namespaces (script opcode vs sighash flag) and do "
                "not conflict."
            ),
            "enables": [
                "Arbitrary message signature verification",
                "Oracle-attested state transitions",
                "Delegation covenants (owner authorizes delegate)",
                "Combined CSFS + CTV parameterized covenants",
                "Vault protections with operator attestation",
            ],
        }
