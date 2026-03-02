"""
SIGHASH_ANYPREVOUT (BIP-118) covenant.

BIP-118 introduces two new sighash types for Tapscript:
  - SIGHASH_ANYPREVOUT (0x41): Does *not* commit to the input
    outpoint or the spending UTXO's scriptPubKey, but still commits
    to all outputs, other inputs, and the leaf script.
  - SIGHASH_ANYPREVOUTANYSCRIPT (0xc1): Additionally does *not*
    commit to the spending script or leaf hash, making the
    signature fully reusable across any Tapscript leaf.

This enables:
  - LN-Symmetry (eltoo): Latest-state-wins channel updates where
    any later state can spend any earlier state without revocation.
  - Rebindable transactions: The same signed tx can spend different
    UTXOs, enabling efficient protocol rounds.
  - Channel factories and multiparty protocols.

Real BIP-118 sighash algorithm (not fully simulated):
  1. Epoch byte 0x00 (future upgrade path)
  2. hash_type byte
  3. SigMsg fields per BIP-341, but with outpoint and amounts
     omitted for ANYPREVOUT, and additionally script/leaf omitted
     for ANYPREVOUTANYSCRIPT.
  Our simulation uses a domain-separated hash to approximate this:
    SHA256("APO_SIGHASH_v1:" || epoch || hash_type || tx_data)

Reference: https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki
"""
from __future__ import annotations

import hashlib
import struct
from typing import Optional

from bitcoin.core import CScript
from coincurve import PrivateKey, PublicKey

from .opcodes import OpCode, sha256


# BIP-118: Epoch byte prepended to sighash message for future extensibility
_APO_EPOCH: int = 0x00

# Domain separator for our simulated APO sighash (versioned)
_APO_DOMAIN = b"APO_SIGHASH_v1:"


class APOCovenant:
    """
    BIP-118 SIGHASH_ANYPREVOUT implementation.

    Key properties:
      - Signatures are rebindable (valid for any input spending the
        same script, unlike normal SIGHASH_ALL).
      - Enables LN-Symmetry update mechanism where each new state
        can supersede any older state without revocation toxicity.
      - Requires Tapscript (BIP-342) — APO sighash types are only
        valid inside Tapscript execution.
    """

    @staticmethod
    def build_apo_update_script(update_key: bytes) -> CScript:
        """
        Simple APO script: <update_key> OP_CHECKSIG

        The signature uses SIGHASH_ANYPREVOUT so the same sig
        is valid regardless of which UTXO is being spent — the
        script only checks the key, not the outpoint.
        """
        return CScript(
            update_key + bytes([OpCode.OP_CHECKSIG])
        )

    @staticmethod
    def build_apo_pool_script(
        update_key: bytes,
        state_hash: bytes,
    ) -> CScript:
        """
        Pool update script with embedded state commitment:
          <state_hash> OP_DROP <update_key> OP_CHECKSIG

        The state hash is pushed and dropped — it doesn't affect
        script execution but is committed in the leaf script
        itself, so any indexer can extract the pool state from
        the witness/script without executing it.
        """
        return CScript(
            state_hash
            + bytes([OpCode.OP_DROP])
            + update_key
            + bytes([OpCode.OP_CHECKSIG])
        )

    @staticmethod
    def build_ln_symmetry_script(
        update_key: bytes,
        state_number: int,
        settlement_delay: int = 144,
    ) -> CScript:
        """
        LN-Symmetry (eltoo) update script with two spending paths:

        Path 1 — Update (APO signature, no timelock):
          OP_IF
            <update_key> OP_CHECKSIG
          OP_ELSE

        Path 2 — Settle (after relative timelock):
            <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
            <update_key> OP_CHECKSIG
          OP_ENDIF

        The update path uses SIGHASH_ANYPREVOUT so any later state
        can spend any earlier state.  The settle path requires waiting
        for the timelock, giving the counterparty time to broadcast
        a newer state.
        """
        # Encode delay as minimal CScriptNum (little-endian, no unnecessary zero padding)
        delay_bytes = settlement_delay.to_bytes(
            (settlement_delay.bit_length() + 8) // 8, 'little'
        ) if settlement_delay > 0 else b'\x00'
        # Encode state number as 4-byte LE for indexer consumption
        state_bytes = struct.pack('<I', state_number)

        return CScript(
            # Commit state number (dropped, for indexer only)
            state_bytes
            + bytes([OpCode.OP_DROP])
            + bytes([OpCode.OP_IF])
            # Update path: rebindable APO signature
            + update_key
            + bytes([OpCode.OP_CHECKSIG])
            + bytes([OpCode.OP_ELSE])
            # Settle path: timelock + signature
            + delay_bytes
            + bytes([OpCode.OP_CHECKSEQUENCEVERIFY, OpCode.OP_DROP])
            + update_key
            + bytes([OpCode.OP_CHECKSIG])
            + bytes([OpCode.OP_ENDIF])
        )

    @staticmethod
    def _compute_sighash(
        tx_data: bytes,
        hash_type: int = OpCode.SIGHASH_ANYPREVOUT,
    ) -> bytes:
        """
        Compute a simulated BIP-118 sighash.

        Real BIP-118 constructs the sighash as:
          SHA256(epoch || hash_type || <BIP-341 SigMsg with omitted fields>)

        We simulate this with a domain-separated hash:
          SHA256("APO_SIGHASH_v1:" || epoch || hash_type || tx_data)

        The domain prefix ensures our simulated sighash can never
        collide with real Bitcoin sighash messages.
        """
        return sha256(
            _APO_DOMAIN
            + bytes([_APO_EPOCH, hash_type])
            + tx_data
        )

    @staticmethod
    def create_apo_signature(
        private_key: PrivateKey,
        tx_data: bytes,
        hash_type: int = OpCode.SIGHASH_ANYPREVOUT,
    ) -> bytes:
        """
        Create a simulated APO signature.

        The signature commits to the hash_type (ANYPREVOUT or
        ANYPREVOUTANYSCRIPT), which is appended as the last byte
        per BIP-341 signature encoding.
        """
        sighash = APOCovenant._compute_sighash(tx_data, hash_type)
        sig = private_key.sign(sighash, hasher=None)
        # Append sighash type byte (BIP-341 convention)
        return sig + bytes([hash_type])

    @staticmethod
    def create_anyprevoutanyscript_signature(
        private_key: PrivateKey,
        tx_data: bytes,
    ) -> bytes:
        """
        Create SIGHASH_ANYPREVOUTANYSCRIPT signature — the most
        flexible variant.  Does not commit to outpoint, script,
        or leaf hash.  Useful for LN-Symmetry updates where the
        same signature works across any leaf script version.
        """
        return APOCovenant.create_apo_signature(
            private_key, tx_data,
            hash_type=OpCode.SIGHASH_ANYPREVOUTANYSCRIPT,
        )

    @staticmethod
    def verify_apo_signature(
        pubkey: bytes,
        signature: bytes,
        tx_data: bytes,
    ) -> bool:
        """
        Verify an APO-style signature.

        Extracts the sighash type from the last byte and recomputes
        the sighash to verify against.
        """
        if len(signature) < 2:
            return False
        sig_body = signature[:-1]
        hash_type = signature[-1]
        sighash = APOCovenant._compute_sighash(tx_data, hash_type)
        try:
            pub = PublicKey(pubkey)
            return pub.verify(sig_body, sighash, hasher=None)
        except Exception:
            return False

    @staticmethod
    def info() -> dict:
        return {
            "bip": "BIP-118",
            "epoch": _APO_EPOCH,
            "sighash_types": {
                "ANYPREVOUT": f"0x{OpCode.SIGHASH_ANYPREVOUT:02x}",
                "ANYPREVOUTANYSCRIPT": f"0x{OpCode.SIGHASH_ANYPREVOUTANYSCRIPT:02x}",
            },
            "status": "Active on Bitcoin Inquisition Signet",
            "requires": "Tapscript execution (BIP-342)",
            "enables": [
                "LN-Symmetry (eltoo) — latest-state-wins channels",
                "Floating/rebindable transactions",
                "Rebindable HTLCs for efficient routing",
                "Channel factories with O(1) on-chain footprint",
                "Efficient multiparty state machines",
            ],
        }
