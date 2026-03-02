"""
Covenant primitives: opcodes, hash helpers, and network enum.
"""
from __future__ import annotations

import hashlib
from enum import Enum


class OpCode:
    """Hypothetical / soft-fork Bitcoin opcodes used by covenant strategies."""
    OP_CAT = 0x7e               # BIP-347 (re-enabled on Inquisition Signet)
    OP_CTV = 0xb3               # BIP-119 OP_CHECKTEMPLATEVERIFY
    SIGHASH_ANYPREVOUT = 0x41   # BIP-118
    SIGHASH_ANYPREVOUTANYSCRIPT = 0xc1
    OP_CHECKSIGFROMSTACK = 0xc1 # Elements / Liquid

    @staticmethod
    def info() -> dict:
        return {
            "OP_CAT": "0x7e -- BIP-347, re-enables concatenation",
            "OP_CTV": "0xb3 -- BIP-119, output template locking",
            "APO":    "0x41 -- BIP-118, input-agnostic sighash",
            "CSFS":   "0xc1 -- Elements, arbitrary message sig check",
        }


def sha256(data: bytes) -> bytes:
    """SHA-256 helper (single round)."""
    return hashlib.sha256(data).digest()


def taproot_tweak_pubkey(internal_key: bytes, merkle_root: bytes) -> bytes:
    """
    BIP-341 style Taproot key tweak.
    t = SHA256(internal_key || merkle_root)
    tweaked = SHA256(internal_key || t)   -- simplified simulation
    """
    t = sha256(internal_key + merkle_root)
    return sha256(internal_key + t)


class CovenantNetwork(Enum):
    """
    Bitcoin network variants with different opcode availability.
    The hybrid engine selects the best strategy for each network.
    """
    REGTEST = "regtest"
    MAINNET = "mainnet"
    INQUISITION_SIGNET = "inquisition_signet"
    LIQUID = "liquid"

    @property
    def has_op_cat(self) -> bool:
        return self in (self.REGTEST, self.INQUISITION_SIGNET, self.LIQUID)

    @property
    def has_op_ctv(self) -> bool:
        return self in (self.REGTEST, self.INQUISITION_SIGNET)

    @property
    def has_apo(self) -> bool:
        return self in (self.REGTEST, self.INQUISITION_SIGNET)

    @property
    def has_csfs(self) -> bool:
        return self in (self.REGTEST, self.LIQUID)

    @property
    def has_presigned_trees(self) -> bool:
        return True  # works on all networks
