"""
Covenant primitives: opcodes, hash helpers, serialization, and network enum.

BIP-340 tagged hashes, BIP-341 Taproot key tweaking, CompactSize
serialization, and the hypothetical / soft-fork opcode constants
used by all covenant strategies.
"""
from __future__ import annotations

import hashlib
import struct
from enum import Enum


# ---------------------------------------------------------------------------
# Opcode constants
# ---------------------------------------------------------------------------

class OpCode:
    """
    Hypothetical / soft-fork Bitcoin opcodes used by covenant strategies.

    Namespace note:
      - Script opcodes (OP_*) live in the script interpreter.
      - Sighash type flags (SIGHASH_*) are appended to signatures and
        interpreted during signature verification — they are NOT opcodes.
      These namespaces never collide on-chain even if numeric values overlap.
    """
    # Re-enabled (BIP-347, active on Inquisition Signet + Liquid)
    OP_CAT = 0x7e

    # BIP-119 OP_CHECKTEMPLATEVERIFY
    OP_CTV = 0xb3

    # BIP-342 OP_CHECKSIGADD (tapscript multi-sig replacement)
    OP_CHECKSIGADD = 0xba

    # Elements / Liquid -- OP_CHECKSIGFROMSTACK / VERIFY
    # (No assigned opcode in mainnet Bitcoin proposals yet;
    #  Elements uses 0xc1/0xc2 in its own script interpreter.)
    OP_CHECKSIGFROMSTACK = 0xc1
    OP_CHECKSIGFROMSTACKVERIFY = 0xc2

    # BIP-118 sighash type flags (NOT opcodes)
    SIGHASH_ANYPREVOUT = 0x41
    SIGHASH_ANYPREVOUTANYSCRIPT = 0xc1

    # Common script opcodes referenced in covenant scripts
    OP_SHA256 = 0xa8
    OP_EQUALVERIFY = 0x88
    OP_DROP = 0x75
    OP_CHECKSIG = 0xac
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_IF = 0x63
    OP_ELSE = 0x67
    OP_ENDIF = 0x68

    # Tapscript leaf versions (BIP-342)
    TAPSCRIPT_LEAF_VERSION = 0xc0

    # Maximum script element size (consensus rule, applies to OP_CAT result)
    MAX_SCRIPT_ELEMENT_SIZE = 520

    @staticmethod
    def info() -> dict:
        return {
            "OP_CAT":  "0x7e -- BIP-347, re-enables concatenation (max 520 bytes)",
            "OP_CTV":  "0xb3 -- BIP-119, output template locking",
            "OP_CHECKSIGADD": "0xba -- BIP-342, tapscript multi-sig",
            "APO":     "0x41 -- BIP-118, input-agnostic sighash flag",
            "CSFS":    "0xc1 -- Elements, arbitrary message sig check",
        }


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """SHA-256 helper (single round)."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Double SHA-256 (Bitcoin's standard hash)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# Cache tag hashes: SHA256(tag) is constant per tag string, so we
# precompute once.  This matches Bitcoin Core's optimization.
# Re-export from crypto.keys to avoid duplicate implementations.
from ..crypto.keys import tagged_hash  # noqa: F401


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) -- used in P2PKH, P2SH."""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# CompactSize serialization (Bitcoin varint)
# ---------------------------------------------------------------------------

def compact_size(n: int) -> bytes:
    """
    Encode an integer as Bitcoin's CompactSize (variable-length integer).

    Used in transaction serialization for counts and lengths:
      0x00-0xfc       -> 1 byte
      0xfd-0xffff     -> 0xfd + uint16 LE
      0x10000-0xffffffff -> 0xfe + uint32 LE
      larger          -> 0xff + uint64 LE
    """
    if n < 0:
        raise ValueError(f"compact_size: negative value {n}")
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


# ---------------------------------------------------------------------------
# Taproot key tweaking (BIP-341)
# ---------------------------------------------------------------------------

def taproot_tweak_pubkey(internal_key: bytes, merkle_root: bytes) -> bytes:
    """
    BIP-341 Taproot output key computation (simulated).

    Real computation:
      t = tagged_hash("TapTweak", internal_key || merkle_root)
      Q = P + t*G   (secp256k1 point addition)

    Since point addition requires elliptic curve arithmetic, we simulate
    the tweaked key as tagged_hash("TapTweak", P || h) which produces a
    deterministic 32-byte result suitable for testing script logic.
    The on-chain version would use coincurve for real point math.
    """
    tweak = tagged_hash("TapTweak", internal_key + merkle_root)
    # Simulated: in production this would be P + tweak*G
    # We return the tweak itself as a stand-in for the tweaked x-only pubkey
    return tweak


def taproot_tweak_pubkey_real(
    internal_key: bytes,
    merkle_root: bytes,
) -> bytes:
    """
    BIP-341 Taproot output key -- REAL point arithmetic via coincurve.

    Computes Q = P + tagged_hash("TapTweak", P || merkle_root) * G.
    Requires the internal_key to be a valid 33-byte compressed public key.
    """
    from coincurve import PublicKey, PrivateKey

    tweak_scalar = tagged_hash("TapTweak", internal_key[1:] + merkle_root)
    # tweak * G
    tweak_point = PublicKey.from_secret(tweak_scalar)
    # Q = P + tweak*G
    combined = PublicKey.combine_keys([
        PublicKey(internal_key),
        tweak_point,
    ])
    # Return x-only (32 bytes) for Taproot output key
    return combined.format(compressed=True)[1:]


def tapleaf_hash(script: bytes, leaf_version: int = 0xc0) -> bytes:
    """
    BIP-341 TapLeaf hash.

    tagged_hash("TapLeaf", leaf_version || compact_size(len(script)) || script)
    """
    return tagged_hash(
        "TapLeaf",
        bytes([leaf_version]) + compact_size(len(script)) + script,
    )


def tapbranch_hash(left: bytes, right: bytes) -> bytes:
    """
    BIP-341 TapBranch hash.

    tagged_hash("TapBranch", sorted(left, right))
    Branches are sorted lexicographically for canonical ordering.
    """
    if left > right:
        left, right = right, left
    return tagged_hash("TapBranch", left + right)


# ---------------------------------------------------------------------------
# Network enum
# ---------------------------------------------------------------------------

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
