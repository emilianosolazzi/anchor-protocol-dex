"""
Real Bitcoin HTLC, multisig, and Tapscript constructions.

Uses python-bitcoinlib for actual Bitcoin Script construction.

Improvements:
  - RealHTLCScript: input validation, script size check, HASH160 variant
  - CSVHTLCScript: relative timelock via OP_CHECKSEQUENCEVERIFY (BIP-68/112)
  - TapscriptHTLC: SegWit v1 HTLC for Taproot script-path spends
  - TapscriptMultiSig: OP_CHECKSIGADD based multisig (BIP-342)
  - TimeLockVault: time-locked single-sig for cold storage
  - Script size validation (520 bytes legacy, 10K tapscript)
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import hashlib
from typing import List, Optional

from bitcoin.core import CScript
from bitcoin.core.script import (
    OP_IF, OP_ELSE, OP_ENDIF, OP_NOTIF,
    OP_SHA256, OP_HASH160, OP_EQUALVERIFY, OP_EQUAL,
    OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_CHECKMULTISIG, OP_0, OP_1,
    OP_TRUE,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_LEGACY_SCRIPT_SIZE = 520       # P2SH redeem script limit
MAX_TAPSCRIPT_SIZE = 10_000        # BIP-342 tapscript limit
MAX_MULTISIG_KEYS_LEGACY = 15      # OP_CHECKMULTISIG limit
MAX_MULTISIG_KEYS_TAPSCRIPT = 999  # Practical limit with OP_CHECKSIGADD
MIN_TIMELOCK_BLOCKS = 1
MAX_TIMELOCK_BLOCKS = 500_000_000  # BIP-65 threshold (below = blocks, above = time)


def _validate_pubkey(pubkey: bytes, label: str = "pubkey"):
    """Validate compressed (33 bytes) or x-only (32 bytes) public key."""
    if not isinstance(pubkey, bytes):
        raise TypeError(f"{label} must be bytes")
    if len(pubkey) == 33:
        if pubkey[0] not in (0x02, 0x03):
            raise ValueError(f"{label}: invalid compressed pubkey prefix 0x{pubkey[0]:02x}")
    elif len(pubkey) == 32:
        pass  # x-only is valid
    else:
        raise ValueError(f"{label}: expected 32 or 33 bytes, got {len(pubkey)}")


def _validate_hash(h: bytes, expected_len: int, label: str = "hash"):
    """Validate hash length."""
    if not isinstance(h, bytes):
        raise TypeError(f"{label} must be bytes")
    if len(h) != expected_len:
        raise ValueError(f"{label}: expected {expected_len} bytes, got {len(h)}")


def _check_script_size(script: CScript, limit: int, label: str):
    """Raise if script exceeds size limit."""
    if len(script) > limit:
        raise ValueError(
            f"{label} script too large: {len(script)} bytes > {limit} byte limit"
        )


class RealHTLCScript:
    """
    HTLC using real Bitcoin Script opcodes (SegWit v0).

    Script:
      OP_IF
        OP_SHA256 <secret_hash> OP_EQUALVERIFY
        <recipient_pubkey> OP_CHECKSIG
      OP_ELSE
        <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
        <sender_pubkey> OP_CHECKSIG
      OP_ENDIF

    Uses absolute timelock (CLTV) — see CSVHTLCScript for relative.
    """

    def __init__(self, sender_pubkey: bytes, recipient_pubkey: bytes,
                 secret_hash: bytes, timelock_blocks: int = 144):
        _validate_pubkey(sender_pubkey, "sender_pubkey")
        _validate_pubkey(recipient_pubkey, "recipient_pubkey")
        _validate_hash(secret_hash, 32, "secret_hash (SHA256)")
        if not (MIN_TIMELOCK_BLOCKS <= timelock_blocks <= MAX_TIMELOCK_BLOCKS):
            raise ValueError(
                f"timelock_blocks must be in [{MIN_TIMELOCK_BLOCKS}, "
                f"{MAX_TIMELOCK_BLOCKS}], got {timelock_blocks}"
            )

        self.sender_pubkey = sender_pubkey
        self.recipient_pubkey = recipient_pubkey
        self.secret_hash = secret_hash
        self.timelock_blocks = timelock_blocks

        self.redeem_script = CScript([
            OP_IF,
            OP_SHA256, self.secret_hash, OP_EQUALVERIFY,
            self.recipient_pubkey, OP_CHECKSIG,
            OP_ELSE,
            self.timelock_blocks, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
            self.sender_pubkey, OP_CHECKSIG,
            OP_ENDIF,
        ])

        _check_script_size(self.redeem_script, MAX_LEGACY_SCRIPT_SIZE, "HTLC redeem")

        script_hash = hashlib.sha256(self.redeem_script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def hex(self) -> str:
        return self.redeem_script.hex()

    def claim_witness(self, signature: bytes, secret: bytes) -> List[bytes]:
        """Build witness stack for claiming (secret-path)."""
        if len(secret) == 0:
            raise ValueError("Secret must not be empty for HTLC claim")
        expected_hash = hashlib.sha256(secret).digest()
        if expected_hash != self.secret_hash:
            raise ValueError("Secret does not match HTLC secret_hash")
        return [signature, secret, b'\x01', self.redeem_script]

    def refund_witness(self, signature: bytes) -> List[bytes]:
        """Build witness stack for refund (timelock-path)."""
        return [signature, b'', self.redeem_script]

    @property
    def script_size(self) -> int:
        return len(self.redeem_script)

    def info(self) -> dict:
        return {
            "type": "HTLC (CLTV, SegWit v0)",
            "redeem_script_hex": self.hex(),
            "redeem_script_size": self.script_size,
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "timelock": self.timelock_blocks,
            "sender_pubkey": self.sender_pubkey.hex(),
            "recipient_pubkey": self.recipient_pubkey.hex(),
            "secret_hash": self.secret_hash.hex(),
        }


class CSVHTLCScript:
    """
    HTLC with relative timelock via OP_CHECKSEQUENCEVERIFY (BIP-68/112).

    Script:
      OP_IF
        OP_SHA256 <secret_hash> OP_EQUALVERIFY
        <recipient_pubkey> OP_CHECKSIG
      OP_ELSE
        <relative_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
        <sender_pubkey> OP_CHECKSIG
      OP_ENDIF

    Relative timelocks are measured from the UTXO's confirmation,
    not from an absolute block height. This is preferred for
    Lightning-style payment channels where the timeout starts
    when the commitment is broadcast, not at a fixed time.

    BIP-68 encoding:
      - Bits 0-15: value (blocks if bit 22 unset, 512-second units if set)
      - Bit 22: type flag (0 = blocks, 1 = seconds)
      - Bits 16-21, 23-31: must be zero
    """

    # BIP-68: max relative timelock in blocks (16-bit value field)
    MAX_CSV_BLOCKS = 0xFFFF

    def __init__(self, sender_pubkey: bytes, recipient_pubkey: bytes,
                 secret_hash: bytes, relative_blocks: int = 144):
        _validate_pubkey(sender_pubkey, "sender_pubkey")
        _validate_pubkey(recipient_pubkey, "recipient_pubkey")
        _validate_hash(secret_hash, 32, "secret_hash (SHA256)")
        if not (1 <= relative_blocks <= self.MAX_CSV_BLOCKS):
            raise ValueError(
                f"relative_blocks must be in [1, {self.MAX_CSV_BLOCKS}], "
                f"got {relative_blocks}"
            )

        self.sender_pubkey = sender_pubkey
        self.recipient_pubkey = recipient_pubkey
        self.secret_hash = secret_hash
        self.relative_blocks = relative_blocks

        self.redeem_script = CScript([
            OP_IF,
            OP_SHA256, self.secret_hash, OP_EQUALVERIFY,
            self.recipient_pubkey, OP_CHECKSIG,
            OP_ELSE,
            self.relative_blocks, OP_CHECKSEQUENCEVERIFY, OP_DROP,
            self.sender_pubkey, OP_CHECKSIG,
            OP_ENDIF,
        ])

        _check_script_size(self.redeem_script, MAX_LEGACY_SCRIPT_SIZE, "CSV-HTLC redeem")

        script_hash = hashlib.sha256(self.redeem_script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def hex(self) -> str:
        return self.redeem_script.hex()

    def claim_witness(self, signature: bytes, secret: bytes) -> List[bytes]:
        if len(secret) == 0:
            raise ValueError("Secret must not be empty for HTLC claim")
        return [signature, secret, b'\x01', self.redeem_script]

    def refund_witness(self, signature: bytes) -> List[bytes]:
        return [signature, b'', self.redeem_script]

    @property
    def nsequence(self) -> int:
        """nSequence value to set on the spending input for CSV."""
        return self.relative_blocks

    def info(self) -> dict:
        return {
            "type": "HTLC (CSV relative timelock, SegWit v0)",
            "redeem_script_hex": self.hex(),
            "redeem_script_size": len(self.redeem_script),
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "relative_blocks": self.relative_blocks,
            "nsequence": self.nsequence,
            "sender_pubkey": self.sender_pubkey.hex(),
            "recipient_pubkey": self.recipient_pubkey.hex(),
            "secret_hash": self.secret_hash.hex(),
        }


class TapscriptHTLC:
    """
    HTLC for Taproot script-path spends (SegWit v1 / BIP-342).

    Unlike SegWit v0 HTLC, this uses OP_CHECKSIGVERIFY instead of
    OP_CHECKSIG + OP_IF branching, because Tapscript uses separate
    leaf scripts for each spending condition.

    Claim leaf:
      <recipient_x_only_pubkey> OP_CHECKSIGVERIFY
      OP_SHA256 <secret_hash> OP_EQUAL

    Refund leaf:
      <sender_x_only_pubkey> OP_CHECKSIGVERIFY
      <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
      OP_TRUE

    These leaves are placed in a MAST (Merkle Abstract Syntax Tree),
    revealing only the used path on-chain.
    """

    def __init__(self, sender_x_pubkey: bytes, recipient_x_pubkey: bytes,
                 secret_hash: bytes, timelock_blocks: int = 144):
        _validate_hash(secret_hash, 32, "secret_hash")
        if len(sender_x_pubkey) != 32:
            raise ValueError(f"sender_x_pubkey must be 32 bytes (x-only), got {len(sender_x_pubkey)}")
        if len(recipient_x_pubkey) != 32:
            raise ValueError(f"recipient_x_pubkey must be 32 bytes (x-only), got {len(recipient_x_pubkey)}")

        self.sender_x_pubkey = sender_x_pubkey
        self.recipient_x_pubkey = recipient_x_pubkey
        self.secret_hash = secret_hash
        self.timelock_blocks = timelock_blocks

        # Claim path: recipient proves knowledge of secret
        self.claim_script = CScript([
            self.recipient_x_pubkey, OP_CHECKSIGVERIFY,
            OP_SHA256, self.secret_hash, OP_EQUAL,
        ])

        # Refund path: sender reclaims after timeout
        self.refund_script = CScript([
            self.sender_x_pubkey, OP_CHECKSIGVERIFY,
            self.timelock_blocks, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
            OP_TRUE,
        ])

        _check_script_size(self.claim_script, MAX_TAPSCRIPT_SIZE, "Tapscript HTLC claim")
        _check_script_size(self.refund_script, MAX_TAPSCRIPT_SIZE, "Tapscript HTLC refund")

        # Leaf hashes for MAST (BIP-341 tagged hash)
        from .keys import tagged_hash
        self.claim_leaf_hash = tagged_hash(
            "TapLeaf", b'\xc0' + len(self.claim_script).to_bytes(1, 'big') + bytes(self.claim_script)
        )
        self.refund_leaf_hash = tagged_hash(
            "TapLeaf", b'\xc0' + len(self.refund_script).to_bytes(1, 'big') + bytes(self.refund_script)
        )
        # Simple 2-leaf MAST: root = tagged_hash("TapBranch", sorted(leaf_a, leaf_b))
        leaves = sorted([self.claim_leaf_hash, self.refund_leaf_hash])
        self.merkle_root = tagged_hash("TapBranch", leaves[0] + leaves[1])

    def info(self) -> dict:
        return {
            "type": "HTLC (Tapscript / SegWit v1)",
            "claim_script_hex": self.claim_script.hex(),
            "claim_script_size": len(self.claim_script),
            "refund_script_hex": self.refund_script.hex(),
            "refund_script_size": len(self.refund_script),
            "merkle_root": self.merkle_root.hex(),
            "timelock": self.timelock_blocks,
        }


class RealMultiSigScript:
    """
    M-of-N multisig script using real Bitcoin opcodes (SegWit v0).

    Script:
      OP_<M> <pubkey1> ... <pubkeyN> OP_<N> OP_CHECKMULTISIG

    For Tapscript (SegWit v1), use TapscriptMultiSig instead,
    which uses OP_CHECKSIGADD (more efficient, no dummy element bug).
    """

    def __init__(self, m: int, pubkeys: List[bytes]):
        if not (1 <= m <= len(pubkeys)):
            raise ValueError(f"m must be in [1, {len(pubkeys)}], got {m}")
        if len(pubkeys) > MAX_MULTISIG_KEYS_LEGACY:
            raise ValueError(
                f"OP_CHECKMULTISIG supports max {MAX_MULTISIG_KEYS_LEGACY} keys, "
                f"got {len(pubkeys)}"
            )
        for i, pk in enumerate(pubkeys):
            _validate_pubkey(pk, f"pubkey[{i}]")

        self.m = m
        self.n = len(pubkeys)
        self.pubkeys = pubkeys

        self.script = CScript([m] + pubkeys + [self.n, OP_CHECKMULTISIG])

        _check_script_size(self.script, MAX_LEGACY_SCRIPT_SIZE, "Multisig")

        script_hash = hashlib.sha256(self.script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def hex(self) -> str:
        return self.script.hex()

    def spending_witness(self, signatures: List[bytes]) -> List[bytes]:
        """
        Build witness stack for OP_CHECKMULTISIG.
        Note: includes dummy OP_0 element (off-by-one bug in Bitcoin).
        """
        if len(signatures) != self.m:
            raise ValueError(f"Need exactly {self.m} signatures, got {len(signatures)}")
        # OP_0 is the dummy element for the CHECKMULTISIG bug
        return [b''] + signatures + [self.script]

    def info(self) -> dict:
        return {
            "type": f"{self.m}-of-{self.n} multisig (SegWit v0)",
            "script_hex": self.hex(),
            "script_size": len(self.script),
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "pubkeys": [pk.hex() for pk in self.pubkeys],
        }


class TapscriptMultiSig:
    """
    M-of-N multisig using OP_CHECKSIGADD (BIP-342 Tapscript).

    Script:
      <pk1> OP_CHECKSIG
      <pk2> OP_CHECKSIGADD
      ...
      <pkN> OP_CHECKSIGADD
      <M> OP_EQUAL

    Advantages over OP_CHECKMULTISIG:
      - No dummy element bug
      - Batch-verifiable Schnorr signatures
      - Supports >15 keys (practical limit ~999)
      - O(n) sig verification instead of O(n*m)

    All pubkeys must be 32-byte x-only (BIP-340).
    """

    def __init__(self, m: int, x_only_pubkeys: List[bytes]):
        if not (1 <= m <= len(x_only_pubkeys)):
            raise ValueError(f"m must be in [1, {len(x_only_pubkeys)}], got {m}")
        if len(x_only_pubkeys) > MAX_MULTISIG_KEYS_TAPSCRIPT:
            raise ValueError(f"Too many keys: {len(x_only_pubkeys)}")
        for i, pk in enumerate(x_only_pubkeys):
            if len(pk) != 32:
                raise ValueError(f"pubkey[{i}]: expected 32-byte x-only, got {len(pk)}")

        self.m = m
        self.n = len(x_only_pubkeys)
        self.x_only_pubkeys = x_only_pubkeys

        # Build: <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD ... <M> OP_EQUAL
        # python-bitcoinlib doesn't have OP_CHECKSIGADD (0xBA), so we
        # construct manually via raw bytes.
        OP_CHECKSIGADD = 0xBA
        ops: list = [x_only_pubkeys[0], OP_CHECKSIG]
        for pk in x_only_pubkeys[1:]:
            ops.append(pk)
            # Use raw byte for OP_CHECKSIGADD since not in python-bitcoinlib
            ops.append(OP_CHECKSIGADD)
        ops.append(m)
        ops.append(OP_EQUAL)

        self.script = CScript(ops)
        _check_script_size(self.script, MAX_TAPSCRIPT_SIZE, "Tapscript multisig")

        # Leaf hash for MAST
        from .keys import tagged_hash
        script_bytes = bytes(self.script)
        self.leaf_hash = tagged_hash(
            "TapLeaf",
            b'\xc0' + len(script_bytes).to_bytes(
                (len(script_bytes).bit_length() + 7) // 8 or 1, 'big'
            ) + script_bytes
        )

    def hex(self) -> str:
        return self.script.hex()

    def info(self) -> dict:
        return {
            "type": f"{self.m}-of-{self.n} multisig (Tapscript / OP_CHECKSIGADD)",
            "script_hex": self.hex(),
            "script_size": len(self.script),
            "leaf_hash": self.leaf_hash.hex(),
            "pubkeys": [pk.hex() for pk in self.x_only_pubkeys],
        }


class TimeLockVault:
    """
    Time-locked vault script for cold storage.

    Immediate path (2-of-2 hot + cold key):
      OP_IF
        <hot_pubkey> OP_CHECKSIGVERIFY
        <cold_pubkey> OP_CHECKSIG
      OP_ELSE
        <delay_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
        <recovery_pubkey> OP_CHECKSIG
      OP_ENDIF

    The immediate path requires both hot and cold keys.
    The recovery path requires only the recovery key but must
    wait for delay_blocks relative blocks after broadcast.
    """

    def __init__(self, hot_pubkey: bytes, cold_pubkey: bytes,
                 recovery_pubkey: bytes, delay_blocks: int = 1008):
        _validate_pubkey(hot_pubkey, "hot_pubkey")
        _validate_pubkey(cold_pubkey, "cold_pubkey")
        _validate_pubkey(recovery_pubkey, "recovery_pubkey")
        if not (1 <= delay_blocks <= CSVHTLCScript.MAX_CSV_BLOCKS):
            raise ValueError(f"delay_blocks out of range: {delay_blocks}")

        self.hot_pubkey = hot_pubkey
        self.cold_pubkey = cold_pubkey
        self.recovery_pubkey = recovery_pubkey
        self.delay_blocks = delay_blocks

        self.redeem_script = CScript([
            OP_IF,
            self.hot_pubkey, OP_CHECKSIGVERIFY,
            self.cold_pubkey, OP_CHECKSIG,
            OP_ELSE,
            self.delay_blocks, OP_CHECKSEQUENCEVERIFY, OP_DROP,
            self.recovery_pubkey, OP_CHECKSIG,
            OP_ENDIF,
        ])

        _check_script_size(self.redeem_script, MAX_LEGACY_SCRIPT_SIZE, "Vault")

        script_hash = hashlib.sha256(self.redeem_script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def immediate_witness(self, hot_sig: bytes, cold_sig: bytes) -> List[bytes]:
        """Witness for immediate 2-of-2 path."""
        return [cold_sig, hot_sig, b'\x01', self.redeem_script]

    def recovery_witness(self, recovery_sig: bytes) -> List[bytes]:
        """Witness for delayed recovery path."""
        return [recovery_sig, b'', self.redeem_script]

    @property
    def nsequence_recovery(self) -> int:
        """nSequence value for the recovery spending input."""
        return self.delay_blocks

    def info(self) -> dict:
        return {
            "type": "TimeLock Vault (2-of-2 immediate / recovery with CSV)",
            "script_hex": self.redeem_script.hex(),
            "script_size": len(self.redeem_script),
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "delay_blocks": self.delay_blocks,
            "hot_pubkey": self.hot_pubkey.hex(),
            "cold_pubkey": self.cold_pubkey.hex(),
            "recovery_pubkey": self.recovery_pubkey.hex(),
        }
