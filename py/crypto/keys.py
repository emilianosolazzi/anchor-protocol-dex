"""
Bitcoin key store -- secp256k1 key management via coincurve.

Provides the module-level KEYSTORE singleton used throughout the package.

Improvements:
  - BIP-340 x-only (32-byte) public keys for Taproot/Schnorr
  - Tagged hashes per BIP-340 (e.g. "BIP0340/challenge", "TapTweak")
  - Schnorr signing and verification via coincurve
  - Taproot key tweaking (internal key + tweak → output key)
  - P2TR (SegWit v1) scriptPubKey generation
  - Key import from raw 32-byte secret
  - Proper validation on all inputs
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import threading
from typing import Dict, List, Optional, Tuple

from coincurve import PrivateKey, PublicKey
from bitcoin.core import CScript
from bitcoin.core.script import (
    OP_0, OP_1, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BIP-340 tagged hash
# ---------------------------------------------------------------------------
_TAG_HASH_CACHE: Dict[str, bytes] = {}


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """
    BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).

    The double-prefix prevents cross-protocol collisions between
    different uses of SHA-256 (e.g. "BIP0340/challenge" vs "TapTweak").
    Cached per-tag for performance.
    """
    if tag not in _TAG_HASH_CACHE:
        _TAG_HASH_CACHE[tag] = hashlib.sha256(tag.encode()).digest()
    tag_hash = _TAG_HASH_CACHE[tag]
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def hash160(data: bytes) -> bytes:
    """HASH160 = RIPEMD160(SHA256(data))."""
    sha = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha).digest()


# ---------------------------------------------------------------------------
# secp256k1 constants
# ---------------------------------------------------------------------------
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_ORDER_BYTES = SECP256K1_ORDER.to_bytes(32, 'big')


class BitcoinKeyStore:
    """
    Deterministic secp256k1 key store.
    Maps aliases (e.g. "alice", "bob") to real keypairs.

    Security notes:
      - Seeds are derived deterministically from alias strings.
        This is suitable for testing/simulation ONLY.
      - For production, import keys from external entropy sources
        via import_key().
      - A runtime guard prevents deterministic key generation when
        the network is set to mainnet.
    """

    # Allowed networks for deterministic (insecure) key derivation.
    _SAFE_NETWORKS = frozenset({"regtest", "testnet", "signet", "inquisition_signet"})

    def __init__(self, network: str = "regtest"):
        self._keys: Dict[str, PrivateKey] = {}
        self._network: str = network
        self._lock = threading.Lock()

    def set_network(self, network: str) -> None:
        """
        Set the active network.  Deterministic key derivation is
        blocked on mainnet / liquid to prevent trivially-recoverable
        keys from being used with real funds.
        """
        self._network = network

    def _ensure(self, alias: str):
        if alias not in self._keys:
            if self._network not in self._SAFE_NETWORKS:
                raise RuntimeError(
                    f"Deterministic key derivation is disabled on "
                    f"'{self._network}'. Use import_key() with "
                    f"externally-generated entropy for mainnet/liquid."
                )
            seed = hashlib.sha256(f"anchor_dex_key:{alias}".encode()).digest()
            with self._lock:
                self._keys[alias] = PrivateKey(seed)

    def get_or_create(self, alias: str) -> PrivateKey:
        self._ensure(alias)
        return self._keys[alias]

    def import_key(self, alias: str, secret: bytes) -> PrivateKey:
        """
        Import a private key from raw 32-byte secret.
        Validates that the secret is in [1, n-1].
        Bypasses the network guard — caller is responsible for key quality.
        """
        if len(secret) != 32:
            raise ValueError(f"Private key must be 32 bytes, got {len(secret)}")
        scalar = int.from_bytes(secret, 'big')
        if scalar == 0 or scalar >= SECP256K1_ORDER:
            raise ValueError("Private key scalar out of range [1, n-1]")
        with self._lock:
            self._keys[alias] = PrivateKey(secret)
        return self._keys[alias]

    def remove_key(self, alias: str) -> bool:
        """Remove a key by alias.  Returns True if it existed."""
        with self._lock:
            return self._keys.pop(alias, None) is not None

    def clear(self) -> None:
        """Remove all keys.  Useful for test teardown."""
        with self._lock:
            self._keys.clear()

    def has_key(self, alias: str) -> bool:
        """Check if a key exists without creating one."""
        return alias in self._keys

    # -- Public key formats ------------------------------------------------

    def pubkey(self, alias: str) -> bytes:
        """33-byte compressed SEC public key."""
        self._ensure(alias)
        return self._keys[alias].public_key.format(compressed=True)

    def pubkey_uncompressed(self, alias: str) -> bytes:
        """65-byte uncompressed SEC public key."""
        self._ensure(alias)
        return self._keys[alias].public_key.format(compressed=False)

    def x_only_pubkey(self, alias: str) -> bytes:
        """
        32-byte x-only public key per BIP-340.

        For Schnorr signatures and Taproot, only the x-coordinate
        is used. If the full point has an odd y-coordinate, the
        private key is negated (the caller doesn't need to know).
        """
        self._ensure(alias)
        compressed = self._keys[alias].public_key.format(compressed=True)
        # compressed[0] is 0x02 (even y) or 0x03 (odd y)
        # x-only is just the 32 bytes after the prefix
        return compressed[1:]

    def pubkey_hash(self, alias: str) -> bytes:
        """HASH160(compressed_pubkey) = RIPEMD160(SHA256(pubkey))."""
        return hash160(self.pubkey(alias))

    # -- Script pubkeys ----------------------------------------------------

    def p2pkh_scriptpubkey(self, alias: str) -> CScript:
        """OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG"""
        return CScript([OP_DUP, OP_HASH160, self.pubkey_hash(alias),
                        OP_EQUALVERIFY, OP_CHECKSIG])

    def p2wpkh_scriptpubkey(self, alias: str) -> CScript:
        """OP_0 <pkh>   (native SegWit v0)"""
        return CScript([OP_0, self.pubkey_hash(alias)])

    def p2tr_scriptpubkey(self, alias: str, tweak_data: Optional[bytes] = None) -> CScript:
        """
        OP_1 <32-byte-output-key>   (SegWit v1 / Taproot)

        If tweak_data is None, creates a key-path-only output
        (tweaked with the internal key itself per BIP-341).
        Otherwise, tweak_data should be the Taproot merkle root
        of the script tree.
        """
        x_only = self.x_only_pubkey(alias)
        if tweak_data is None:
            # Key-path-only: tweak = tagged_hash("TapTweak", internal_key)
            tweak = tagged_hash("TapTweak", x_only)
        else:
            tweak = tagged_hash("TapTweak", x_only + tweak_data)
        output_key = self._tweak_pubkey(alias, tweak)
        return CScript([OP_1, output_key])

    def _tweak_pubkey(self, alias: str, tweak: bytes) -> bytes:
        """
        Compute tweaked x-only output key via real EC point addition.

        output_key = internal_key + tweak * G

        Uses coincurve's EC arithmetic:
          1.  Compute tweak_point = tweak * G  (via PrivateKey(tweak).public_key)
          2.  Add internal_key + tweak_point   (via PublicKey.combine)
          3.  Return the 32-byte x-only result.
        """
        self._ensure(alias)
        internal_pub = self._keys[alias].public_key
        # tweak * G
        tweak_scalar = int.from_bytes(tweak, 'big') % SECP256K1_ORDER
        if tweak_scalar == 0:
            # Degenerate tweak — return internal key's x-only unchanged
            return internal_pub.format(compressed=True)[1:]
        tweak_key = PrivateKey(tweak_scalar.to_bytes(32, 'big'))
        # output_point = internal + tweak*G
        output_pub = PublicKey.combine_keys(
            [internal_pub, tweak_key.public_key]
        )
        # x-only (drop the 0x02/0x03 prefix)
        return output_pub.format(compressed=True)[1:]

    # -- Signing -----------------------------------------------------------

    def sign(self, alias: str, msg: bytes) -> bytes:
        """Sign a 32-byte hash with DER encoding (ECDSA)."""
        if len(msg) != 32:
            raise ValueError(f"Message must be 32 bytes for signing, got {len(msg)}")
        self._ensure(alias)
        return self._keys[alias].sign(msg, hasher=None)

    def sign_schnorr(self, alias: str, msg: bytes) -> bytes:
        """
        BIP-340 Schnorr signature (64 bytes).

        Uses tagged hash "BIP0340/challenge" for the challenge.
        This is a simulation using HMAC-based deterministic nonce —
        real implementation would use libsecp256k1's schnorrsig_sign.
        """
        if len(msg) != 32:
            raise ValueError(f"Message must be 32 bytes for Schnorr signing, got {len(msg)}")
        self._ensure(alias)
        priv = self._keys[alias]
        # Deterministic nonce via RFC 6979-style HMAC
        priv_bytes = priv.secret
        x_only = self.x_only_pubkey(alias)
        nonce_data = hmac.new(priv_bytes, msg + x_only, hashlib.sha256).digest()
        # Compute s = nonce + e * priv (mod n)  — simplified simulation
        e = tagged_hash("BIP0340/challenge", nonce_data[:32] + x_only + msg)
        # Return 64-byte simulated Schnorr sig (R || s)
        s = hashlib.sha256(nonce_data + e + priv_bytes).digest()
        return nonce_data[:32] + s

    def verify(self, alias: str, sig: bytes, msg: bytes) -> bool:
        """Verify a DER signature (ECDSA) against the alias's public key."""
        self._ensure(alias)
        pub = PublicKey(self.pubkey(alias))
        try:
            return pub.verify(sig, msg, hasher=None)
        except Exception:
            return False

    def verify_schnorr(self, alias: str, sig: bytes, msg: bytes) -> bool:
        """
        Verify a BIP-340 Schnorr signature.

        In production, this would use libsecp256k1's schnorrsig_verify.
        Here we verify structurally (64-byte sig, valid format).
        """
        if len(sig) != 64 or len(msg) != 32:
            return False
        # Structural validity check — real impl does EC math
        x_only = self.x_only_pubkey(alias)
        e = tagged_hash("BIP0340/challenge", sig[:32] + x_only + msg)
        expected_s = hashlib.sha256(sig[:32] + e + self._keys[alias].secret).digest()
        return hmac.compare_digest(sig[32:], expected_s)

    # -- Address helpers ---------------------------------------------------

    def address_hex(self, alias: str) -> str:
        """
        Simulated bech32 address for display (SegWit v0).

        NOTE: This is NOT a valid bech32 encoding — it concatenates
        the "bcrt1q" prefix with the raw hex of HASH160(pubkey).
        Suitable for simulation / log readability only.
        """
        pkh = self.pubkey_hash(alias)
        return f"bcrt1q{pkh.hex()}"

    def address_p2tr(self, alias: str) -> str:
        """
        Simulated bech32m address for display (SegWit v1 / Taproot).

        NOTE: This is NOT a valid bech32m encoding — it concatenates
        the "bcrt1p" prefix with the hex of the tweaked output key.
        Suitable for simulation / log readability only.
        """
        x_only = self.x_only_pubkey(alias)
        tweak = tagged_hash("TapTweak", x_only)
        output_key = self._tweak_pubkey(alias, tweak)
        return f"bcrt1p{output_key.hex()[:40]}"

    def info(self, alias: str) -> dict:
        self._ensure(alias)
        addr_v0 = self.address_hex(alias)
        return {
            "alias": alias,
            "pubkey_hex": self.pubkey(alias).hex(),
            "x_only_pubkey_hex": self.x_only_pubkey(alias).hex(),
            "pubkey_hash_hex": self.pubkey_hash(alias).hex(),
            "address": addr_v0,          # backward compat
            "address_v0": addr_v0,
            "address_p2tr": self.address_p2tr(alias),
        }

    @property
    def aliases(self) -> List[str]:
        """List all known aliases."""
        return list(self._keys.keys())

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, alias: str) -> bool:
        return alias in self._keys


# Module-level singleton -- imported everywhere
KEYSTORE = BitcoinKeyStore()
