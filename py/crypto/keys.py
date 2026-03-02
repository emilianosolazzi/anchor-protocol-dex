"""
Bitcoin key store -- secp256k1 key management via coincurve.

Provides the module-level KEYSTORE singleton used throughout the package.
"""
from __future__ import annotations

import hashlib
from typing import Dict

from coincurve import PrivateKey, PublicKey
from bitcoin.core import CScript
from bitcoin.core.script import (
    OP_0, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
)


class BitcoinKeyStore:
    """
    Deterministic secp256k1 key store.
    Maps aliases (e.g. "alice", "bob") to real keypairs.
    """

    def __init__(self):
        self._keys: Dict[str, PrivateKey] = {}

    def _ensure(self, alias: str):
        if alias not in self._keys:
            seed = hashlib.sha256(f"anchor_dex_key:{alias}".encode()).digest()
            self._keys[alias] = PrivateKey(seed)

    def get_or_create(self, alias: str) -> PrivateKey:
        self._ensure(alias)
        return self._keys[alias]

    def pubkey(self, alias: str) -> bytes:
        self._ensure(alias)
        return self._keys[alias].public_key.format(compressed=True)

    def pubkey_hash(self, alias: str) -> bytes:
        """HASH160(pubkey) = RIPEMD160(SHA256(pubkey))."""
        import hashlib as _hl
        pk = self.pubkey(alias)
        sha = _hl.sha256(pk).digest()
        return _hl.new('ripemd160', sha).digest()

    def p2pkh_scriptpubkey(self, alias: str) -> CScript:
        """OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG"""
        return CScript([OP_DUP, OP_HASH160, self.pubkey_hash(alias),
                        OP_EQUALVERIFY, OP_CHECKSIG])

    def p2wpkh_scriptpubkey(self, alias: str) -> CScript:
        """OP_0 <pkh>   (native SegWit v0)"""
        return CScript([OP_0, self.pubkey_hash(alias)])

    def sign(self, alias: str, msg: bytes) -> bytes:
        """Sign a 32-byte hash with the alias's private key (DER)."""
        self._ensure(alias)
        return self._keys[alias].sign(msg, hasher=None)

    def verify(self, alias: str, sig: bytes, msg: bytes) -> bool:
        """Verify a DER signature against the alias's public key."""
        self._ensure(alias)
        pub = PublicKey(self.pubkey(alias))
        try:
            return pub.verify(sig, msg, hasher=None)
        except Exception:
            return False

    def address_hex(self, alias: str) -> str:
        """Mock bech32m-style address for display."""
        pkh = self.pubkey_hash(alias)
        return f"bcrt1q{pkh.hex()}"

    def info(self, alias: str) -> dict:
        self._ensure(alias)
        return {
            "alias": alias,
            "pubkey_hex": self.pubkey(alias).hex(),
            "pubkey_hash_hex": self.pubkey_hash(alias).hex(),
            "address": self.address_hex(alias),
        }


# Module-level singleton -- imported everywhere
KEYSTORE = BitcoinKeyStore()
