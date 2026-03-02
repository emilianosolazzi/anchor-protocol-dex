"""
Real Bitcoin HTLC and multisig scripts.

Uses python-bitcoinlib for actual Bitcoin Script construction.
"""
from __future__ import annotations

import hashlib
from typing import List

from bitcoin.core import CScript
from bitcoin.core.script import (
    OP_IF, OP_ELSE, OP_ENDIF,
    OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG,
    OP_CHECKLOCKTIMEVERIFY, OP_DROP,
    OP_CHECKMULTISIG, OP_0,
)


class RealHTLCScript:
    """
    HTLC using real Bitcoin Script opcodes.

    Script:
      OP_IF
        OP_SHA256 <secret_hash> OP_EQUALVERIFY
        <recipient_pubkey> OP_CHECKSIG
      OP_ELSE
        <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
        <sender_pubkey> OP_CHECKSIG
      OP_ENDIF
    """

    def __init__(self, sender_pubkey: bytes, recipient_pubkey: bytes,
                 secret_hash: bytes, timelock_blocks: int = 144):
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

        script_hash = hashlib.sha256(self.redeem_script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def hex(self) -> str:
        return self.redeem_script.hex()

    def claim_witness(self, signature: bytes, secret: bytes) -> List[bytes]:
        return [signature, secret, b'\x01', self.redeem_script]

    def refund_witness(self, signature: bytes) -> List[bytes]:
        return [signature, b'', self.redeem_script]

    def info(self) -> dict:
        return {
            "redeem_script_hex": self.hex(),
            "redeem_script_size": len(self.redeem_script),
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "timelock": self.timelock_blocks,
            "sender_pubkey": self.sender_pubkey.hex(),
            "recipient_pubkey": self.recipient_pubkey.hex(),
            "secret_hash": self.secret_hash.hex(),
        }


class RealMultiSigScript:
    """
    M-of-N multisig script using real Bitcoin opcodes.

    Script:
      OP_<M> <pubkey1> ... <pubkeyN> OP_<N> OP_CHECKMULTISIG
    """

    def __init__(self, m: int, pubkeys: List[bytes]):
        self.m = m
        self.n = len(pubkeys)
        self.pubkeys = pubkeys

        self.script = CScript([m] + pubkeys + [self.n, OP_CHECKMULTISIG])

        script_hash = hashlib.sha256(self.script).digest()
        self.p2wsh_scriptpubkey = CScript([OP_0, script_hash])

    def hex(self) -> str:
        return self.script.hex()

    def info(self) -> dict:
        return {
            "type": f"{self.m}-of-{self.n} multisig",
            "script_hex": self.hex(),
            "script_size": len(self.script),
            "p2wsh_hex": self.p2wsh_scriptpubkey.hex(),
            "pubkeys": [pk.hex() for pk in self.pubkeys],
        }
