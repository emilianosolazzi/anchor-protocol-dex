"""
Real Bitcoin transaction builder.

Constructs CTransaction objects for HTLC funding, claiming,
refunding, and OP_RETURN outputs.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut,
    COutPoint, CScript,
)
from bitcoin.core.script import (
    OP_RETURN, OP_0,
    SignatureHash, SIGHASH_ALL,
)

from .scripts import RealHTLCScript


class RealTransactionBuilder:
    """Build real Bitcoin transactions for the DEX."""

    @staticmethod
    def build_funding_tx(
        funding_outpoint: COutPoint,
        htlc_script: RealHTLCScript,
        amount: int,
    ) -> CTransaction:
        """Fund an HTLC by sending to the P2WSH address."""
        tx = CMutableTransaction()
        tx.vin = [CTxIn(funding_outpoint)]
        tx.vout = [CTxOut(amount, htlc_script.p2wsh_scriptpubkey)]
        return CTransaction.from_tx(tx)

    @staticmethod
    def build_claim_tx(
        funding_txid: bytes,
        funding_vout: int,
        htlc_script: RealHTLCScript,
        amount: int,
        destination_scriptpubkey: CScript,
    ) -> Tuple[CTransaction, bytes]:
        """
        Build a claim transaction spending the HTLC.
        Returns (unsigned_tx, sighash).
        """
        tx = CMutableTransaction()
        tx.vin = [CTxIn(COutPoint(funding_txid, funding_vout))]
        claim_amount = amount - 1000  # fee
        tx.vout = [CTxOut(claim_amount, destination_scriptpubkey)]
        sighash = SignatureHash(
            htlc_script.redeem_script, tx, 0, SIGHASH_ALL,
        )
        return CTransaction.from_tx(tx), sighash

    @staticmethod
    def build_refund_tx(
        funding_txid: bytes,
        funding_vout: int,
        htlc_script: RealHTLCScript,
        amount: int,
        destination_scriptpubkey: CScript,
    ) -> Tuple[CTransaction, bytes]:
        """
        Build a refund transaction for after the timelock expires.
        Returns (unsigned_tx, sighash).
        """
        tx = CMutableTransaction()
        tx.vin = [CTxIn(COutPoint(funding_txid, funding_vout))]
        tx.nLockTime = htlc_script.timelock_blocks
        refund_amount = amount - 1000  # fee
        tx.vout = [CTxOut(refund_amount, destination_scriptpubkey)]
        sighash = SignatureHash(
            htlc_script.redeem_script, tx, 0, SIGHASH_ALL,
        )
        return CTransaction.from_tx(tx), sighash

    @staticmethod
    def build_op_return_tx(
        funding_outpoint: COutPoint,
        data: bytes,
        change_scriptpubkey: CScript,
        change_amount: int,
    ) -> CTransaction:
        """Build an OP_RETURN output (for RGB state anchoring)."""
        tx = CMutableTransaction()
        tx.vin = [CTxIn(funding_outpoint)]
        op_return_script = CScript([OP_RETURN, data])
        tx.vout = [
            CTxOut(0, op_return_script),
            CTxOut(change_amount, change_scriptpubkey),
        ]
        return CTransaction.from_tx(tx)

    @staticmethod
    def serialize_hex(tx: CTransaction) -> str:
        return tx.serialize().hex()

    @staticmethod
    def txid_hex(tx: CTransaction) -> str:
        return tx.GetTxid().hex()
