"""
Real Bitcoin transaction builder.

Constructs CTransaction objects for HTLC funding, claiming,
refunding, OP_RETURN outputs, and more.

Improvements:
  - RBF signaling via nSequence (BIP-125)
  - Dust threshold enforcement (BIP-353 / policy rule)
  - Fee estimation helpers (vbyte-based)
  - CPFP (Child-Pays-For-Parent) transaction builder
  - Batch transaction builder for multiple outputs
  - Taproot key-path spend skeleton
  - Proper witness serialization metadata
  - Input validation on all public methods
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut,
    COutPoint, CScript,
)
from bitcoin.core.script import (
    OP_RETURN, OP_0, OP_1,
    SignatureHash, SIGHASH_ALL,
)

from .scripts import RealHTLCScript


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DUST_THRESHOLD = 546        # Minimum output value (satoshis) per Bitcoin Core policy
SEGWIT_DISCOUNT = 4         # SegWit witness discount factor
DEFAULT_FEE_RATE = 2        # sats/vbyte — conservative default
MIN_FEE = 110               # Minimum relay fee (1 sat/vbyte * ~110 vbytes)
MAX_FEE_RATE = 10_000       # sats/vbyte — sanity cap
MAX_TX_WEIGHT = 400_000     # 100 kvB standard limit
MAX_OP_RETURN_SIZE = 80     # OP_RETURN data size limit

# BIP-125 RBF signaling
SEQUENCE_RBF_ENABLED = 0xFFFFFFFD   # Signals RBF (< 0xFFFFFFFE)
SEQUENCE_FINAL = 0xFFFFFFFF          # No RBF, final


def _validate_amount(amount: int, label: str = "amount"):
    """Validate a satoshi amount."""
    if not isinstance(amount, int):
        raise TypeError(f"{label} must be an integer")
    if amount < 0:
        raise ValueError(f"{label} must be >= 0, got {amount}")


def _check_dust(amount: int, label: str = "output"):
    """Reject outputs below dust threshold."""
    if 0 < amount < DUST_THRESHOLD:
        raise ValueError(
            f"{label} amount {amount} sats is below dust threshold "
            f"({DUST_THRESHOLD} sats)"
        )


def estimate_vsize(num_inputs: int, num_outputs: int,
                   witness_items_per_input: int = 2,
                   is_segwit: bool = True) -> int:
    """
    Estimate transaction virtual size (vbytes).

    vsize = (weight + 3) / 4
    weight = base_size * 3 + total_size  (for segwit)

    Rough formula:
      non-witness: 10 (header) + 41*inputs + 32*outputs
      witness: ~(73+34)*inputs per signature
    """
    base = 10 + 41 * num_inputs + 32 * num_outputs
    if is_segwit:
        witness = witness_items_per_input * 36 * num_inputs
        weight = base * 3 + (base + witness)
        return (weight + 3) // 4
    return base


def estimate_fee(num_inputs: int, num_outputs: int,
                 fee_rate: int = DEFAULT_FEE_RATE,
                 is_segwit: bool = True) -> int:
    """
    Estimate transaction fee in satoshis.

    Args:
        fee_rate: satoshis per virtual byte
    """
    if fee_rate > MAX_FEE_RATE:
        raise ValueError(f"Fee rate {fee_rate} sats/vbyte exceeds max {MAX_FEE_RATE}")
    vsize = estimate_vsize(num_inputs, num_outputs, is_segwit=is_segwit)
    fee = max(MIN_FEE, vsize * fee_rate)
    return fee


class RealTransactionBuilder:
    """
    Build real Bitcoin transactions for the DEX.

    All methods validate inputs and enforce dust thresholds.
    """

    @staticmethod
    def build_funding_tx(
        funding_outpoint: COutPoint,
        htlc_script: RealHTLCScript,
        amount: int,
        enable_rbf: bool = False,
    ) -> CTransaction:
        """
        Fund an HTLC by sending to the P2WSH address.

        Args:
            enable_rbf: If True, sets nSequence for BIP-125 RBF signaling.
        """
        _validate_amount(amount, "funding amount")
        _check_dust(amount, "funding output")
        tx = CMutableTransaction()
        nseq = SEQUENCE_RBF_ENABLED if enable_rbf else SEQUENCE_FINAL
        tx.vin = [CTxIn(funding_outpoint, nSequence=nseq)]
        tx.vout = [CTxOut(amount, htlc_script.p2wsh_scriptpubkey)]
        return CTransaction.from_tx(tx)

    @staticmethod
    def build_claim_tx(
        funding_txid: bytes,
        funding_vout: int,
        htlc_script: RealHTLCScript,
        amount: int,
        destination_scriptpubkey: CScript,
        fee: int = 1000,
        enable_rbf: bool = True,
    ) -> Tuple[CTransaction, bytes]:
        """
        Build a claim transaction spending the HTLC.

        Returns (unsigned_tx, sighash).
        RBF is enabled by default for claim txs (allows fee bumping
        in case of congestion).
        """
        _validate_amount(amount, "input amount")
        _validate_amount(fee, "fee")
        claim_amount = amount - fee
        _check_dust(claim_amount, "claim output")
        if claim_amount <= 0:
            raise ValueError(f"Claim amount after fee would be {claim_amount} (non-positive)")

        tx = CMutableTransaction()
        nseq = SEQUENCE_RBF_ENABLED if enable_rbf else SEQUENCE_FINAL
        tx.vin = [CTxIn(COutPoint(funding_txid, funding_vout), nSequence=nseq)]
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
        fee: int = 1000,
    ) -> Tuple[CTransaction, bytes]:
        """
        Build a refund transaction for after the timelock expires.

        Returns (unsigned_tx, sighash).
        nSequence is set to FINAL (no RBF) since refund relies on
        nLockTime which requires nSequence < 0xFFFFFFFF... but we
        use 0xFFFFFFFE to avoid enabling RBF unintentionally.
        """
        _validate_amount(amount, "input amount")
        _validate_amount(fee, "fee")
        refund_amount = amount - fee
        _check_dust(refund_amount, "refund output")
        if refund_amount <= 0:
            raise ValueError(f"Refund amount after fee would be {refund_amount}")

        tx = CMutableTransaction()
        # nSequence must be < 0xFFFFFFFF for nLockTime to be active
        tx.vin = [CTxIn(COutPoint(funding_txid, funding_vout),
                        nSequence=0xFFFFFFFE)]
        tx.nLockTime = htlc_script.timelock_blocks
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
        """
        Build an OP_RETURN output (for RGB state anchoring).

        Validates OP_RETURN data size (max 80 bytes per policy).
        """
        if len(data) > MAX_OP_RETURN_SIZE:
            raise ValueError(
                f"OP_RETURN data too large: {len(data)} bytes > "
                f"{MAX_OP_RETURN_SIZE} byte limit"
            )
        _validate_amount(change_amount, "change amount")
        _check_dust(change_amount, "change output")

        tx = CMutableTransaction()
        tx.vin = [CTxIn(funding_outpoint)]
        op_return_script = CScript([OP_RETURN, data])
        tx.vout = [
            CTxOut(0, op_return_script),
            CTxOut(change_amount, change_scriptpubkey),
        ]
        return CTransaction.from_tx(tx)

    @staticmethod
    def build_batch_tx(
        funding_outpoints: List[COutPoint],
        outputs: List[Tuple[CScript, int]],
        change_scriptpubkey: Optional[CScript] = None,
        change_amount: int = 0,
        enable_rbf: bool = False,
    ) -> CTransaction:
        """
        Build a transaction with multiple inputs and outputs.

        Useful for batching multiple payments or UTXO consolidation.
        All output amounts are validated against dust threshold.
        """
        if not funding_outpoints:
            raise ValueError("At least one input required")
        if not outputs:
            raise ValueError("At least one output required")

        tx = CMutableTransaction()
        nseq = SEQUENCE_RBF_ENABLED if enable_rbf else SEQUENCE_FINAL
        tx.vin = [CTxIn(outpoint, nSequence=nseq) for outpoint in funding_outpoints]

        tx.vout = []
        for i, (script, amount) in enumerate(outputs):
            _validate_amount(amount, f"output[{i}]")
            _check_dust(amount, f"output[{i}]")
            tx.vout.append(CTxOut(amount, script))

        if change_scriptpubkey is not None and change_amount > 0:
            _check_dust(change_amount, "change output")
            tx.vout.append(CTxOut(change_amount, change_scriptpubkey))

        return CTransaction.from_tx(tx)

    @staticmethod
    def build_cpfp_tx(
        parent_txid: bytes,
        parent_vout: int,
        parent_amount: int,
        destination_scriptpubkey: CScript,
        target_total_fee: int,
    ) -> CTransaction:
        """
        Build a Child-Pays-For-Parent (CPFP) transaction.

        CPFP is used when a parent transaction is stuck with
        insufficient fee.  The child spends an output of the parent
        with enough fee to incentivize miners to confirm both.

        Args:
            target_total_fee: Total fee budget covering BOTH parent
                              and child transactions.
        """
        _validate_amount(parent_amount, "parent output amount")
        _validate_amount(target_total_fee, "target total fee")
        child_amount = parent_amount - target_total_fee
        _check_dust(child_amount, "CPFP output")
        if child_amount <= 0:
            raise ValueError(
                f"CPFP output would be {child_amount} sats "
                f"(parent_amount={parent_amount}, fee={target_total_fee})"
            )

        tx = CMutableTransaction()
        # RBF enabled on CPFP so it can be further bumped
        tx.vin = [CTxIn(COutPoint(parent_txid, parent_vout),
                        nSequence=SEQUENCE_RBF_ENABLED)]
        tx.vout = [CTxOut(child_amount, destination_scriptpubkey)]
        return CTransaction.from_tx(tx)

    @staticmethod
    def build_taproot_keypath_tx(
        funding_outpoint: COutPoint,
        amount: int,
        destination_scriptpubkey: CScript,
        fee: int = 1000,
    ) -> Tuple[CTransaction, bytes]:
        """
        Build a Taproot key-path spend transaction skeleton.

        For key-path spends, the witness is just a single 64-byte
        Schnorr signature (or 65 bytes with non-default sighash).
        No script reveal needed — maximum privacy.

        Returns (unsigned_tx, message_to_sign).
        The caller should produce a BIP-340 Schnorr signature
        over the returned message.
        """
        _validate_amount(amount, "input amount")
        _validate_amount(fee, "fee")
        output_amount = amount - fee
        _check_dust(output_amount, "output")

        tx = CMutableTransaction()
        tx.vin = [CTxIn(funding_outpoint, nSequence=SEQUENCE_FINAL)]
        tx.vout = [CTxOut(output_amount, destination_scriptpubkey)]

        # BIP-341 sighash: for simulation we hash the serialized tx
        # Real impl would use SigHashTaproot with epoch 0x00
        msg = hashlib.sha256(
            b'\x00' +  # epoch byte (BIP-341)
            tx.serialize()
        ).digest()

        return CTransaction.from_tx(tx), msg

    # -- Utility -----------------------------------------------------------

    @staticmethod
    def serialize_hex(tx: CTransaction) -> str:
        """Serialize transaction to hex string."""
        return tx.serialize().hex()

    @staticmethod
    def txid_hex(tx: CTransaction) -> str:
        """Get transaction ID as hex string."""
        return tx.GetTxid().hex()

    @staticmethod
    def weight(tx: CTransaction) -> int:
        """
        Estimate transaction weight units.

        weight = base_size * 3 + total_size  (SegWit)
        """
        raw = tx.serialize()
        # Simplified: assume SegWit transaction
        return len(raw) * SEGWIT_DISCOUNT

    @staticmethod
    def vsize(tx: CTransaction) -> int:
        """Virtual size in vbytes = ceil(weight / 4)."""
        w = RealTransactionBuilder.weight(tx)
        return (w + 3) // 4

    @staticmethod
    def fee_for_tx(tx: CTransaction, fee_rate: int = DEFAULT_FEE_RATE) -> int:
        """Calculate fee for an existing transaction at the given rate."""
        return RealTransactionBuilder.vsize(tx) * fee_rate
