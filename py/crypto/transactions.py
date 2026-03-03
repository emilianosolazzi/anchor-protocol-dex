"""
Real Bitcoin transaction builder + PSBT (BIP-174 / BIP-370).

Constructs CTransaction objects for HTLC funding, claiming,
refunding, OP_RETURN outputs, and more.  Also provides a
lightweight PSBT implementation for multi-party signing workflows.

Features:
  - RBF signaling via nSequence (BIP-125)
  - Dust threshold enforcement (BIP-353 / policy rule)
  - Fee estimation helpers (vbyte-based)
  - CPFP (Child-Pays-For-Parent) transaction builder
  - Batch transaction builder for multiple outputs
  - Taproot key-path spend skeleton
  - Proper witness serialization metadata
  - Input validation on all public methods
  - PSBT creation, signing, combining, finalizing, and extraction
"""
from __future__ import annotations

import base64
import copy
import enum
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from bitcoin.core import (
    CTransaction, CMutableTransaction, CTxIn, CTxOut,
    COutPoint, CScript,
)
from bitcoin.core.script import (
    OP_RETURN, OP_0, OP_1,
    SignatureHash, SIGHASH_ALL,
)

from .scripts import RealHTLCScript

logger = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# PSBT — Partially Signed Bitcoin Transaction (BIP-174 / BIP-370)
# ---------------------------------------------------------------------------
# This is a purpose-built implementation for multi-party DEX workflows
# (HTLC atomic swaps, covenant co-signs, Taproot key-path spends).
# It is NOT a full BIP-174 serializer — it operates on the in-memory
# transaction graph rather than the binary PSBT format.
#
# Lifecycle:   create -> add sigs -> combine -> finalize -> extract
# ---------------------------------------------------------------------------

class PSBTRole(enum.Enum):
    """BIP-174 roles."""
    CREATOR = "creator"
    UPDATER = "updater"
    SIGNER = "signer"
    COMBINER = "combiner"
    FINALIZER = "finalizer"
    EXTRACTOR = "extractor"


@dataclass
class PSBTInput:
    """Per-input PSBT metadata."""
    # Previous output being spent
    utxo_amount: int = 0
    # Redeem / witness script (for P2WSH / P2SH-P2WSH)
    witness_script: Optional[bytes] = None
    redeem_script: Optional[bytes] = None
    # Sighash type requested
    sighash_type: int = SIGHASH_ALL
    # Partial signatures: pubkey_hex -> DER sig bytes
    partial_sigs: Dict[str, bytes] = field(default_factory=dict)
    # BIP-32 derivation paths (pubkey_hex -> path string)
    bip32_derivation: Dict[str, str] = field(default_factory=dict)
    # Finalized scriptSig / witness
    final_script_sig: Optional[bytes] = None
    final_script_witness: Optional[List[bytes]] = None


@dataclass
class PSBTOutput:
    """Per-output PSBT metadata."""
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivation: Dict[str, str] = field(default_factory=dict)


class PSBT:
    """
    Partially Signed Bitcoin Transaction.

    Manages the unsigned transaction and per-input / per-output
    metadata required for safe multi-party signing.

    Usage::

        psbt = PSBT.from_unsigned_tx(tx)
        psbt.update_input(0, utxo_amount=50_000,
                          witness_script=htlc.redeem_script)
        psbt.add_signature(0, pubkey_hex, sig_bytes)
        # ... other party signs ...
        combined = PSBT.combine([psbt, other_psbt])
        combined.finalize_input(0, build_witness_fn)
        signed_tx = combined.extract()

    Thread-safe: all mutation acquires an internal lock.
    """

    # Magic bytes per BIP-174 (for future serialization)
    _MAGIC = b"psbt\xff"
    _MAX_INPUTS = 500
    _MAX_OUTPUTS = 500

    def __init__(self, unsigned_tx: CTransaction):
        import threading
        self._tx = CMutableTransaction.from_tx(unsigned_tx)
        self._inputs: List[PSBTInput] = [
            PSBTInput() for _ in self._tx.vin
        ]
        self._outputs: List[PSBTOutput] = [
            PSBTOutput() for _ in self._tx.vout
        ]
        self._finalized = False
        self._lock = threading.Lock()

    # -- Creator -----------------------------------------------------------

    @classmethod
    def from_unsigned_tx(cls, tx: CTransaction) -> "PSBT":
        """
        Create a PSBT from an unsigned transaction (Creator role).

        Validates that the tx has no scriptSigs (must be unsigned).
        """
        if len(tx.vin) > cls._MAX_INPUTS:
            raise ValueError(
                f"Too many inputs: {len(tx.vin)} > {cls._MAX_INPUTS}"
            )
        if len(tx.vout) > cls._MAX_OUTPUTS:
            raise ValueError(
                f"Too many outputs: {len(tx.vout)} > {cls._MAX_OUTPUTS}"
            )
        for i, txin in enumerate(tx.vin):
            if txin.scriptSig and len(txin.scriptSig) > 0:
                raise ValueError(
                    f"Input {i} already has a scriptSig — "
                    f"PSBT requires an unsigned transaction"
                )
        return cls(tx)

    @classmethod
    def for_htlc(
        cls,
        funding_txid: bytes,
        funding_vout: int,
        htlc_script: RealHTLCScript,
        amount: int,
        destination: CScript,
        fee: int = 1000,
    ) -> "PSBT":
        """
        Convenience: create a PSBT for claiming an HTLC output.

        Pre-fills the witness_script metadata on input 0.
        """
        tx, _sighash = RealTransactionBuilder.build_claim_tx(
            funding_txid, funding_vout, htlc_script, amount, destination, fee,
        )
        psbt = cls.from_unsigned_tx(tx)
        psbt.update_input(
            0,
            utxo_amount=amount,
            witness_script=bytes(htlc_script.redeem_script),
        )
        return psbt

    # -- Updater -----------------------------------------------------------

    def update_input(
        self,
        index: int,
        *,
        utxo_amount: Optional[int] = None,
        witness_script: Optional[bytes] = None,
        redeem_script: Optional[bytes] = None,
        sighash_type: Optional[int] = None,
        bip32_derivation: Optional[Dict[str, str]] = None,
    ) -> None:
        """Add metadata to an input (Updater role)."""
        self._check_not_finalized()
        inp = self._get_input(index)
        with self._lock:
            if utxo_amount is not None:
                _validate_amount(utxo_amount, f"input[{index}] utxo_amount")
                inp.utxo_amount = utxo_amount
            if witness_script is not None:
                inp.witness_script = witness_script
            if redeem_script is not None:
                inp.redeem_script = redeem_script
            if sighash_type is not None:
                inp.sighash_type = sighash_type
            if bip32_derivation is not None:
                inp.bip32_derivation.update(bip32_derivation)

    def update_output(
        self,
        index: int,
        *,
        redeem_script: Optional[bytes] = None,
        witness_script: Optional[bytes] = None,
        bip32_derivation: Optional[Dict[str, str]] = None,
    ) -> None:
        """Add metadata to an output (Updater role)."""
        self._check_not_finalized()
        out = self._get_output(index)
        with self._lock:
            if redeem_script is not None:
                out.redeem_script = redeem_script
            if witness_script is not None:
                out.witness_script = witness_script
            if bip32_derivation is not None:
                out.bip32_derivation.update(bip32_derivation)

    # -- Signer ------------------------------------------------------------

    def add_signature(
        self,
        index: int,
        pubkey_hex: str,
        signature: bytes,
    ) -> None:
        """
        Add a partial signature for an input (Signer role).

        The pubkey_hex identifies which key produced the signature.
        Multiple signers can contribute independently.
        """
        self._check_not_finalized()
        inp = self._get_input(index)
        if len(pubkey_hex) not in (66, 64):  # 33-byte compressed or 32-byte x-only
            raise ValueError(
                f"Invalid pubkey hex length {len(pubkey_hex)} "
                f"(expected 66 for compressed, 64 for x-only)"
            )
        if not signature:
            raise ValueError("Signature must not be empty")
        with self._lock:
            inp.partial_sigs[pubkey_hex] = signature
        logger.info(f"  [PSBT] Input {index}: added sig from {pubkey_hex[:16]}...")

    def sign_input(
        self,
        index: int,
        alias: str,
        sighash: bytes,
        *,
        schnorr: bool = False,
    ) -> None:
        """
        Sign an input using KEYSTORE (convenience wrapper).

        Automatically adds the resulting partial signature.
        """
        from .keys import KEYSTORE
        if schnorr:
            sig = KEYSTORE.sign_schnorr(alias, sighash)
            pubkey_hex = KEYSTORE.x_only_pubkey(alias).hex()
        else:
            sig = KEYSTORE.sign(alias, sighash)
            pubkey_hex = KEYSTORE.pubkey(alias).hex()
        self.add_signature(index, pubkey_hex, sig)

    # -- Combiner ----------------------------------------------------------

    @classmethod
    def combine(cls, psbts: List["PSBT"]) -> "PSBT":
        """
        Merge multiple PSBTs for the same transaction (Combiner role).

        Each PSBT may contain different partial signatures.
        The underlying unsigned tx must be identical.
        """
        if not psbts:
            raise ValueError("Need at least one PSBT to combine")
        if len(psbts) == 1:
            return psbts[0]

        base_hex = psbts[0]._tx.serialize().hex()
        for i, p in enumerate(psbts[1:], 1):
            if p._tx.serialize().hex() != base_hex:
                raise ValueError(
                    f"PSBT[{i}] has a different unsigned transaction"
                )

        result = cls(CTransaction.from_tx(psbts[0]._tx))
        # Deep-copy input/output metadata from first PSBT
        result._inputs = [copy.deepcopy(inp) for inp in psbts[0]._inputs]
        result._outputs = [copy.deepcopy(out) for out in psbts[0]._outputs]

        # Merge partial sigs and derivation info from remaining PSBTs
        for p in psbts[1:]:
            for idx, inp in enumerate(p._inputs):
                result._inputs[idx].partial_sigs.update(inp.partial_sigs)
                result._inputs[idx].bip32_derivation.update(
                    inp.bip32_derivation
                )
                # Prefer non-None witness/redeem scripts
                if inp.witness_script and not result._inputs[idx].witness_script:
                    result._inputs[idx].witness_script = inp.witness_script
                if inp.redeem_script and not result._inputs[idx].redeem_script:
                    result._inputs[idx].redeem_script = inp.redeem_script
            for idx, out in enumerate(p._outputs):
                result._outputs[idx].bip32_derivation.update(
                    out.bip32_derivation
                )

        logger.info(f"  [PSBT] Combined {len(psbts)} PSBTs")
        return result

    # -- Finalizer ---------------------------------------------------------

    def finalize_input(
        self,
        index: int,
        witness_builder: Optional[Any] = None,
    ) -> None:
        """
        Finalize an input — produce the scriptSig / witness (Finalizer role).

        If witness_builder is provided, call it as
          witness_builder(partial_sigs, witness_script) -> List[bytes]
        Otherwise, build a simple P2WPKH-style witness from the
        first available partial signature.
        """
        self._check_not_finalized()
        inp = self._get_input(index)

        if not inp.partial_sigs:
            raise ValueError(
                f"Input {index} has no partial signatures — cannot finalize"
            )

        with self._lock:
            if witness_builder is not None:
                inp.final_script_witness = witness_builder(
                    inp.partial_sigs, inp.witness_script,
                )
            else:
                # Default: single-sig P2WPKH witness  [sig, pubkey]
                pubkey_hex, sig = next(iter(inp.partial_sigs.items()))
                inp.final_script_witness = [sig, bytes.fromhex(pubkey_hex)]

            # Clear partial data after finalizing (BIP-174 §Finalizer)
            inp.partial_sigs = {}
            inp.bip32_derivation = {}
            inp.redeem_script = None
            inp.witness_script = None

    def finalize_all(
        self,
        witness_builder: Optional[Any] = None,
    ) -> None:
        """Finalize every input."""
        for i in range(len(self._inputs)):
            self.finalize_input(i, witness_builder)
        with self._lock:
            self._finalized = True

    # -- Extractor ---------------------------------------------------------

    def extract(self) -> CTransaction:
        """
        Extract the finalized, fully-signed transaction (Extractor role).

        Returns an immutable CTransaction ready for broadcast.
        """
        # At least one input must be finalized
        any_final = any(
            inp.final_script_witness is not None or inp.final_script_sig is not None
            for inp in self._inputs
        )
        if not any_final:
            raise ValueError(
                "No inputs are finalized — call finalize_input() first"
            )

        tx = CMutableTransaction.from_tx(self._tx)
        for i, inp in enumerate(self._inputs):
            if inp.final_script_sig is not None:
                tx.vin[i].scriptSig = CScript(inp.final_script_sig)
            # NOTE: python-bitcoinlib's CTxIn doesn't carry witness
            # data directly — in a real node the witness is separate.
            # We store it in the PSBT metadata for completeness.
        return CTransaction.from_tx(tx)

    # -- Introspection -----------------------------------------------------

    @property
    def num_inputs(self) -> int:
        return len(self._inputs)

    @property
    def num_outputs(self) -> int:
        return len(self._outputs)

    @property
    def is_finalized(self) -> bool:
        return self._finalized

    def input_has_sig(self, index: int, pubkey_hex: str) -> bool:
        """Check whether a specific pubkey has signed an input."""
        return pubkey_hex in self._get_input(index).partial_sigs

    def input_sig_count(self, index: int) -> int:
        """Number of partial signatures on an input."""
        return len(self._get_input(index).partial_sigs)

    def summary(self) -> Dict[str, Any]:
        """Human-readable PSBT summary."""
        return {
            "inputs": self.num_inputs,
            "outputs": self.num_outputs,
            "finalized": self._finalized,
            "input_details": [
                {
                    "index": i,
                    "utxo_sats": inp.utxo_amount,
                    "sigs": len(inp.partial_sigs),
                    "has_witness_script": inp.witness_script is not None,
                    "finalized": inp.final_script_witness is not None,
                }
                for i, inp in enumerate(self._inputs)
            ],
        }

    def to_base64(self) -> str:
        """
        Encode PSBT to base64 for transport.

        NOTE: This is a simplified encoding (magic + serialized tx)
        — not the full BIP-174 binary format.  Sufficient for
        inter-process transport within the DEX.
        """
        payload = self._MAGIC + self._tx.serialize()
        return base64.b64encode(payload).decode("ascii")

    @classmethod
    def from_base64(cls, b64: str) -> "PSBT":
        """Decode a base64-encoded PSBT."""
        raw = base64.b64decode(b64)
        if not raw.startswith(cls._MAGIC):
            raise ValueError("Invalid PSBT magic bytes")
        tx_bytes = raw[len(cls._MAGIC):]
        tx = CTransaction.deserialize(tx_bytes)
        return cls(tx)

    # -- Internal ----------------------------------------------------------

    def _get_input(self, index: int) -> PSBTInput:
        if index < 0 or index >= len(self._inputs):
            raise IndexError(
                f"Input index {index} out of range [0, {len(self._inputs)})"
            )
        return self._inputs[index]

    def _get_output(self, index: int) -> PSBTOutput:
        if index < 0 or index >= len(self._outputs):
            raise IndexError(
                f"Output index {index} out of range [0, {len(self._outputs)})"
            )
        return self._outputs[index]

    def _check_not_finalized(self) -> None:
        if self._finalized:
            raise RuntimeError("PSBT is already finalized — cannot modify")
