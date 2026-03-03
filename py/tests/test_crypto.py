"""
Tests for the crypto layer: keys, scripts, transactions, PSBT.
"""
import hashlib
import os
import pytest

from bitcoin.core import COutPoint, CTransaction, CTxIn, CTxOut, CScript, lx

from py.crypto.keys import (
    BitcoinKeyStore, KEYSTORE, SECP256K1_ORDER,
    tagged_hash, hash160,
)
from py.crypto.scripts import (
    RealHTLCScript, CSVHTLCScript, TapscriptHTLC,
    RealMultiSigScript, TapscriptMultiSig, TimeLockVault,
)
from py.crypto.transactions import (
    RealTransactionBuilder, estimate_vsize, estimate_fee,
    DUST_THRESHOLD, PSBT, PSBTInput, PSBTOutput, PSBTRole,
)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

class TestTaggedHash:
    def test_deterministic(self):
        h1 = tagged_hash("test", b"data")
        h2 = tagged_hash("test", b"data")
        assert h1 == h2

    def test_32_bytes(self):
        h = tagged_hash("BIP0340/challenge", b"msg")
        assert len(h) == 32

    def test_different_tags_differ(self):
        h1 = tagged_hash("tag_a", b"same")
        h2 = tagged_hash("tag_b", b"same")
        assert h1 != h2

    def test_different_msgs_differ(self):
        h1 = tagged_hash("tag", b"msg1")
        h2 = tagged_hash("tag", b"msg2")
        assert h1 != h2


class TestHash160:
    def test_20_bytes(self):
        result = hash160(b"hello")
        assert len(result) == 20

    def test_deterministic(self):
        assert hash160(b"x") == hash160(b"x")


class TestBitcoinKeyStore:
    def test_mainnet_guard(self):
        ks = BitcoinKeyStore(network="mainnet")
        with pytest.raises(RuntimeError, match="Deterministic.*disabled"):
            ks.get_or_create("should_fail")

    def test_liquid_guard(self):
        ks = BitcoinKeyStore(network="liquid")
        with pytest.raises(RuntimeError, match="Deterministic.*disabled"):
            ks.get_or_create("should_fail_liquid")

    def test_regtest_allowed(self):
        ks = BitcoinKeyStore(network="regtest")
        pk = ks.get_or_create("regtest_ok")
        assert pk is not None

    def test_import_key_bypasses_guard(self):
        ks = BitcoinKeyStore(network="mainnet")
        secret = hashlib.sha256(b"external_entropy_12345").digest()
        pk = ks.import_key("imported", secret)
        assert pk is not None

    def test_set_network(self):
        ks = BitcoinKeyStore(network="regtest")
        ks.get_or_create("before_switch")
        ks.set_network("mainnet")
        with pytest.raises(RuntimeError):
            ks.get_or_create("after_switch")

    def test_pubkey_33_bytes(self):
        pub = KEYSTORE.pubkey("test_pub33")
        assert len(pub) == 33

    def test_pubkey_uncompressed_65_bytes(self):
        pub = KEYSTORE.pubkey_uncompressed("test_pub65")
        assert len(pub) == 65

    def test_x_only_pubkey_32_bytes(self):
        xpub = KEYSTORE.x_only_pubkey("test_xonly")
        assert len(xpub) == 32

    def test_pubkey_hash_20_bytes(self):
        pkh = KEYSTORE.pubkey_hash("test_pkh")
        assert len(pkh) == 20

    def test_deterministic_same_alias(self):
        ks = BitcoinKeyStore()
        p1 = ks.pubkey("det_test")
        p2 = ks.pubkey("det_test")
        assert p1 == p2

    def test_different_aliases_different_keys(self):
        ks = BitcoinKeyStore()
        p1 = ks.pubkey("alias_a")
        p2 = ks.pubkey("alias_b")
        assert p1 != p2

    def test_has_key(self):
        ks = BitcoinKeyStore()
        assert ks.has_key("nonexistent") is False
        ks.get_or_create("exists_now")
        assert ks.has_key("exists_now") is True

    def test_import_key_validates(self):
        ks = BitcoinKeyStore()
        with pytest.raises(ValueError):
            ks.import_key("bad", b"short")
        with pytest.raises(ValueError):
            ks.import_key("zero", b"\x00" * 32)

    def test_p2pkh_script(self):
        script = KEYSTORE.p2pkh_scriptpubkey("p2pkh_test")
        assert isinstance(script, CScript)

    def test_p2wpkh_script(self):
        script = KEYSTORE.p2wpkh_scriptpubkey("p2wpkh_test")
        assert isinstance(script, CScript)

    def test_p2tr_script(self):
        script = KEYSTORE.p2tr_scriptpubkey("p2tr_test")
        assert isinstance(script, CScript)

    def test_sign_and_verify_ecdsa(self):
        msg = hashlib.sha256(b"test_message").digest()
        sig = KEYSTORE.sign("ecdsa_test", msg)
        assert isinstance(sig, bytes)
        assert KEYSTORE.verify("ecdsa_test", sig, msg) is True

    def test_sign_and_verify_schnorr(self):
        msg = hashlib.sha256(b"schnorr_message").digest()
        sig = KEYSTORE.sign_schnorr("schnorr_test", msg)
        assert len(sig) == 64
        assert KEYSTORE.verify_schnorr("schnorr_test", sig, msg) is True

    def test_verify_schnorr_wrong_msg(self):
        msg = hashlib.sha256(b"right_msg").digest()
        wrong = hashlib.sha256(b"wrong_msg").digest()
        sig = KEYSTORE.sign_schnorr("schnorr_wrong", msg)
        assert KEYSTORE.verify_schnorr("schnorr_wrong", sig, wrong) is False

    def test_address_hex(self):
        addr = KEYSTORE.address_hex("addr_test")
        assert addr.startswith("bcrt1q")

    def test_address_p2tr(self):
        addr = KEYSTORE.address_p2tr("addr_p2tr")
        assert addr.startswith("bcrt1p")

    def test_info(self):
        info = KEYSTORE.info("info_test")
        assert "alias" in info
        assert "pubkey_hex" in info

    def test_aliases_property(self):
        ks = BitcoinKeyStore()
        ks.get_or_create("ap1")
        ks.get_or_create("ap2")
        assert "ap1" in ks.aliases
        assert "ap2" in ks.aliases


# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------

class TestRealHTLCScript:
    def test_construction(self):
        sender = KEYSTORE.pubkey("htlc_sender")
        recipient = KEYSTORE.pubkey("htlc_recipient")
        secret_hash = hashlib.sha256(b"secret").digest()
        htlc = RealHTLCScript(sender, recipient, secret_hash)
        assert htlc.redeem_script is not None
        assert htlc.p2wsh_scriptpubkey is not None

    def test_hex_output(self):
        sender = KEYSTORE.pubkey("htlc_hex_s")
        recipient = KEYSTORE.pubkey("htlc_hex_r")
        h = hashlib.sha256(b"s").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        assert isinstance(htlc.hex(), str)

    def test_claim_witness(self):
        sender = KEYSTORE.pubkey("cw_s")
        recipient = KEYSTORE.pubkey("cw_r")
        h = hashlib.sha256(b"claim").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        witness = htlc.claim_witness(b"sig123", b"claim")
        assert isinstance(witness, list)

    def test_info(self):
        sender = KEYSTORE.pubkey("inf_s")
        recipient = KEYSTORE.pubkey("inf_r")
        h = hashlib.sha256(b"info").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        info = htlc.info()
        assert isinstance(info, dict)


class TestCSVHTLCScript:
    def test_construction(self):
        sender = KEYSTORE.pubkey("csv_s")
        recipient = KEYSTORE.pubkey("csv_r")
        h = hashlib.sha256(b"csv").digest()
        csv = CSVHTLCScript(sender, recipient, h, relative_blocks=72)
        assert csv.nsequence > 0

    def test_info(self):
        sender = KEYSTORE.pubkey("csvi_s")
        recipient = KEYSTORE.pubkey("csvi_r")
        h = hashlib.sha256(b"csvi").digest()
        csv = CSVHTLCScript(sender, recipient, h)
        assert isinstance(csv.info(), dict)


class TestTapscriptHTLC:
    def test_construction(self):
        sender = KEYSTORE.x_only_pubkey("tap_s")
        recipient = KEYSTORE.x_only_pubkey("tap_r")
        h = hashlib.sha256(b"tap").digest()
        tap = TapscriptHTLC(sender, recipient, h)
        assert tap.claim_script is not None
        assert tap.refund_script is not None
        assert len(tap.merkle_root) == 32

    def test_info(self):
        sender = KEYSTORE.x_only_pubkey("tapi_s")
        recipient = KEYSTORE.x_only_pubkey("tapi_r")
        h = hashlib.sha256(b"tapi").digest()
        tap = TapscriptHTLC(sender, recipient, h)
        assert isinstance(tap.info(), dict)


class TestMultiSig:
    def test_real_multisig(self):
        pubs = [KEYSTORE.pubkey(f"ms_{i}") for i in range(3)]
        ms = RealMultiSigScript(2, pubs)
        assert isinstance(ms.hex(), str)
        assert isinstance(ms.info(), dict)

    def test_tapscript_multisig(self):
        xpubs = [KEYSTORE.x_only_pubkey(f"tms_{i}") for i in range(3)]
        tms = TapscriptMultiSig(2, xpubs)
        assert tms.script is not None
        assert len(tms.leaf_hash) == 32
        assert isinstance(tms.info(), dict)


class TestTimeLockVault:
    def test_construction(self):
        hot = KEYSTORE.pubkey("vault_hot")
        cold = KEYSTORE.pubkey("vault_cold")
        recovery = KEYSTORE.pubkey("vault_recovery")
        vault = TimeLockVault(hot, cold, recovery, delay_blocks=100)
        assert vault.nsequence_recovery > 0
        assert isinstance(vault.info(), dict)

    def test_witnesses(self):
        hot = KEYSTORE.pubkey("vw_hot")
        cold = KEYSTORE.pubkey("vw_cold")
        recovery = KEYSTORE.pubkey("vw_recovery")
        vault = TimeLockVault(hot, cold, recovery)
        imm = vault.immediate_witness(b"hot_sig", b"cold_sig")
        assert isinstance(imm, list)
        rec = vault.recovery_witness(b"rec_sig")
        assert isinstance(rec, list)


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

class TestEstimates:
    def test_vsize_positive(self):
        vs = estimate_vsize(1, 2)
        assert vs > 0

    def test_fee_positive(self):
        fee = estimate_fee(1, 2, fee_rate=5)
        assert fee > 0

    def test_fee_increases_with_rate(self):
        f1 = estimate_fee(1, 1, fee_rate=1)
        f2 = estimate_fee(1, 1, fee_rate=10)
        assert f2 > f1


class TestRealTransactionBuilder:
    def test_build_funding_tx(self):
        outpoint = COutPoint(lx("11" * 32), 0)
        sender = KEYSTORE.pubkey("fund_s")
        recipient = KEYSTORE.pubkey("fund_r")
        h = hashlib.sha256(b"fund").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        tx = RealTransactionBuilder.build_funding_tx(outpoint, htlc, 50_000)
        assert isinstance(tx, CTransaction)

    def test_build_claim_tx(self):
        outpoint = COutPoint(lx("22" * 32), 0)
        sender = KEYSTORE.pubkey("claim_s")
        recipient = KEYSTORE.pubkey("claim_r")
        h = hashlib.sha256(b"claim_tx").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        fund_tx = RealTransactionBuilder.build_funding_tx(outpoint, htlc, 50_000)
        dest = KEYSTORE.p2wpkh_scriptpubkey("claim_dest")
        tx, sighash = RealTransactionBuilder.build_claim_tx(
            fund_tx.GetTxid(), 0, htlc, 50_000, dest,
        )
        assert isinstance(tx, CTransaction)
        assert len(sighash) == 32

    def test_build_op_return_tx(self):
        outpoint = COutPoint(lx("33" * 32), 0)
        change = KEYSTORE.p2wpkh_scriptpubkey("opret_change")
        tx = RealTransactionBuilder.build_op_return_tx(
            outpoint, b"hello anchor", change, 49_000,
        )
        assert isinstance(tx, CTransaction)

    def test_build_batch_tx(self):
        outpoints = [COutPoint(lx(f"{i:02x}" * 32), 0) for i in range(3)]
        dest = KEYSTORE.p2wpkh_scriptpubkey("batch_dest")
        outputs = [(dest, 10_000), (dest, 20_000)]
        tx = RealTransactionBuilder.build_batch_tx(outpoints, outputs)
        assert len(tx.vin) == 3
        assert len(tx.vout) >= 2

    def test_serialize_and_txid(self):
        outpoint = COutPoint(lx("44" * 32), 0)
        change = KEYSTORE.p2wpkh_scriptpubkey("ser_change")
        tx = RealTransactionBuilder.build_op_return_tx(
            outpoint, b"test", change, 49_000,
        )
        hex_str = RealTransactionBuilder.serialize_hex(tx)
        assert isinstance(hex_str, str)
        txid = RealTransactionBuilder.txid_hex(tx)
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_weight_and_vsize(self):
        outpoint = COutPoint(lx("55" * 32), 0)
        change = KEYSTORE.p2wpkh_scriptpubkey("wv_change")
        tx = RealTransactionBuilder.build_op_return_tx(
            outpoint, b"wv", change, 49_000,
        )
        w = RealTransactionBuilder.weight(tx)
        vs = RealTransactionBuilder.vsize(tx)
        assert w > 0
        assert vs > 0
        assert w >= vs

    def test_build_cpfp_tx(self):
        dest = KEYSTORE.p2wpkh_scriptpubkey("cpfp_dest")
        tx = RealTransactionBuilder.build_cpfp_tx(
            lx("66" * 32), 0, 50_000, dest, 2000,
        )
        assert isinstance(tx, CTransaction)

    def test_build_taproot_keypath_tx(self):
        outpoint = COutPoint(lx("77" * 32), 0)
        dest = KEYSTORE.p2wpkh_scriptpubkey("tapkp_dest")
        tx, sighash = RealTransactionBuilder.build_taproot_keypath_tx(
            outpoint, 50_000, dest,
        )
        assert isinstance(tx, CTransaction)
        assert len(sighash) == 32


# ---------------------------------------------------------------------------
# KeyStore — new features (clear, remove, thread safety, EC tweak)
# ---------------------------------------------------------------------------

class TestKeyStoreNewFeatures:
    def test_clear(self):
        ks = BitcoinKeyStore()
        ks.get_or_create("c1")
        ks.get_or_create("c2")
        assert len(ks) >= 2
        ks.clear()
        assert len(ks) == 0
        assert "c1" not in ks

    def test_remove_key(self):
        ks = BitcoinKeyStore()
        ks.get_or_create("rem1")
        assert ks.remove_key("rem1") is True
        assert ks.remove_key("rem1") is False
        assert "rem1" not in ks

    def test_contains(self):
        ks = BitcoinKeyStore()
        assert "cont_test" not in ks
        ks.get_or_create("cont_test")
        assert "cont_test" in ks

    def test_len(self):
        ks = BitcoinKeyStore()
        assert len(ks) == 0
        ks.get_or_create("l1")
        assert len(ks) == 1

    def test_ec_tweak_deterministic(self):
        """_tweak_pubkey should produce the same result for the same inputs."""
        ks = BitcoinKeyStore()
        tweak = tagged_hash("TapTweak", ks.x_only_pubkey("tw_test"))
        r1 = ks._tweak_pubkey("tw_test", tweak)
        r2 = ks._tweak_pubkey("tw_test", tweak)
        assert r1 == r2
        assert len(r1) == 32  # x-only

    def test_ec_tweak_changes_key(self):
        """Tweaked key should differ from the original internal key."""
        ks = BitcoinKeyStore()
        x_only = ks.x_only_pubkey("tw_diff")
        tweak = tagged_hash("TapTweak", x_only)
        tweaked = ks._tweak_pubkey("tw_diff", tweak)
        assert tweaked != x_only

    def test_p2tr_uses_real_ec_tweak(self):
        """p2tr_scriptpubkey should produce a 34-byte script (OP_1 + 32 bytes)."""
        ks = BitcoinKeyStore()
        script = ks.p2tr_scriptpubkey("p2tr_ec")
        assert isinstance(script, CScript)
        # OP_1 (1 byte) + push-32 (1 byte) + 32-byte key = 34 bytes
        assert len(script) == 34

    def test_thread_safety_concurrent_create(self):
        """Multiple threads creating keys should not corrupt state."""
        import threading
        ks = BitcoinKeyStore()
        errors = []

        def worker(alias):
            try:
                ks.get_or_create(alias)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"thr_{i}",))
                   for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(ks) == 20


# ---------------------------------------------------------------------------
# PSBT
# ---------------------------------------------------------------------------

def _make_unsigned_tx():
    """Helper: build a simple unsigned 1-in-1-out tx."""
    outpoint = COutPoint(lx("aa" * 32), 0)
    dest = KEYSTORE.p2wpkh_scriptpubkey("psbt_dest")
    from bitcoin.core import CMutableTransaction
    tx = CMutableTransaction()
    tx.vin = [CTxIn(outpoint)]
    tx.vout = [CTxOut(49_000, dest)]
    return CTransaction.from_tx(tx)


class TestPSBTCreation:
    def test_from_unsigned_tx(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        assert psbt.num_inputs == 1
        assert psbt.num_outputs == 1
        assert psbt.is_finalized is False

    def test_rejects_signed_tx(self):
        """A tx with non-empty scriptSig should be rejected."""
        from bitcoin.core import CMutableTransaction
        tx = CMutableTransaction()
        tx.vin = [CTxIn(COutPoint(lx("bb" * 32), 0),
                        scriptSig=CScript(b"\x01\x02\x03"))]
        tx.vout = [CTxOut(49_000, CScript(b"\x00\x14" + b"\x00" * 20))]
        with pytest.raises(ValueError, match="scriptSig"):
            PSBT.from_unsigned_tx(CTransaction.from_tx(tx))

    def test_for_htlc(self):
        sender = KEYSTORE.pubkey("psbt_htlc_s")
        recipient = KEYSTORE.pubkey("psbt_htlc_r")
        h = hashlib.sha256(b"psbt_htlc").digest()
        htlc = RealHTLCScript(sender, recipient, h)
        fund_outpoint = COutPoint(lx("cc" * 32), 0)
        fund_tx = RealTransactionBuilder.build_funding_tx(
            fund_outpoint, htlc, 50_000,
        )
        dest = KEYSTORE.p2wpkh_scriptpubkey("psbt_htlc_dest")
        psbt = PSBT.for_htlc(
            fund_tx.GetTxid(), 0, htlc, 50_000, dest,
        )
        assert psbt.num_inputs == 1
        # Witness script should be pre-filled
        summary = psbt.summary()
        assert summary["input_details"][0]["has_witness_script"] is True


class TestPSBTSigning:
    def test_add_signature(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pubkey_hex = KEYSTORE.pubkey("psbt_sig").hex()
        fake_sig = b"\x30" * 72  # DER-ish
        psbt.add_signature(0, pubkey_hex, fake_sig)
        assert psbt.input_has_sig(0, pubkey_hex)
        assert psbt.input_sig_count(0) == 1

    def test_add_signature_rejects_empty(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pubkey_hex = KEYSTORE.pubkey("psbt_empty").hex()
        with pytest.raises(ValueError, match="empty"):
            psbt.add_signature(0, pubkey_hex, b"")

    def test_sign_input_ecdsa(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        msg = hashlib.sha256(b"psbt_sign_test").digest()
        psbt.sign_input(0, "psbt_signer", msg)
        pubkey_hex = KEYSTORE.pubkey("psbt_signer").hex()
        assert psbt.input_has_sig(0, pubkey_hex)

    def test_sign_input_schnorr(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        msg = hashlib.sha256(b"psbt_schnorr_test").digest()
        psbt.sign_input(0, "psbt_schnorr", msg, schnorr=True)
        pubkey_hex = KEYSTORE.x_only_pubkey("psbt_schnorr").hex()
        assert psbt.input_has_sig(0, pubkey_hex)


class TestPSBTCombine:
    def test_combine_two(self):
        tx = _make_unsigned_tx()
        p1 = PSBT.from_unsigned_tx(tx)
        p2 = PSBT.from_unsigned_tx(tx)
        pk1 = KEYSTORE.pubkey("psbt_c1").hex()
        pk2 = KEYSTORE.pubkey("psbt_c2").hex()
        p1.add_signature(0, pk1, b"\x30" * 72)
        p2.add_signature(0, pk2, b"\x31" * 72)
        combined = PSBT.combine([p1, p2])
        assert combined.input_sig_count(0) == 2
        assert combined.input_has_sig(0, pk1)
        assert combined.input_has_sig(0, pk2)

    def test_combine_rejects_different_tx(self):
        tx1 = _make_unsigned_tx()
        # Different outpoint → different tx
        from bitcoin.core import CMutableTransaction
        tx2m = CMutableTransaction()
        tx2m.vin = [CTxIn(COutPoint(lx("ff" * 32), 1))]
        tx2m.vout = [CTxOut(48_000, CScript(b"\x00\x14" + b"\x00" * 20))]
        tx2 = CTransaction.from_tx(tx2m)
        p1 = PSBT.from_unsigned_tx(tx1)
        p2 = PSBT.from_unsigned_tx(tx2)
        with pytest.raises(ValueError, match="different"):
            PSBT.combine([p1, p2])

    def test_combine_single(self):
        tx = _make_unsigned_tx()
        p = PSBT.from_unsigned_tx(tx)
        assert PSBT.combine([p]) is p


class TestPSBTFinalize:
    def test_finalize_and_extract(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pk_hex = KEYSTORE.pubkey("psbt_fin").hex()
        psbt.add_signature(0, pk_hex, b"\x30" * 72)
        psbt.finalize_input(0)
        extracted = psbt.extract()
        assert isinstance(extracted, CTransaction)

    def test_finalize_clears_partial_sigs(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pk_hex = KEYSTORE.pubkey("psbt_clr").hex()
        psbt.add_signature(0, pk_hex, b"\x30" * 72)
        psbt.finalize_input(0)
        assert psbt.input_sig_count(0) == 0  # cleared

    def test_finalize_with_custom_witness_builder(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pk_hex = KEYSTORE.pubkey("psbt_wb").hex()
        psbt.add_signature(0, pk_hex, b"\x30" * 72)
        psbt.update_input(0, witness_script=b"\xab\xcd")

        def custom_builder(sigs, witness_script):
            sig = next(iter(sigs.values()))
            return [sig, b"\x01", witness_script]

        psbt.finalize_input(0, witness_builder=custom_builder)
        extracted = psbt.extract()
        assert isinstance(extracted, CTransaction)

    def test_finalize_rejects_unsigned_input(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        with pytest.raises(ValueError, match="no partial signatures"):
            psbt.finalize_input(0)

    def test_finalize_all(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pk_hex = KEYSTORE.pubkey("psbt_all").hex()
        psbt.add_signature(0, pk_hex, b"\x30" * 72)
        psbt.finalize_all()
        assert psbt.is_finalized is True

    def test_cannot_modify_after_finalize(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        pk_hex = KEYSTORE.pubkey("psbt_lock").hex()
        psbt.add_signature(0, pk_hex, b"\x30" * 72)
        psbt.finalize_all()
        with pytest.raises(RuntimeError, match="finalized"):
            psbt.add_signature(0, pk_hex, b"\x30" * 72)


class TestPSBTSerialization:
    def test_base64_roundtrip(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        b64 = psbt.to_base64()
        assert isinstance(b64, str)
        restored = PSBT.from_base64(b64)
        assert restored.num_inputs == psbt.num_inputs
        assert restored.num_outputs == psbt.num_outputs

    def test_invalid_base64(self):
        import base64
        bad = base64.b64encode(b"not_a_psbt").decode()
        with pytest.raises(ValueError, match="magic"):
            PSBT.from_base64(bad)

    def test_summary(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        s = psbt.summary()
        assert s["inputs"] == 1
        assert s["outputs"] == 1
        assert s["finalized"] is False


class TestPSBTUpdate:
    def test_update_input_metadata(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        psbt.update_input(0, utxo_amount=50_000,
                          witness_script=b"\x00\x01\x02")
        s = psbt.summary()
        assert s["input_details"][0]["utxo_sats"] == 50_000
        assert s["input_details"][0]["has_witness_script"] is True

    def test_update_output_metadata(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        psbt.update_output(0, witness_script=b"\xab\xcd")
        # No assertion error = success (output metadata is internal)

    def test_index_out_of_range(self):
        tx = _make_unsigned_tx()
        psbt = PSBT.from_unsigned_tx(tx)
        with pytest.raises(IndexError):
            psbt.update_input(99, utxo_amount=1000)
