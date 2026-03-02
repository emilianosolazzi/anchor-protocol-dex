"""
Tests for the crypto layer: keys, scripts, transactions.
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
    DUST_THRESHOLD,
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
