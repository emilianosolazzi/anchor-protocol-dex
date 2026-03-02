"""
Tests for the covenants layer: CTV, CAT, APO, CSFS, presigned, engine.
"""
import pytest
from bitcoin.core import COutPoint, CTransaction, CTxIn, CTxOut, CScript, lx

from py.covenants.ctv import CTVTemplate
from py.covenants.cat import CATCovenant, _MAX_CAT_RESULT
from py.covenants.apo import APOCovenant
from py.covenants.csfs import CSFSCovenant
from py.covenants.presigned import PreSignedTree, DEFAULT_EXIT_DELAY
from py.covenants.engine import HybridCovenantEngine
from py.covenants.opcodes import CovenantNetwork, sha256
from py.amm.state import PoolState, SwapType
from py.amm.covenant_amm import CovenantAMMScript
from py.crypto.keys import KEYSTORE


# ---------------------------------------------------------------------------
# CTV
# ---------------------------------------------------------------------------

class TestCTVTemplate:
    def _make_tx(self):
        """Create a minimal valid CTransaction."""
        outpoint = COutPoint(lx("ab" * 32), 0)
        tx = CTransaction([CTxIn(outpoint)],
                          [CTxOut(10_000, CScript(b"\x00\x14" + b"\xaa" * 20))])
        return tx

    def test_template_hash_deterministic(self):
        tx = self._make_tx()
        h1 = CTVTemplate.compute_template_hash(tx)
        h2 = CTVTemplate.compute_template_hash(tx)
        assert h1 == h2
        assert len(h1) == 32

    def test_from_transaction_alias(self):
        tx = self._make_tx()
        assert CTVTemplate.from_transaction(tx) == CTVTemplate.compute_template_hash(tx)

    def test_outputs_hash_32_bytes(self):
        tx = self._make_tx()
        assert len(CTVTemplate.compute_outputs_hash(tx)) == 32

    def test_sequences_hash_32_bytes(self):
        tx = self._make_tx()
        assert len(CTVTemplate.compute_sequences_hash(tx)) == 32

    def test_build_ctv_script(self):
        h = b"\x00" * 32
        script = CTVTemplate.build_ctv_script(h)
        assert isinstance(script, CScript)
        assert len(script) > 0

    def test_build_ctv_tapleaf(self):
        h = b"\xff" * 32
        leaf = CTVTemplate.build_ctv_tapleaf(h)
        assert isinstance(leaf, bytes)
        assert len(leaf) == 32  # SHA-256 hash

    def test_info_returns_dict(self):
        info = CTVTemplate.info()
        assert isinstance(info, dict)
        assert "bip" in info or "name" in info or len(info) > 0


# ---------------------------------------------------------------------------
# CAT
# ---------------------------------------------------------------------------

class TestCATCovenant:
    def test_state_commitment_script(self):
        old_h = sha256(b"old")
        new_h = sha256(b"new")
        script = CATCovenant.build_state_commitment_script(old_h, new_h)
        assert isinstance(script, CScript)
        assert len(script) > 0

    def test_amm_invariant_check(self):
        script, witness = CATCovenant.build_amm_invariant_check(
            100_000, 100_000, 110_000, 91_000,
        )
        assert isinstance(script, CScript)
        assert isinstance(witness, bytes)

    def test_cat_ctv_hybrid_script(self):
        sc = sha256(b"state")
        ch = sha256(b"ctv")
        script = CATCovenant.build_cat_ctv_hybrid_script(sc, ch)
        assert isinstance(script, CScript)

    def test_vault_script(self):
        hot = KEYSTORE.pubkey("hot")
        cold = KEYSTORE.pubkey("cold")
        script = CATCovenant.build_vault_script(hot, cold, 100)
        assert isinstance(script, CScript)

    def test_max_cat_elements(self):
        assert CATCovenant.max_cat_elements(32) > 0
        assert CATCovenant.max_cat_elements(520) == 1

    def test_info(self):
        info = CATCovenant.info()
        assert isinstance(info, dict)


# ---------------------------------------------------------------------------
# APO
# ---------------------------------------------------------------------------

class TestAPOCovenant:
    def test_build_apo_update_script(self):
        key = KEYSTORE.pubkey("apo_test")
        script = APOCovenant.build_apo_update_script(key)
        assert isinstance(script, CScript)

    def test_build_apo_pool_script(self):
        key = KEYSTORE.pubkey("apo_pool")
        state_h = sha256(b"pool_state")
        script = APOCovenant.build_apo_pool_script(key, state_h)
        assert isinstance(script, CScript)

    def test_ln_symmetry_script(self):
        key = KEYSTORE.pubkey("ln_key")
        script = APOCovenant.build_ln_symmetry_script(key, state_number=42)
        assert isinstance(script, CScript)

    def test_create_and_verify_apo_signature(self):
        pk = KEYSTORE.get_or_create("apo_signer")
        tx_data = sha256(b"some_tx")
        sig = APOCovenant.create_apo_signature(pk, tx_data)
        assert isinstance(sig, bytes)
        assert len(sig) > 0
        # Verification
        pub = KEYSTORE.pubkey("apo_signer")
        result = APOCovenant.verify_apo_signature(pub, sig, tx_data)
        assert result is True

    def test_anyprevoutanyscript_signature(self):
        pk = KEYSTORE.get_or_create("apoas_signer")
        sig = APOCovenant.create_anyprevoutanyscript_signature(pk, sha256(b"data"))
        assert isinstance(sig, bytes)

    def test_info(self):
        assert isinstance(APOCovenant.info(), dict)


# ---------------------------------------------------------------------------
# CSFS
# ---------------------------------------------------------------------------

class TestCSFSCovenant:
    def test_build_csfs_covenant_script(self):
        key = KEYSTORE.pubkey("csfs_op")
        state = sha256(b"state")
        script = CSFSCovenant.build_csfs_covenant_script(key, state)
        assert isinstance(script, CScript)

    def test_build_combined_script(self):
        key = KEYSTORE.pubkey("csfs_comb")
        state = sha256(b"s")
        ctv_h = sha256(b"c")
        script = CSFSCovenant.build_csfs_ctv_combined_script(key, state, ctv_h)
        assert isinstance(script, CScript)

    def test_delegation_script(self):
        owner = KEYSTORE.pubkey("owner")
        delegate = KEYSTORE.pubkey("delegate")
        script = CSFSCovenant.build_delegation_script(owner, delegate)
        assert isinstance(script, CScript)

    def test_sign_and_verify_state(self):
        state_data = sha256(b"some_state")
        sig = CSFSCovenant.sign_state_transition("csfs_test_signer", state_data)
        assert isinstance(sig, bytes)
        assert CSFSCovenant.verify_state_signature("csfs_test_signer", sig, state_data)

    def test_info(self):
        assert isinstance(CSFSCovenant.info(), dict)


# ---------------------------------------------------------------------------
# PreSignedTree
# ---------------------------------------------------------------------------

class TestPreSignedTree:
    def test_build_swap_tree(self):
        tree = PreSignedTree(signers=["alice_ps", "bob_ps"])
        outpoint = COutPoint(lx("cc" * 32), 0)
        pool = PoolState(
            btc_reserve=100_000_000,
            anch_reserve=10_000_000,
            lp_total=0,
            taproot_address="bcrt1ptest",
            script_merkle_root=b"\x00" * 32,
        )
        root = tree.build_swap_tree(outpoint, pool, SwapType.BTC_TO_ANCH,
                                    price_ticks=[100, 200, 500])
        assert root is not None
        assert root.label is not None

    def test_verify_all_signatures(self):
        tree = PreSignedTree(signers=["sig_a", "sig_b"])
        outpoint = COutPoint(lx("dd" * 32), 0)
        pool = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        tree.build_swap_tree(outpoint, pool, SwapType.BTC_TO_ANCH, [100])
        assert tree.verify_all_signatures() is True

    def test_tree_summary(self):
        tree = PreSignedTree(signers=["sum_a"])
        outpoint = COutPoint(lx("ee" * 32), 0)
        pool = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        tree.build_swap_tree(outpoint, pool, SwapType.BTC_TO_ANCH, [100, 500])
        summary = tree.get_tree_summary()
        assert isinstance(summary, list)
        assert len(summary) > 0

    def test_find_matching_leaf(self):
        tree = PreSignedTree(signers=["leaf_a"])
        outpoint = COutPoint(lx("ff" * 32), 0)
        pool = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        tree.build_swap_tree(outpoint, pool, SwapType.BTC_TO_ANCH, [100, 500, 1000])
        # Should find a leaf or return None (both are valid)
        result = tree.find_matching_leaf(500)
        # Just ensure it doesn't crash

    def test_refresh_needed(self):
        tree = PreSignedTree(signers=["refresh_a"], exit_delay=144)
        assert tree.refresh_needed_by(200, 0) >= 0

    def test_info(self):
        tree = PreSignedTree(signers=["info_a"])
        info = tree.info()
        assert isinstance(info, dict)


# ---------------------------------------------------------------------------
# HybridCovenantEngine
# ---------------------------------------------------------------------------

class TestHybridCovenantEngine:
    def setup_method(self):
        CovenantAMMScript.reset()

    def test_enforce_swap_regtest(self):
        engine = HybridCovenantEngine(CovenantNetwork.REGTEST)
        old = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        new = PoolState(101_000_000, 9_901_000, 0, "", b"\x00" * 32)
        result = engine.enforce_swap(old, new, SwapType.BTC_TO_ANCH, 1_000_000, 99_000)
        assert isinstance(result, dict)
        assert "strategy" in result

    def test_enforce_swap_mainnet(self):
        engine = HybridCovenantEngine(CovenantNetwork.MAINNET)
        old = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        new = PoolState(101_000_000, 9_901_000, 0, "", b"\x00" * 32)
        result = engine.enforce_swap(old, new, SwapType.BTC_TO_ANCH, 1_000_000, 99_000)
        assert isinstance(result, dict)
        assert result["strategy"] == "presigned"

    def test_get_capabilities(self):
        engine = HybridCovenantEngine(CovenantNetwork.REGTEST)
        caps = engine.get_capabilities()
        assert isinstance(caps, dict)
        assert "network" in caps

    def test_strategy_override(self):
        engine = HybridCovenantEngine(CovenantNetwork.REGTEST, strategy_override="cat_only")
        old = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
        new = PoolState(101_000_000, 9_901_000, 0, "", b"\x00" * 32)
        result = engine.enforce_swap(old, new, SwapType.BTC_TO_ANCH, 1_000_000, 99_000)
        assert result["strategy"] == "cat_only"

    def test_can_upgrade_and_upgrade(self):
        engine = HybridCovenantEngine(CovenantNetwork.REGTEST)
        # Test upgrade to a different strategy than current
        caps = engine.get_capabilities()
        current = caps.get("strategy", "")
        # Pick a target that differs from the current strategy
        targets = [s for s in HybridCovenantEngine.STRATEGIES if s != current]
        if targets:
            target = targets[0]
            can = engine.can_upgrade_to(target)
            if can:
                assert engine.upgrade_strategy(target) is True

    def test_all_networks_enforce(self):
        for net in CovenantNetwork:
            engine = HybridCovenantEngine(net)
            old = PoolState(100_000_000, 10_000_000, 0, "", b"\x00" * 32)
            new = PoolState(101_000_000, 9_901_000, 0, "", b"\x00" * 32)
            result = engine.enforce_swap(old, new, SwapType.BTC_TO_ANCH, 1_000_000, 99_000)
            assert "strategy" in result
