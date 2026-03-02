"""
Tests for PersistentDEX: swap recording, oracle sync, DB round-trip.
"""
import pytest


class TestPersistentDEXInit:
    def test_fresh_pool(self, pdex):
        info = pdex.get_pool_info()
        assert info["btc_reserve"] == 100_000_000
        assert info["anch_reserve"] == 10_000_000


class TestPersistentFunding:
    def test_fund_and_query(self, pdex):
        pdex.fund_btc("alice", 5_000_000)
        bal = pdex.get_balances("alice")
        assert bal["btc_sats"] == 5_000_000

    def test_balance_persisted(self, pdex):
        pdex.fund_anch("bob", 1_000_000)
        saved = pdex.store.load_user("bob")
        assert saved is not None
        assert saved["anch"] == 1_000_000


class TestPersistentSwaps:
    def test_swap_btc_to_anch(self, pdex):
        pdex.fund_btc("alice", 10_000_000)
        ok = pdex.swap_btc_to_anch("alice", 1_000_000)
        assert ok is True
        bal = pdex.get_balances("alice")
        assert bal["btc_sats"] < 10_000_000
        assert bal["anch"] > 0

    def test_swap_recorded_in_history(self, pdex):
        pdex.fund_btc("alice", 10_000_000)
        pdex.swap_btc_to_anch("alice", 1_000_000)
        history = pdex.history(limit=10)
        assert len(history) >= 1
        rec = history[0]
        assert rec["user"] == "alice"
        assert rec["direction"] == "BTC_TO_ANCH"
        assert rec["btc_amount"] == 1_000_000
        # anch_amount should be the actual swap output, not total balance
        assert rec["anch_amount"] > 0
        assert rec["anch_amount"] < 10_000_000  # not total balance

    def test_swap_anch_to_btc_records_correct_amounts(self, pdex):
        pdex.fund_anch("bob", 2_000_000)
        pdex.swap_anch_to_btc("bob", 500_000)
        history = pdex.history(limit=10)
        rec = history[0]
        assert rec["direction"] == "ANCH_TO_BTC"
        assert rec["anch_amount"] == 500_000
        # btc_amount should be the swap output, not total balance
        assert rec["btc_amount"] > 0
        assert rec["btc_amount"] < 100_000_000


class TestPersistentDBRoundTrip:
    def test_reload_from_db(self, tmp_path):
        from py.persistence import PersistentDEX
        from py.amm.covenant_amm import CovenantAMMScript
        CovenantAMMScript.reset()

        db_path = str(tmp_path / "roundtrip.db")
        p1 = PersistentDEX(db_path=db_path)
        p1.fund_btc("alice", 5_000_000)
        p1.swap_btc_to_anch("alice", 1_000_000)
        info1 = p1.get_pool_info()
        bal1 = p1.get_balances("alice")

        # Reload from same DB
        CovenantAMMScript.reset()
        p2 = PersistentDEX(db_path=db_path)
        info2 = p2.get_pool_info()
        bal2 = p2.get_balances("alice")

        assert info2["btc_reserve"] == info1["btc_reserve"]
        assert info2["anch_reserve"] == info1["anch_reserve"]
        assert bal2["btc_sats"] == bal1["btc_sats"]
        assert bal2["anch"] == bal1["anch"]
