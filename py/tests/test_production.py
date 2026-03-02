"""
Tests for ProductionDEX: pool creation, funding, swaps, cancels.
"""
import pytest

from py.production import ProductionDEX


class TestPoolCreation:
    def test_default_reserves(self, dex):
        info = dex.get_pool_info()
        assert info["btc_reserve"] == 100_000_000
        assert info["anch_reserve"] == 10_000_000
        assert info["pending_swaps"] == 0

    def test_custom_reserves(self):
        d = ProductionDEX(initial_btc=50_000, initial_anch=5_000)
        info = d.get_pool_info()
        assert info["btc_reserve"] == 50_000
        assert info["anch_reserve"] == 5_000


class TestFunding:
    def test_fund_btc(self, dex):
        dex.fund_user_btc("alice", 1_000_000)
        bal = dex.get_balances("alice")
        assert bal["btc_sats"] == 1_000_000
        assert bal["anch"] == 0

    def test_fund_anch(self, dex):
        dex.fund_user_anch("alice", 500_000)
        bal = dex.get_balances("alice")
        assert bal["anch"] == 500_000
        assert bal["btc_sats"] == 0

    def test_zero_balance_unknown_user(self, dex):
        bal = dex.get_balances("nobody")
        assert bal["btc_sats"] == 0
        assert bal["anch"] == 0


class TestSwaps:
    def test_swap_btc_for_anch(self, funded_dex):
        dex = funded_dex
        bal_before = dex.get_balances("alice")
        swap_id, htlc, rgb = dex.swap_btc_for_anch("alice", 5_000_000)
        assert isinstance(swap_id, str) and len(swap_id) == 64
        ok = dex.complete_swap(swap_id)
        assert ok is True
        bal_after = dex.get_balances("alice")
        assert bal_after["btc_sats"] < bal_before["btc_sats"]
        assert bal_after["anch"] > bal_before["anch"]

    def test_swap_anch_for_btc(self, funded_dex):
        dex = funded_dex
        bal_before = dex.get_balances("bob")
        swap_id, rgb, htlc = dex.swap_anch_for_btc("bob", 500_000)
        assert isinstance(swap_id, str)
        ok = dex.complete_swap(swap_id)
        assert ok is True
        bal_after = dex.get_balances("bob")
        assert bal_after["btc_sats"] > bal_before["btc_sats"]
        assert bal_after["anch"] < bal_before["anch"]

    def test_swap_preserves_k(self, funded_dex):
        """k should be non-decreasing after a swap (fees increase it)."""
        dex = funded_dex
        info_before = dex.get_pool_info()
        k_before = info_before["btc_reserve"] * info_before["anch_reserve"]

        sid, _, _ = dex.swap_btc_for_anch("alice", 2_000_000)
        dex.complete_swap(sid)

        info_after = dex.get_pool_info()
        k_after = info_after["btc_reserve"] * info_after["anch_reserve"]
        assert k_after >= k_before

    def test_complete_unknown_swap(self, dex):
        assert dex.complete_swap("nonexistent_id") is False


class TestCancelSwap:
    def test_cancel_partial_refund(self, funded_dex):
        """
        Cancel refunds the RGB leg; BTC may only refund after
        HTLC timelock expires.  ProductionDEX.cancel_swap reports
        True for partial refunds too.
        """
        dex = funded_dex
        sid, _, _ = dex.swap_btc_for_anch("alice", 1_000_000)
        # Cancel (timelock still active — partial cancel expected)
        ok = dex.cancel_swap(sid, current_block=999_999)
        assert ok is True
        assert sid not in dex._pending

    def test_cancel_unknown_swap(self, dex):
        assert dex.cancel_swap("nonexistent", current_block=1) is False


class TestStaleSwapCleanup:
    def test_cleanup_stale_swaps(self, funded_dex):
        import time
        dex = funded_dex
        sid, _, _ = dex.swap_btc_for_anch("alice", 1_000_000)
        # Artificially age the pending swap
        dex._pending[sid]["created_at"] = time.time() - dex.PENDING_TTL_SECS - 1
        cleaned = dex.cleanup_stale_swaps()
        assert cleaned == 1
        assert sid not in dex._pending

    def test_cleanup_keeps_fresh_swaps(self, funded_dex):
        dex = funded_dex
        sid, _, _ = dex.swap_btc_for_anch("alice", 1_000_000)
        cleaned = dex.cleanup_stale_swaps()
        assert cleaned == 0
        assert sid in dex._pending
        # Clean up
        dex.cancel_swap(sid, current_block=999_999)
