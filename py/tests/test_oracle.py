"""
Tests for SimpleOracle: price updates, staleness, deviation guards.
"""
import time
import pytest

from py.amm.oracle import SimpleOracle


class TestSimpleOracle:
    def test_initial_price(self):
        o = SimpleOracle(10.0)
        assert o.price == 10.0
        assert o.price_fixed == 10 * 10**8

    def test_update_price(self):
        o = SimpleOracle(10.0)
        o.update_price(10.5)
        assert o.price == 10.5
        assert o.update_count == 1

    def test_reject_zero_price(self):
        with pytest.raises(ValueError):
            SimpleOracle(0)

    def test_reject_negative_price(self):
        with pytest.raises(ValueError):
            SimpleOracle(-5.0)

    def test_reject_nan(self):
        with pytest.raises(ValueError):
            SimpleOracle(float("nan"))

    def test_reject_inf(self):
        with pytest.raises(ValueError):
            SimpleOracle(float("inf"))

    def test_deviation_guard(self):
        o = SimpleOracle(10.0)
        # >50% change should be rejected
        with pytest.raises(ValueError, match="too large"):
            o.update_price(100.0)

    def test_check_price_integer(self):
        o = SimpleOracle(10.0)
        # 10 sats per ANCH => 10000 sats / 1000 ANCH = 10
        assert o.check_price_integer(10_000, 1_000) is True

    def test_check_price_integer_out_of_range(self):
        o = SimpleOracle(10.0)
        # 100 sats / 1 ANCH = 100 -- way off from oracle price of 10
        assert o.check_price_integer(100, 1) is False

    def test_history_capped(self):
        o = SimpleOracle(10.0)
        # Update many times within deviation limits
        price = 10.0
        for _ in range(1100):
            price *= 1.0001  # tiny increments
            o.update_price(price)
        assert len(o._history) <= o.MAX_HISTORY

    def test_staleness_check(self):
        o = SimpleOracle(10.0)
        # Artificially age the oracle
        o._updated_at = time.time() - o.MAX_STALENESS_SECS - 1
        assert o.check_price_integer(10_000, 1_000) is False
