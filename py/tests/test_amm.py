"""
Tests for CovenantAMMScript: swap verification, pause, fees.
"""
import hashlib
import pytest

from py.amm.covenant_amm import CovenantAMMScript
from py.amm.state import FeeAccumulator


class TestCovenantReset:
    def test_reset_clears_state(self):
        CovenantAMMScript.emit_event("test", {"x": 1})
        CovenantAMMScript._paused = True
        CovenantAMMScript._last_swap_block = 42
        CovenantAMMScript.reset()
        assert CovenantAMMScript._paused is False
        assert len(CovenantAMMScript._events) == 0
        assert CovenantAMMScript._last_swap_block == 0


class TestPauseAuth:
    def test_empty_signature_rejected(self):
        assert CovenantAMMScript.verify_pause_auth(b"") is False

    def test_any_signature_dev_mode(self):
        """With no authority set, any non-empty signature is accepted."""
        CovenantAMMScript.reset()
        CovenantAMMScript._pause_auth_hash = None
        assert CovenantAMMScript.verify_pause_auth(b"any") is True

    def test_set_authority_validates(self):
        CovenantAMMScript.reset()
        secret = b"authorized_pause_key"
        auth_hash = hashlib.sha256(secret).digest()
        CovenantAMMScript.set_pause_authority(auth_hash)

        # Correct key passes
        assert CovenantAMMScript.verify_pause_auth(secret) is True
        # Wrong key fails
        assert CovenantAMMScript.verify_pause_auth(b"wrong_key") is False
        # Clean up
        CovenantAMMScript._pause_auth_hash = None

    def test_set_authority_bad_length(self):
        with pytest.raises(ValueError):
            CovenantAMMScript.set_pause_authority(b"short")


class TestPause:
    def test_pause_and_unpause(self):
        CovenantAMMScript.reset()
        CovenantAMMScript.set_paused(True, b"auth")
        assert CovenantAMMScript._paused is True
        CovenantAMMScript.set_paused(False, b"auth")
        assert CovenantAMMScript._paused is False


class TestEventCap:
    def test_events_capped(self):
        CovenantAMMScript.reset()
        for i in range(CovenantAMMScript._MAX_EVENTS + 500):
            CovenantAMMScript.emit_event("test", {"i": i})
        assert len(CovenantAMMScript._events) <= CovenantAMMScript._MAX_EVENTS
        CovenantAMMScript.reset()


class TestSwapVerification:
    def test_valid_btc_to_anch_swap(self):
        CovenantAMMScript.reset()
        out = CovenantAMMScript.get_amount_out(
            amount_in=1_000_000,
            reserve_in=100_000_000,
            reserve_out=10_000_000,
            fee_basis=3,
        )
        ok = CovenantAMMScript.verify_swap(
            old_btc=100_000_000, old_anch=10_000_000,
            new_btc=100_000_000 + 1_000_000,
            new_anch=10_000_000 - out,
            btc_in=1_000_000, anch_out=out,
        )
        assert ok is True

    def test_reject_swap_exceeding_max_output(self):
        """Swap claiming more output than formula allows should fail."""
        CovenantAMMScript.reset()
        out = CovenantAMMScript.get_amount_out(1_000_000, 100_000_000, 10_000_000)
        ok = CovenantAMMScript.verify_swap(
            old_btc=100_000_000, old_anch=10_000_000,
            new_btc=101_000_000, new_anch=10_000_000 - (out + 1),
            btc_in=1_000_000, anch_out=out + 1,
        )
        assert ok is False

    def test_reject_zero_input(self):
        CovenantAMMScript.reset()
        ok = CovenantAMMScript.verify_swap(
            old_btc=100, old_anch=100,
            new_btc=100, new_anch=100,
            btc_in=0, anch_out=0,
        )
        assert ok is False
