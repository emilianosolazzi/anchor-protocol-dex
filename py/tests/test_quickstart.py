"""
Tests for the quickstart demo script.
"""
import pytest


class TestQuickstart:
    def test_quickstart_runs_without_error(self):
        """Smoke test: quickstart.main() should complete without exceptions."""
        from py.amm.covenant_amm import CovenantAMMScript
        CovenantAMMScript.reset()
        from py.quickstart import main
        # Should not raise
        main()
