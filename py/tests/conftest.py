"""
Fixtures shared across the ANCHOR DEX test suite.
"""
import os
import sys
import pytest

# Ensure the project root is on sys.path so ``import py`` works.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Force regtest + initialise the package
import py  # noqa: F401, E402

from py.production import ProductionDEX  # noqa: E402
from py.persistence import PersistentDEX  # noqa: E402
from py.amm.covenant_amm import CovenantAMMScript  # noqa: E402


@pytest.fixture
def dex():
    """Fresh ProductionDEX with default reserves (100M sats / 10M ANCH)."""
    CovenantAMMScript.reset()
    return ProductionDEX(initial_btc=100_000_000, initial_anch=10_000_000)


@pytest.fixture
def funded_dex(dex):
    """ProductionDEX with alice (20M sats) and bob (2M ANCH) funded."""
    dex.fund_user_btc("alice", 20_000_000)
    dex.fund_user_anch("bob", 2_000_000)
    return dex


@pytest.fixture
def pdex(tmp_path):
    """PersistentDEX using a temp SQLite database."""
    CovenantAMMScript.reset()
    db_path = str(tmp_path / "test_dex.db")
    return PersistentDEX(db_path=db_path)
