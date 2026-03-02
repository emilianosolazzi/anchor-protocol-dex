"""
Tests for the Flask REST API: health, pool, swap, error handling, auth.
"""
import os
import tempfile
import pytest


@pytest.fixture
def api_client(tmp_path):
    """Flask test client with no API key required, fresh DB."""
    # Ensure no API key for basic tests
    os.environ.pop("ANCHOR_DEX_API_KEY", None)

    from py.amm.covenant_amm import CovenantAMMScript
    CovenantAMMScript.reset()

    from py.persistence import PersistentDEX
    from py.api.flask_app import create_flask_app
    import py.api.flask_app as mod
    mod.API_KEY = None

    pdex = PersistentDEX(db_path=str(tmp_path / "test_api.db"))
    app = create_flask_app(pdex=pdex)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def authed_client(tmp_path):
    """Flask test client requiring X-API-Key header."""
    from py.amm.covenant_amm import CovenantAMMScript
    CovenantAMMScript.reset()

    from py.persistence import PersistentDEX
    from py.api.flask_app import create_flask_app
    import py.api.flask_app as mod
    mod.API_KEY = "test-secret-key"

    pdex = PersistentDEX(db_path=str(tmp_path / "test_api_auth.db"))
    app = create_flask_app(pdex=pdex)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

    mod.API_KEY = None


class TestHealth:
    def test_root_health(self, api_client):
        r = api_client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_v1_health(self, api_client):
        r = api_client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert "pool" in data


class TestPool:
    def test_pool_info(self, api_client):
        r = api_client.get("/api/v1/pool")
        assert r.status_code == 200
        data = r.get_json()
        assert data["btc_reserve"] > 0
        assert data["anch_reserve"] > 0

    def test_spot_price(self, api_client):
        r = api_client.get("/api/v1/pool/spot-price")
        assert r.status_code == 200
        assert "spot_price_fixed" in r.get_json()


class TestFund:
    def test_fund_btc(self, api_client):
        r = api_client.post("/api/v1/fund", json={
            "user": "alice", "btc": 5_000_000,
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["balances"]["btc_sats"] == 5_000_000

    def test_fund_no_amount(self, api_client):
        r = api_client.post("/api/v1/fund", json={"user": "alice"})
        assert r.status_code == 400


class TestSwap:
    def test_btc_to_anch(self, api_client):
        # Fund first
        api_client.post("/api/v1/fund", json={"user": "alice", "btc": 10_000_000})
        r = api_client.post("/api/v1/swap", json={
            "user": "alice", "amount": 1_000_000, "direction": "BTC_TO_ANCH",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "completed"

    def test_invalid_direction(self, api_client):
        r = api_client.post("/api/v1/swap", json={
            "user": "alice", "amount": 100, "direction": "INVALID",
        })
        assert r.status_code == 400


class TestQuote:
    def test_get_quote(self, api_client):
        r = api_client.get("/api/v1/quote?direction=BTC_TO_ANCH&amount=1000000")
        assert r.status_code == 200
        data = r.get_json()
        assert data["amount_out"] > 0
        assert data["direction"] == "BTC_TO_ANCH"


class TestHistory:
    def test_history_empty(self, api_client):
        r = api_client.get("/api/v1/history")
        assert r.status_code == 200
        data = r.get_json()
        assert "swaps" in data
        assert "pagination" in data


class TestErrorHandling:
    def test_404(self, api_client):
        r = api_client.get("/api/v1/nonexistent")
        assert r.status_code == 404

    def test_405(self, api_client):
        r = api_client.delete("/api/v1/health")
        assert r.status_code == 405


class TestAPIKeyAuth:
    def test_no_key_blocks_fund(self, authed_client):
        r = authed_client.post("/api/v1/fund", json={
            "user": "alice", "btc": 100,
        })
        assert r.status_code == 401

    def test_wrong_key_blocks(self, authed_client):
        r = authed_client.post("/api/v1/fund",
                               json={"user": "alice", "btc": 100},
                               headers={"X-API-Key": "wrong"})
        assert r.status_code == 401

    def test_correct_key_allows(self, authed_client):
        r = authed_client.post("/api/v1/fund",
                               json={"user": "alice", "btc": 100},
                               headers={"X-API-Key": "test-secret-key"})
        assert r.status_code == 200

    def test_health_bypasses_auth(self, authed_client):
        # Health probes should not require auth
        r = authed_client.get("/health")
        assert r.status_code == 200
