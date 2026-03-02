"""
Tests for the RGB asset module: mint, transfer, settle, refund.
"""
import pytest

from py.anchor.rgb import RGBAsset, MAX_BALANCE


class TestMint:
    def test_mint_and_balance(self):
        asset = RGBAsset("TEST")
        asset.mint("alice", 1_000)
        assert asset.balance_of("alice") == 1_000
        assert asset.total_supply == 1_000

    def test_mint_overflow_rejected(self):
        asset = RGBAsset("TEST")
        with pytest.raises(ValueError, match="ceiling"):
            asset.mint("alice", MAX_BALANCE + 1)

    def test_mint_zero_rejected(self):
        asset = RGBAsset("TEST")
        with pytest.raises(ValueError, match="positive"):
            asset.mint("alice", 0)


class TestTransfer:
    def test_create_and_settle(self):
        asset = RGBAsset("TEST")
        asset.mint("alice", 10_000)
        import hashlib
        secret = b"my_htlc_secret"
        secret_hash = hashlib.sha256(secret).hexdigest()

        t = asset.create_transfer(
            from_addr="alice", to_addr="bob", amount=5_000,
            condition=f"OP_HASH256 {secret_hash} OP_EQUAL",
        )
        # alice's balance reduced (escrowed)
        assert asset.balance_of("alice") == 5_000
        # bob hasn't received yet
        assert asset.balance_of("bob") == 0

        # Settle
        ok = asset.settle_transfer(t.transfer_id, secret)
        assert ok is True
        assert asset.balance_of("bob") == 5_000

    def test_insufficient_balance(self):
        asset = RGBAsset("TEST")
        asset.mint("alice", 100)
        import hashlib
        with pytest.raises(ValueError, match="Insufficient"):
            asset.create_transfer(
                from_addr="alice", to_addr="bob", amount=200,
                condition="OP_HASH256 abc OP_EQUAL",
            )

    def test_refund_transfer(self):
        asset = RGBAsset("TEST")
        asset.mint("alice", 10_000)
        import hashlib
        secret_hash = hashlib.sha256(b"x").hexdigest()
        t = asset.create_transfer(
            from_addr="alice", to_addr="bob", amount=3_000,
            condition=f"OP_HASH256 {secret_hash} OP_EQUAL",
        )
        assert asset.balance_of("alice") == 7_000
        ok = asset.refund_transfer(t.transfer_id)
        assert ok is True
        assert asset.balance_of("alice") == 10_000


class TestHistoryCap:
    def test_history_bounded(self):
        from py.anchor.rgb import MAX_HISTORY
        asset = RGBAsset("TEST")
        # Mint many times to fill history
        for i in range(MAX_HISTORY + 100):
            asset.mint(f"user_{i}", 1)
        assert len(asset._history) <= MAX_HISTORY
