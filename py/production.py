"""
ProductionDEX -- four-layer production-grade DEX.

  Layer 1: RGB for ANCH tokens (off-chain client-validated)
  Layer 2: HTLCs for atomic swaps (on-chain Bitcoin Script)
  Layer 3: BitVM fraud proofs for AMM math (challenge-response)
  Layer 4: ANCHOR protocol (ephemeral anchor fee-market)
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import hashlib
import os
import time
from typing import Dict, Tuple

from .amm.state import SwapType
from .amm.oracle import SimpleOracle, BitVMPool
from .anchor.rgb import RGBAsset, RGBTransfer
from .anchor.htlc import HTLCContract, HTLCAtomicSwap
from .anchor.protocol import AnchorProtocol


class ProductionDEX:
    POOL_ADDRESS = "pool_taproot_address_v1"
    SLIPPAGE_BPS = 50  # FIX #3 -- default 0.5 % slippage tolerance
    PENDING_TTL_SECS = 3600  # Abandon pending swaps older than 1 hour

    def __init__(self, initial_btc: int = 100_000_000, initial_anch: int = 10_000_000):
        # Layer 1 -- RGB token ledger
        self.anch_rgb = RGBAsset("ANCH")
        self.anch_rgb.mint(self.POOL_ADDRESS, initial_anch)
        # Layer 2 -- HTLC engine
        self.htlc_engine = HTLCAtomicSwap()
        self.htlc_engine.fund(self.POOL_ADDRESS, initial_btc)
        # Layer 3 -- BitVM AMM
        self.liquidity_pool = BitVMPool(initial_btc, initial_anch)
        # Layer 4 -- ANCHOR protocol
        self.anchor_protocol = AnchorProtocol(self.anch_rgb)
        # FIX #7 -- price oracle
        initial_price = initial_btc / initial_anch
        self.oracle = SimpleOracle(initial_price)
        # Pending swap state
        self._pending: Dict[str, dict] = {}

    def fund_user_btc(self, user: str, amount: int):
        self.htlc_engine.fund(user, amount)

    def fund_user_anch(self, user: str, amount: int):
        self.anch_rgb.mint(user, amount)

    def swap_btc_for_anch(
        self,
        user: str,
        btc_amount: int,
        slippage_bps: int = 50,
    ) -> Tuple[str, HTLCContract, RGBTransfer]:
        logger.info(f"\n  [ProductionDEX] {user[:12]}... wants to swap {btc_amount:,} sats -> ANCH")

        anch_amount = self.liquidity_pool.get_quote(SwapType.BTC_TO_ANCH, btc_amount)
        logger.info(f"  [ProductionDEX] AMM quote: {btc_amount:,} sats -> {anch_amount:,} ANCH")

        if not self.oracle.check_price_integer(btc_amount, anch_amount):
            raise ValueError("[ProductionDEX] Oracle price check failed -- swap aborted")

        min_out = anch_amount * (10_000 - slippage_bps) // 10_000
        logger.info(f"  [ProductionDEX] min_amount_out={min_out:,} ANCH "
              f"(slippage tolerance: {slippage_bps/100:.2f}%)")

        secret = os.urandom(32)
        secret_hash = hashlib.sha256(secret).hexdigest()

        btc_htlc = self.htlc_engine.create_btc_lock(
            sender=user, amount=btc_amount, hashlock=secret_hash,
            recipient=self.POOL_ADDRESS, timelock=144,
        )

        anch_transfer = self.anch_rgb.create_transfer(
            from_addr=self.POOL_ADDRESS, to_addr=user,
            amount=anch_amount, condition=f"OP_HASH256 {secret_hash} OP_EQUAL",
        )

        swap_id = hashlib.sha256(
            (btc_htlc.contract_id + anch_transfer.transfer_id).encode()
        ).hexdigest()

        self._pending[swap_id] = {
            "direction": SwapType.BTC_TO_ANCH,
            "user": user,
            "btc_amount": btc_amount,
            "anch_amount": anch_amount,
            "min_out": min_out,
            "secret": secret,
            "htlc": btc_htlc,
            "rgb_transfer": anch_transfer,
            "created_at": time.time(),
        }
        logger.info(f"  [ProductionDEX] Swap {swap_id[:16]}... initiated. "
              f"Call complete_swap() to reveal secret and settle.")
        return swap_id, btc_htlc, anch_transfer

    def swap_anch_for_btc(
        self,
        user: str,
        anch_amount: int,
        slippage_bps: int = 50,
    ) -> Tuple[str, RGBTransfer, HTLCContract]:
        logger.info(f"\n  [ProductionDEX] {user[:12]}... wants to swap {anch_amount:,} ANCH -> BTC")

        btc_amount = self.liquidity_pool.get_quote(SwapType.ANCH_TO_BTC, anch_amount)
        logger.info(f"  [ProductionDEX] AMM quote: {anch_amount:,} ANCH -> {btc_amount:,} sats")

        if not self.oracle.check_price_integer(btc_amount, anch_amount):
            raise ValueError("[ProductionDEX] Oracle price check failed -- swap aborted")

        min_out = btc_amount * (10_000 - slippage_bps) // 10_000
        logger.info(f"  [ProductionDEX] min_amount_out={min_out:,} sats "
              f"(slippage tolerance: {slippage_bps/100:.2f}%)")

        secret = os.urandom(32)
        secret_hash = hashlib.sha256(secret).hexdigest()

        anch_transfer = self.anch_rgb.create_transfer(
            from_addr=user, to_addr=self.POOL_ADDRESS,
            amount=anch_amount, condition=f"OP_HASH256 {secret_hash} OP_EQUAL",
        )

        btc_htlc = self.htlc_engine.create_btc_lock(
            sender=self.POOL_ADDRESS, amount=btc_amount, hashlock=secret_hash,
            recipient=user, timelock=144,
        )

        swap_id = hashlib.sha256(
            (anch_transfer.transfer_id + btc_htlc.contract_id).encode()
        ).hexdigest()

        self._pending[swap_id] = {
            "direction": SwapType.ANCH_TO_BTC,
            "user": user,
            "btc_amount": btc_amount,
            "anch_amount": anch_amount,
            "min_out": min_out,
            "secret": secret,
            "htlc": btc_htlc,
            "rgb_transfer": anch_transfer,
            "created_at": time.time(),
        }
        logger.info(f"  [ProductionDEX] Swap {swap_id[:16]}... initiated. "
              f"Call complete_swap() to reveal secret and settle.")
        return swap_id, anch_transfer, btc_htlc

    def complete_swap(self, swap_id: str) -> bool:
        entry = self._pending.get(swap_id)
        if entry is None:
            logger.info(f"  [ProductionDEX] Unknown swap {swap_id[:16]}...")
            return False

        secret = entry["secret"]
        direction = entry["direction"]
        htlc = entry["htlc"]
        rgb = entry["rgb_transfer"]

        logger.info(f"\n  [ProductionDEX] Completing swap {swap_id[:16]}... "
              f"(revealing secret)")

        min_out = entry.get("min_out", 0)

        if direction == SwapType.BTC_TO_ANCH:
            if not self.htlc_engine.settle_htlc(htlc.contract_id, secret):
                logger.info("  [ProductionDEX] HTLC settlement failed")
                return False
            if not self.anch_rgb.settle_transfer(rgb.transfer_id, secret):
                logger.info("  [ProductionDEX] RGB settlement failed")
                return False
            ok = self.liquidity_pool.apply_swap(
                SwapType.BTC_TO_ANCH, entry["btc_amount"], entry["anch_amount"],
                min_amount_out=min_out,
            )
        else:
            if not self.htlc_engine.settle_htlc(htlc.contract_id, secret):
                logger.info("  [ProductionDEX] HTLC settlement failed")
                return False
            if not self.anch_rgb.settle_transfer(rgb.transfer_id, secret):
                logger.info("  [ProductionDEX] RGB settlement failed")
                return False
            ok = self.liquidity_pool.apply_swap(
                SwapType.ANCH_TO_BTC, entry["anch_amount"], entry["btc_amount"],
                min_amount_out=min_out,
            )

        if ok:
            del self._pending[swap_id]
            logger.info(f"  [ProductionDEX] Swap {swap_id[:16]}... complete")
        else:
            logger.info(f"  [ProductionDEX] BitVM pool update failed")
        return ok

    def cancel_swap(self, swap_id: str, current_block: int) -> bool:
        entry = self._pending.get(swap_id)
        if entry is None:
            return False
        htlc = entry["htlc"]
        rgb = entry["rgb_transfer"]

        btc_refunded = self.htlc_engine.refund_htlc(htlc.contract_id, current_block)
        anch_refunded = self.anch_rgb.refund_transfer(rgb.transfer_id)

        if btc_refunded and anch_refunded:
            del self._pending[swap_id]
            logger.info(f"  [ProductionDEX] Swap {swap_id[:16]}... cancelled and refunded.")
            return True
        elif btc_refunded or anch_refunded:
            leg_ok = "BTC" if btc_refunded else "ANCH"
            leg_fail = "ANCH" if btc_refunded else "BTC"
            logger.info(f"  [ProductionDEX] Partial cancel {swap_id[:16]}...: "
                  f"{leg_ok} refunded, {leg_fail} was already settled/refunded")
            del self._pending[swap_id]
            return True
        return False

    def cleanup_stale_swaps(self, current_block: int = 999_999) -> int:
        """
        Cancel and refund pending swaps older than PENDING_TTL_SECS.

        Returns the number of swaps cleaned up.
        """
        now = time.time()
        stale_ids = [
            sid for sid, entry in self._pending.items()
            if now - entry.get("created_at", 0) > self.PENDING_TTL_SECS
        ]
        cleaned = 0
        for sid in stale_ids:
            if self.cancel_swap(sid, current_block=current_block):
                cleaned += 1
                logger.info(f"  [ProductionDEX] Stale swap {sid[:16]}... auto-cancelled")
        return cleaned

    def get_balances(self, user: str) -> dict:
        return {
            "btc_sats": self.htlc_engine.btc_balance(user),
            "anch": self.anch_rgb.balance_of(user),
        }

    def get_pool_info(self) -> dict:
        s = self.liquidity_pool.state()
        return {
            "pool_address": self.POOL_ADDRESS,
            "btc_reserve": s.btc_reserve,
            "anch_reserve": s.anch_reserve,
            "lp_total": s.lp_total,
            "pending_swaps": len(self._pending),
        }
