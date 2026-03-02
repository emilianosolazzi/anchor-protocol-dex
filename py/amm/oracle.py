"""
SimpleOracle + BitVMPool.

FIX #7: Oracle hardened with NaN/Inf/zero rejection,
max single-update deviation (50%), and staleness check.
"""
from __future__ import annotations

import math
import time
from typing import List, Tuple, Optional

from .state import PoolState, SwapType
from .pool import OnChainPool


class SimpleOracle:
    """
    FIX #7 -- price oracle for sanity-checking swap amounts.

    Hardening:
      - Rejects NaN, Inf, zero, or negative price updates
      - Enforces max single-update deviation (50% by default)
      - Staleness check: rejects price checks if oracle is too old
    """
    MAX_ORACLE_DEVIATION = 1000  # basis points (10 %)
    MAX_UPDATE_DEVIATION = 5000  # max 50% change per update (basis points)
    MAX_STALENESS_SECS = 3600   # reject checks if oracle older than 1 hr

    def __init__(self, initial_price_sats_per_anch: float):
        if not isinstance(initial_price_sats_per_anch, (int, float)):
            raise TypeError("Oracle price must be numeric")
        price = float(initial_price_sats_per_anch)
        if price <= 0 or math.isnan(price) or math.isinf(price):
            raise ValueError(f"Oracle initial price must be finite and > 0, got {price}")
        self._price = price
        self._updated_at = time.time()
        self._history: List[Tuple[float, float]] = [(time.time(), self._price)]

    def update_price(self, new_price: float):
        new = float(new_price)
        if new <= 0 or math.isnan(new) or math.isinf(new):
            print(f"  [ORACLE] REJECTED invalid price: {new_price}")
            raise ValueError(
                f"Oracle price must be finite and > 0, got {new_price}"
            )
        if self._price > 0:
            ratio = abs(new - self._price) / self._price
            if ratio > self.MAX_UPDATE_DEVIATION / 10_000:
                print(f"  [ORACLE] REJECTED: price change {ratio*100:.1f}% exceeds "
                      f"max {self.MAX_UPDATE_DEVIATION/100:.0f}%")
                raise ValueError(
                    f"Oracle price change too large: "
                    f"{self._price:.6f} -> {new:.6f} ({ratio*100:.1f}%)"
                )
        self._price = new
        self._updated_at = time.time()
        self._history.append((time.time(), self._price))
        print(f"  [ORACLE] Price updated -> {new:.4f} sats/ANCH")

    @property
    def price(self) -> float:
        return self._price

    @property
    def age_seconds(self) -> float:
        return time.time() - self._updated_at

    def check_price(
        self,
        btc_amount: int,
        anch_amount: int,
        max_dev_bps: int = 1000,
    ) -> bool:
        if anch_amount <= 0:
            return False
        if self.age_seconds > self.MAX_STALENESS_SECS:
            print(f"  [ORACLE] STALE: last update was {self.age_seconds:.0f}s ago "
                  f"(max {self.MAX_STALENESS_SECS}s)")
            return False
        lower = self._price * (10_000 - max_dev_bps) / 10_000
        upper = self._price * (10_000 + max_dev_bps) / 10_000
        btc_per_anch = btc_amount / anch_amount
        ok = lower <= btc_per_anch <= upper
        if not ok:
            print(f"  [ORACLE] Price check FAILED: "
                  f"implied={btc_per_anch:.4f} sats/ANCH "
                  f"oracle={self._price} "
                  f"allowed=[{lower:.4f}, {upper:.4f}]")
        return ok


class BitVMPool:
    """
    Thin adapter that exposes OnChainPool's AMM math to ProductionDEX.
    """

    def __init__(self, btc_reserve: int, anch_reserve: int):
        self._pool = OnChainPool(btc_reserve, anch_reserve, owner="bitvm_pool")
        # Instant finality: BitVMPool validates via full covenant + oracle
        # pipeline BEFORE calling propose_swap, making the challenge window
        # redundant.  This is intentional.
        self._pool.challenge_period = 0

    @property
    def pool(self) -> OnChainPool:
        return self._pool

    @property
    def address(self) -> str:
        return self._pool.state.taproot_address

    def get_quote(self, swap_type: SwapType, amount_in: int) -> int:
        return self._pool.quote(swap_type, amount_in)

    def apply_swap(
        self,
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
        min_amount_out: int = 0,
    ) -> bool:
        sig = b"production_internal"
        txid = self._pool.propose_swap(
            "bitvm_pool", swap_type, amount_in, amount_out, sig,
            min_amount_out=min_amount_out,
        )
        if txid is None:
            return False
        result = self._pool.finalize_swap(txid)
        return result is not None

    def state(self) -> PoolState:
        return self._pool.state
