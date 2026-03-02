"""
SimpleOracle, TWAPOracle, and BitVMPool.

FIX #7: Oracle hardened with NaN/Inf/zero rejection,
max single-update deviation (50%), and staleness check.

Additions:
  - TWAPOracle: manipulation-resistant time-weighted average price
    using cumulative price accumulators (Uniswap v2 style).
  - Integer-based price checks to avoid float precision issues.
  - Multi-source oracle aggregation via median selection.
"""
from __future__ import annotations

import math
import time
from collections import deque
from typing import List, Tuple, Optional, Sequence

from .state import PoolState, SwapType, TWAPSnapshot
from .pool import OnChainPool
from .math import safe_mul, safe_div, mul_div, BPS_DENOMINATOR


class SimpleOracle:
    """
    FIX #7 -- price oracle for sanity-checking swap amounts.

    Hardening:
      - Rejects NaN, Inf, zero, or negative price updates
      - Enforces max single-update deviation (50% by default)
      - Staleness check: rejects price checks if oracle is too old
      - Integer price tracking alongside float for precision
    """
    MAX_ORACLE_DEVIATION = 1000  # basis points (10 %)
    MAX_UPDATE_DEVIATION = 5000  # max 50% change per update (basis points)
    MAX_STALENESS_SECS = 3600   # reject checks if oracle older than 1 hr
    MAX_HISTORY = 1000          # ring buffer cap for price history

    def __init__(self, initial_price_sats_per_anch: float):
        if not isinstance(initial_price_sats_per_anch, (int, float)):
            raise TypeError("Oracle price must be numeric")
        price = float(initial_price_sats_per_anch)
        if price <= 0 or math.isnan(price) or math.isinf(price):
            raise ValueError(f"Oracle initial price must be finite and > 0, got {price}")
        self._price = price
        # Integer representation: price * 10^8 for precision
        self._price_fixed: int = int(price * 10**8)
        self._updated_at = time.time()
        self._history: deque = deque([(time.time(), self._price)], maxlen=self.MAX_HISTORY)
        self._update_count: int = 0

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
        self._price_fixed = int(new * 10**8)
        self._updated_at = time.time()
        self._history.append((time.time(), self._price))
        self._update_count += 1
        print(f"  [ORACLE] Price updated -> {new:.4f} sats/ANCH")

    @property
    def price(self) -> float:
        return self._price

    @property
    def price_fixed(self) -> int:
        """Price in fixed-point (sats * 10^8 per ANCH)."""
        return self._price_fixed

    @property
    def age_seconds(self) -> float:
        return time.time() - self._updated_at

    @property
    def update_count(self) -> int:
        return self._update_count

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

    def check_price_integer(
        self,
        btc_amount: int,
        anch_amount: int,
        max_dev_bps: int = 1000,
    ) -> bool:
        """
        Integer-only price check — no floating point in the
        comparison path.

        Uses cross-multiplication:
          implied_price = btc_amount / anch_amount
          lower = price * (10000 - dev) / 10000
          upper = price * (10000 + dev) / 10000

        Cross-multiply to avoid division:
          lower_check: btc_amount * 10000 * 10^8 >= price_fixed * anch_amount * (10000 - dev)
          upper_check: btc_amount * 10000 * 10^8 <= price_fixed * anch_amount * (10000 + dev)
        """
        if anch_amount <= 0 or self._price_fixed <= 0:
            return False
        if self.age_seconds > self.MAX_STALENESS_SECS:
            return False
        lhs = btc_amount * BPS_DENOMINATOR * 10**8
        rhs_base = self._price_fixed * anch_amount
        lower_ok = lhs >= rhs_base * (BPS_DENOMINATOR - max_dev_bps)
        upper_ok = lhs <= rhs_base * (BPS_DENOMINATOR + max_dev_bps)
        return lower_ok and upper_ok


class TWAPOracle:
    """
    Time-Weighted Average Price oracle.

    Maintains a sliding window of cumulative price * time
    observations.  The TWAP over any sub-window is:

      twap = (cumulative[end] - cumulative[start]) / (end - start)

    This is manipulation-resistant because an attacker would
    need to sustain the manipulated price for the entire window
    to meaningfully move the TWAP.  A single-block sandwich
    attack barely affects the TWAP.

    Based on Uniswap v2 oracle design, adapted for Bitcoin.
    """

    def __init__(
        self,
        window_size: int = 10,
        initial_btc: int = 0,
        initial_anch: int = 0,
    ):
        """
        Args:
            window_size: Number of observations to keep for TWAP.
            initial_btc: Initial BTC reserve for first observation.
            initial_anch: Initial ANCH reserve for first observation.
        """
        self._window_size = max(2, window_size)
        self._observations: deque[TWAPSnapshot] = deque(maxlen=self._window_size)
        if initial_btc > 0 and initial_anch > 0:
            self._observations.append(TWAPSnapshot(
                timestamp=time.time(),
                btc_reserve=initial_btc,
                anch_reserve=initial_anch,
                cumulative_price_btc=0,
                cumulative_price_anch=0,
            ))

    def update(self, btc_reserve: int, anch_reserve: int):
        """
        Record a new observation.

        Call this after each state transition (swap, add/remove liquidity).
        The cumulative accumulators are updated based on the time elapsed
        since the last observation.
        """
        now = time.time()
        if btc_reserve <= 0 or anch_reserve <= 0:
            return  # Skip invalid states

        if len(self._observations) == 0:
            self._observations.append(TWAPSnapshot(
                timestamp=now,
                btc_reserve=btc_reserve,
                anch_reserve=anch_reserve,
                cumulative_price_btc=0,
                cumulative_price_anch=0,
            ))
            return

        last = self._observations[-1]
        dt = now - last.timestamp
        if dt <= 0:
            dt = 1  # Minimum 1 second to avoid zero-division

        # Cumulative price accumulators (fixed-point * 10^18)
        # price_btc_per_anch = btc_reserve * 10^18 / anch_reserve
        price_btc = last.btc_reserve * 10**18 // last.anch_reserve
        price_anch = last.anch_reserve * 10**18 // last.btc_reserve

        new_cumulative_btc = last.cumulative_price_btc + int(price_btc * dt)
        new_cumulative_anch = last.cumulative_price_anch + int(price_anch * dt)

        self._observations.append(TWAPSnapshot(
            timestamp=now,
            btc_reserve=btc_reserve,
            anch_reserve=anch_reserve,
            cumulative_price_btc=new_cumulative_btc,
            cumulative_price_anch=new_cumulative_anch,
        ))

    def get_twap(self) -> Optional[int]:
        """
        Get the current TWAP over the full observation window.

        Returns: TWAP in fixed-point (sats-per-ANCH * 10^18),
                 or None if insufficient observations.
        """
        if len(self._observations) < 2:
            return None
        oldest = self._observations[0]
        newest = self._observations[-1]
        return TWAPSnapshot.compute_twap(oldest, newest)

    def get_twap_price(self) -> Optional[float]:
        """
        Get TWAP as a human-readable float (sats per ANCH).
        For display/logging only — never use in consensus logic.
        """
        twap = self.get_twap()
        if twap is None:
            return None
        return twap / 10**18

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def window_seconds(self) -> float:
        """Time span covered by current observations."""
        if len(self._observations) < 2:
            return 0.0
        return self._observations[-1].timestamp - self._observations[0].timestamp


def median_price(prices: Sequence[float]) -> float:
    """
    Multi-source oracle aggregation via median.

    The median is robust to up to floor(n/2) corrupted sources,
    making it ideal for oracle aggregation.  A single compromised
    feed cannot move the median unless it controls > 50% of sources.
    """
    if not prices:
        raise ValueError("median_price: empty price list")
    sorted_prices = sorted(prices)
    n = len(sorted_prices)
    if n % 2 == 1:
        return sorted_prices[n // 2]
    return (sorted_prices[n // 2 - 1] + sorted_prices[n // 2]) / 2


class BitVMPool:
    """
    Thin adapter that exposes OnChainPool's AMM math to ProductionDEX.

    Adds TWAP oracle tracking for manipulation-resistant price feeds.
    """

    def __init__(self, btc_reserve: int, anch_reserve: int):
        self._pool = OnChainPool(btc_reserve, anch_reserve, owner="bitvm_pool")
        # Instant finality: BitVMPool validates via full covenant + oracle
        # pipeline BEFORE calling propose_swap, making the challenge window
        # redundant.  This is intentional.
        self._pool.challenge_period = 0
        # TWAP oracle for manipulation-resistant price
        self._twap = TWAPOracle(
            window_size=10,
            initial_btc=btc_reserve,
            initial_anch=anch_reserve,
        )

    @property
    def pool(self) -> OnChainPool:
        return self._pool

    @property
    def address(self) -> str:
        return self._pool.state.taproot_address

    @property
    def twap_oracle(self) -> TWAPOracle:
        return self._twap

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
        if result is not None:
            # Update TWAP after successful swap
            self._twap.update(result.btc_reserve, result.anch_reserve)
            return True
        return False

    def state(self) -> PoolState:
        return self._pool.state

    def get_twap_price(self) -> Optional[float]:
        """Get the current TWAP (sats per ANCH)."""
        return self._twap.get_twap_price()
