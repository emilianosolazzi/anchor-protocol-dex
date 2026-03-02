"""
FullyOnChainDEX -- wrapper integrating on-chain AMM with off-chain ledger.

All mutation methods are decorated with @non_reentrant.

Improvements:
  - Pool enumeration (list_pools, get_pool_info)
  - Spot price and TWAP queries
  - Protocol fee collection accounting
  - Per-pool fee accumulator access
  - Accepts PoolConfig for per-pool configuration
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .math import non_reentrant
from .state import (
    PoolState, SwapType, LiquidityType, FraudProof,
    PoolConfig, FeeAccumulator,
)
from .covenant_amm import CovenantAMMScript
from .pool import OnChainPool


class FullyOnChainDEX:
    """
    Wrapper that integrates the on-chain AMM with off-chain LP ledger.

    Provides:
      - Pool lifecycle (create, enumerate, query)
      - Swap execution with reentrancy protection
      - Liquidity add/remove with LP token accounting
      - Challenge / finalize flow
      - Protocol fee collection and distribution accounting
      - Spot price and TWAP queries
    """

    def __init__(self):
        self.pools: Dict[str, OnChainPool] = {}
        self.user_balances: Dict[str, int] = {}
        self.lp_balances: Dict[str, Dict[str, int]] = {}
        self._protocol_fees_btc: int = 0
        self._protocol_fees_anch: int = 0
        self._non_reentrant_lock = threading.Lock()

    def _mint_lp(self, pool_id: str, user: str, amount: int):
        if amount <= 0:
            return
        if pool_id not in self.lp_balances:
            self.lp_balances[pool_id] = {}
        pool_ledger = self.lp_balances[pool_id]
        pool_ledger[user] = pool_ledger.get(user, 0) + amount

    def _burn_lp(self, pool_id: str, user: str, amount: int):
        if amount <= 0:
            return
        if pool_id not in self.lp_balances:
            raise ValueError("Insufficient LP balance")
        pool_ledger = self.lp_balances[pool_id]
        current = pool_ledger.get(user, 0)
        if current < amount:
            raise ValueError("Insufficient LP balance")
        pool_ledger[user] = current - amount

    def lp_balance_of(self, pool_id: str, user: str) -> int:
        return self.lp_balances.get(pool_id, {}).get(user, 0)

    def create_pool(
        self, pool_id: str, btc_reserve: int, anch_reserve: int, owner: str,
        config: Optional[PoolConfig] = None,
    ) -> OnChainPool:
        pool = OnChainPool(btc_reserve, anch_reserve, owner, config=config)
        self.pools[pool_id] = pool
        print(f"  Pool '{pool_id}' created at {pool.state.taproot_address}")
        return pool

    @non_reentrant
    def swap(
        self,
        pool_id: str,
        user: str,
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
        signature: bytes,
        min_amount_out: int = 0,
    ) -> Optional[str]:
        pool = self._get_pool(pool_id)
        txid = pool.propose_swap(
            user, swap_type, amount_in, amount_out, signature,
            min_amount_out=min_amount_out,
        )
        if txid:
            print(f"  User '{user}' proposed {swap_type.name} swap -> txid {txid[:16]}...")
        return txid

    @non_reentrant
    def add_liquidity(
        self,
        pool_id: str,
        user: str,
        btc_amount: int,
        anch_amount: int,
        signature: bytes,
    ) -> Optional[str]:
        pool = self._get_pool(pool_id)
        txid = pool.propose_liquidity_change(
            user, LiquidityType.ADD, btc_amount, anch_amount, signature
        )
        return txid

    @non_reentrant
    def remove_liquidity(
        self,
        pool_id: str,
        user: str,
        lp_to_burn: int,
        signature: bytes,
    ) -> Optional[str]:
        if self.lp_balance_of(pool_id, user) < lp_to_burn:
            print("  REMOVE_LIQUIDITY: insufficient LP balance")
            return None
        pool = self._get_pool(pool_id)
        txid = pool.propose_liquidity_change(
            user, LiquidityType.REMOVE, lp_to_burn, 0, signature
        )
        return txid

    @non_reentrant
    def challenge_liquidity(
        self, pool_id: str, txid: str, challenger: str
    ) -> bool:
        pool = self._get_pool(pool_id)
        return pool.challenge_liquidity(txid, challenger)

    @non_reentrant
    def finalize_liquidity(self, pool_id: str, txid: str) -> Optional[PoolState]:
        pool = self._get_pool(pool_id)
        pending = pool.pending_liquidity.get(txid)
        new_state = pool.finalize_liquidity(txid)
        if new_state is not None and pending is not None:
            if pending.lp_delta > 0:
                self._mint_lp(pool_id, pending.user, pending.lp_delta)
            elif pending.lp_delta < 0:
                self._burn_lp(pool_id, pending.user, -pending.lp_delta)
        return new_state

    @non_reentrant
    def challenge(
        self, pool_id: str, txid: str, challenger: str
    ) -> bool:
        pool = self._get_pool(pool_id)
        pending = pool.pending_swaps.get(txid)
        if pending is None:
            print("  Invalid txid or swap already resolved")
            return False
        fp = FraudProof(pending.old_state, txid, b'simulated_fraud_proof', challenger=challenger)
        return pool.challenge_swap(txid, challenger, fp)

    @non_reentrant
    def finalize(self, pool_id: str, txid: str) -> Optional[PoolState]:
        pool = self._get_pool(pool_id)
        return pool.finalize_swap(txid)

    def _get_pool(self, pool_id: str) -> OnChainPool:
        if pool_id not in self.pools:
            raise ValueError(f"Pool '{pool_id}' not found")
        return self.pools[pool_id]

    # ------------------------------------------------------------------
    # Pool enumeration & queries
    # ------------------------------------------------------------------
    def list_pools(self) -> List[str]:
        """Return all pool IDs."""
        return list(self.pools.keys())

    def get_pool_info(self, pool_id: str) -> dict:
        """Get detailed info for a specific pool."""
        return self._get_pool(pool_id).get_info()

    def get_all_pools_info(self) -> Dict[str, dict]:
        """Get info for all pools."""
        return {pid: pool.get_info() for pid, pool in self.pools.items()}

    def spot_price(self, pool_id: str) -> Optional[int]:
        """
        Current spot price in fixed-point (sats-per-ANCH * 10^8).
        Returns None if pool has zero reserves.
        """
        return self._get_pool(pool_id).spot_price()

    def get_twap(self, pool_id: str) -> Optional[int]:
        """
        Get TWAP over the pool's observation window.
        Returns fixed-point * 10^18, or None if insufficient data.
        """
        return self._get_pool(pool_id).get_twap()

    def quote(self, pool_id: str, swap_type: SwapType, amount_in: int) -> int:
        """Quote an output amount for a given input."""
        return self._get_pool(pool_id).quote(swap_type, amount_in)

    # ------------------------------------------------------------------
    # Fee accounting
    # ------------------------------------------------------------------
    def get_pool_fees(self, pool_id: str) -> FeeAccumulator:
        """Get per-pool cumulative fee data."""
        return self._get_pool(pool_id).fee_accumulator

    @property
    def protocol_fees_btc(self) -> int:
        """Total protocol BTC fees collected across all pools."""
        return sum(p.fee_accumulator.protocol_btc_fees for p in self.pools.values())

    @property
    def protocol_fees_anch(self) -> int:
        """Total protocol ANCH fees collected across all pools."""
        return sum(p.fee_accumulator.protocol_anch_fees for p in self.pools.values())

    @property
    def total_swap_count(self) -> int:
        """Total number of swaps across all pools."""
        return sum(p.fee_accumulator.swap_count for p in self.pools.values())

    @property
    def total_value_locked(self) -> Dict[str, int]:
        """Aggregate TVL across all pools."""
        tvl_btc = sum(p.state.btc_reserve for p in self.pools.values())
        tvl_anch = sum(p.state.anch_reserve for p in self.pools.values())
        return {"btc": tvl_btc, "anch": tvl_anch}

    def summary(self) -> dict:
        """High-level DEX summary."""
        return {
            "pool_count": len(self.pools),
            "total_value_locked": self.total_value_locked,
            "protocol_fees_btc": self.protocol_fees_btc,
            "protocol_fees_anch": self.protocol_fees_anch,
            "total_swaps": self.total_swap_count,
        }
