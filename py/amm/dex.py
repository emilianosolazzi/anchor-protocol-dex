"""
FullyOnChainDEX -- wrapper integrating on-chain AMM with off-chain ledger.

All mutation methods are decorated with @non_reentrant.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from .math import non_reentrant
from .state import (
    PoolState, SwapType, LiquidityType, FraudProof,
)
from .covenant_amm import CovenantAMMScript
from .pool import OnChainPool


class FullyOnChainDEX:
    """
    Wrapper that integrates the on-chain AMM with off-chain LP ledger.
    """

    def __init__(self):
        self.pools: Dict[str, OnChainPool] = {}
        self.user_balances: Dict[str, int] = {}
        self.lp_balances: Dict[str, Dict[str, int]] = {}
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
        self, pool_id: str, btc_reserve: int, anch_reserve: int, owner: str
    ) -> OnChainPool:
        pool = OnChainPool(btc_reserve, anch_reserve, owner)
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
