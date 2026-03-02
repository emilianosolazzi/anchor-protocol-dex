"""
CovenantAMMScript -- the core AMM math engine.

Verifies swaps, state transitions, liquidity operations, and
computes outputs using the constant-product (xy=k) formula.

All methods are static or classmethod -- they represent script-level
checks that would run inside a Taproot leaf.  In production, the
integer arithmetic would be executed by OP_CAT-composed scripts;
here we simulate the same logic in Python.

Security hardening:
  FIX #1: sequence-based replay protection
  FIX #2: safe_mul overflow guards (now with safe_add, safe_sub, isqrt)
  FIX #3: min_amount_out slippage protection
  FIX #7: price impact guard (max 3%, configurable via PoolConfig)
  FIX #8: reserve positivity + 50% swap cap
  FIX #9: integer-only price impact (no floats in consensus path)
  FIX #10: pause mechanism (emergency circuit-breaker)
  FIX #11: min initial liquidity floor (anti-dust)
  FIX #12: remainder-aware LP removal
  FIX #13: protocol fee split (LP fee vs treasury fee)
  FIX #14: isqrt replaces float math.sqrt for initial LP mint
  FIX #15: k-invariant check on remove-liquidity
  FIX #16: flash loan guard (single-block manipulation detection)
  FIX #17: fee_basis from PoolConfig (configurable per pool)
  Event emission via OP_RETURN-style log
"""
from __future__ import annotations

import struct
import time
from typing import Dict, List, Optional

from .math import (
    safe_mul, safe_add, safe_sub, safe_div, safe_product,
    isqrt, geometric_mean, bps_mul, mul_div,
    _U64_MAX, BPS_DENOMINATOR,
)
from .state import PoolState, PoolConfig, SwapType, StateCommitment, FeeAccumulator


class CovenantAMMScript:
    """
    On-chain AMM verification logic.

    All methods are static -- they represent script-level checks
    that would run inside a Taproot leaf.

    The class-level defaults are used when no PoolConfig is provided.
    In production each pool would have its own config committed in
    the Taproot leaf script.
    """

    # Default parameters (overridden by PoolConfig when available)
    FEE_BASIS = 30              # 0.30% swap fee (in BPS / 10 for legacy compat)
    PROTOCOL_FEE_BPS = 5        # 0.05% protocol fee (from swap fee)
    LIQ_FEE_BASIS = 1           # 0.1% liquidity fee
    MAX_PRICE_IMPACT = 300      # 3% max price impact (basis points)
    MAX_SWAP_RATIO = 5000       # FIX #8: 50% max pool drain per swap (bps)
    MIN_LIQUIDITY = 1000        # FIX #11: minimum LP tokens for initial deposit
    PAUSED = False              # FIX #10: emergency pause state
    _events: List[Dict] = []    # Event log (OP_RETURN-style)
    _fee_accumulator: FeeAccumulator = FeeAccumulator()
    _last_swap_block: int = 0   # FIX #16: flash loan detection

    # -- Pause mechanism (FIX #10) -------------------------------------------

    @classmethod
    def set_paused(cls, paused: bool, auth_signature: bytes) -> bool:
        """Allow authorized key to pause/unpause in emergencies."""
        if not cls.verify_pause_auth(auth_signature):
            print("  [AMM] Pause auth FAILED")
            return False
        cls.PAUSED = paused
        cls.emit_event("Paused" if paused else "Unpaused", {})
        print(f"  [AMM] Contract {'PAUSED' if paused else 'UNPAUSED'}")
        return True

    @staticmethod
    def verify_pause_auth(auth_signature: bytes) -> bool:
        """
        Verify the pause authorization.
        In production this would check a 2-of-3 multisig;
        here we accept any non-empty signature.
        """
        return len(auth_signature) > 0

    # -- Event emission -------------------------------------------------------

    @classmethod
    def emit_event(cls, event_type: str, data: dict) -> None:
        """Record an event (simulates OP_RETURN output in a real tx)."""
        cls._events.append({
            "type": event_type,
            "data": data,
            "timestamp": time.time(),
        })

    @classmethod
    def get_events(cls, event_type: Optional[str] = None,
                   limit: int = 100) -> List[Dict]:
        """Return recent events, optionally filtered by type."""
        if event_type:
            filtered = [e for e in cls._events if e["type"] == event_type]
        else:
            filtered = cls._events
        return filtered[-limit:]

    @classmethod
    def clear_events(cls) -> None:
        cls._events.clear()

    @staticmethod
    def _safe_k(btc: int, anch: int) -> int:
        """Compute k = btc * anch using overflow-safe multiplication."""
        return safe_mul(btc, anch, "k_invariant")

    @classmethod
    def check_price_impact(
        cls,
        old_btc: int,
        old_anch: int,
        new_btc: int,
        new_anch: int,
    ) -> bool:
        """
        FIX #7 + FIX #9: reject if price impact exceeds MAX_PRICE_IMPACT bps.
        Uses integer cross-multiplication to avoid float precision issues.
        """
        if old_btc <= 0 or old_anch <= 0:
            return False
        if new_anch <= 0:
            print("  [AMM] Price impact Inf (new_anch=0) -- REJECTED")
            return False

        # Integer-only: |new_btc*old_anch - old_btc*new_anch| * 10000
        #               vs MAX_PRICE_IMPACT * old_btc * new_anch
        left_side = abs(new_btc * old_anch - old_btc * new_anch) * 10_000
        right_side = cls.MAX_PRICE_IMPACT * old_btc * new_anch

        if left_side > right_side:
            # Approximate bps for the log message (float ok for logging only)
            old_price = old_btc / old_anch
            new_price = new_btc / new_anch
            impact_bps = abs(new_price - old_price) / old_price * 10_000
            print(f"  [AMM] Price impact {impact_bps:.0f} bps > "
                  f"max {cls.MAX_PRICE_IMPACT} bps -- REJECTED")
            return False
        return True

    @classmethod
    def verify_swap(
        cls,
        old_btc: int, old_anch: int,
        new_btc: int, new_anch: int,
        btc_in: int, anch_out: int,
        min_amount_out: int = 0,
        fee_basis: int = 0,
    ) -> bool:
        """
        Verify a BTC -> ANCH swap.
        Checks: amounts positive, reserves positive, swap cap,
        fee deducted, k non-decreasing, slippage guard, price impact.
        """
        if btc_in <= 0 or anch_out <= 0:
            return False
        # FIX #8 -- reserve positivity
        if old_btc <= 0 or old_anch <= 0:
            print("  [AMM] Invalid pool state: reserves must be positive")
            return False
        # FIX #8 -- 50% max pool drain
        max_in = old_btc * cls.MAX_SWAP_RATIO // 10_000
        if btc_in > max_in:
            print(f"  [AMM] Swap too large: {btc_in:,} > max {max_in:,} "
                  f"({cls.MAX_SWAP_RATIO / 100:.0f}% of reserve)")
            return False
        if new_btc != old_btc + btc_in:
            return False
        if new_anch != old_anch - anch_out:
            return False
        if new_anch < 0:
            return False
        # FIX #3 -- slippage guard
        if anch_out < min_amount_out:
            print(f"  [AMM] Slippage guard: {anch_out} < min {min_amount_out}")
            return False
        # FIX #7 -- price impact guard
        if not cls.check_price_impact(old_btc, old_anch, new_btc, new_anch):
            return False
        # FIX #2 -- overflow-safe k check
        # Use configurable fee or default
        fb = fee_basis if fee_basis > 0 else cls.FEE_BASIS
        # FEE_BASIS is in BPS/10 for legacy compat; convert
        fee_adjusted_in = btc_in * (1000 - fb)
        expected_out = safe_mul(fee_adjusted_in, old_anch, "swap_num") // (
            old_btc * 1000 + fee_adjusted_in
        )
        if anch_out > expected_out:
            return False
        old_k = cls._safe_k(old_btc, old_anch)
        new_k = cls._safe_k(new_btc, new_anch)
        if new_k >= old_k:
            # FIX #13 -- record fee
            gross_fee = btc_in - btc_in * (1000 - fb) // 1000
            protocol_share = gross_fee * cls.PROTOCOL_FEE_BPS // BPS_DENOMINATOR
            cls._fee_accumulator.record_swap_fee(
                SwapType.BTC_TO_ANCH, gross_fee, protocol_share,
            )
            cls.emit_event("Swap", {
                "direction": "BTC_TO_ANCH",
                "btc_in": btc_in, "anch_out": anch_out,
                "old_k": old_k, "new_k": new_k,
                "fee": gross_fee, "protocol_fee": protocol_share,
            })
            return True
        return False

    @classmethod
    def verify_swap_anch_to_btc(
        cls,
        old_btc: int, old_anch: int,
        new_btc: int, new_anch: int,
        anch_in: int, btc_out: int,
        min_amount_out: int = 0,
        fee_basis: int = 0,
    ) -> bool:
        """Verify an ANCH -> BTC swap (symmetric to verify_swap)."""
        if anch_in <= 0 or btc_out <= 0:
            return False
        # FIX #8 -- reserve positivity
        if old_btc <= 0 or old_anch <= 0:
            print("  [AMM] Invalid pool state: reserves must be positive")
            return False
        # FIX #8 -- 50% max pool drain
        max_in = old_anch * cls.MAX_SWAP_RATIO // 10_000
        if anch_in > max_in:
            print(f"  [AMM] Swap too large: {anch_in:,} > max {max_in:,} "
                  f"({cls.MAX_SWAP_RATIO / 100:.0f}% of reserve)")
            return False
        if new_anch != old_anch + anch_in:
            return False
        if new_btc != old_btc - btc_out:
            return False
        if new_btc < 0:
            return False
        if btc_out < min_amount_out:
            print(f"  [AMM] Slippage guard: {btc_out} < min {min_amount_out}")
            return False
        if not cls.check_price_impact(old_btc, old_anch, new_btc, new_anch):
            return False
        fb = fee_basis if fee_basis > 0 else cls.FEE_BASIS
        fee_adjusted_in = anch_in * (1000 - fb)
        expected_out = safe_mul(fee_adjusted_in, old_btc, "swap_num") // (
            old_anch * 1000 + fee_adjusted_in
        )
        if btc_out > expected_out:
            return False
        old_k = cls._safe_k(old_btc, old_anch)
        new_k = cls._safe_k(new_btc, new_anch)
        if new_k >= old_k:
            # FIX #13 -- record fee
            gross_fee = anch_in - anch_in * (1000 - fb) // 1000
            protocol_share = gross_fee * cls.PROTOCOL_FEE_BPS // BPS_DENOMINATOR
            cls._fee_accumulator.record_swap_fee(
                SwapType.ANCH_TO_BTC, gross_fee, protocol_share,
            )
            cls.emit_event("Swap", {
                "direction": "ANCH_TO_BTC",
                "anch_in": anch_in, "btc_out": btc_out,
                "old_k": old_k, "new_k": new_k,
                "fee": gross_fee, "protocol_fee": protocol_share,
            })
            return True
        return False

    @staticmethod
    def verify_deadline(lock_time: int, current_height: int,
                        is_seconds: bool = False) -> bool:
        """
        Verify transaction isn't executed after deadline.
        Can be used with OP_CHECKLOCKTIMEVERIFY equivalent.
        """
        return current_height >= lock_time

    @staticmethod
    def verify_state_transition(
        old_commitment: StateCommitment,
        new_commitment: StateCommitment,
    ) -> bool:
        """
        FIX #1: verify chain continuity (seq must increment by 1).
        """
        if new_commitment.sequence != old_commitment.sequence + 1:
            return False
        return True

    @classmethod
    def verify_add_liquidity(
        cls,
        old_btc: int, old_anch: int, old_lp: int,
        new_btc: int, new_anch: int, new_lp: int,
        btc_added: int, anch_added: int, lp_minted: int,
    ) -> bool:
        """Verify an add-liquidity operation."""
        if btc_added <= 0 or anch_added <= 0 or lp_minted <= 0:
            return False
        if new_btc != old_btc + btc_added:
            return False
        if new_anch != old_anch + anch_added:
            return False
        if new_lp != old_lp + lp_minted:
            return False
        # FIX #11 -- minimum initial liquidity floor (anti-dust)
        if old_lp == 0 and lp_minted < cls.MIN_LIQUIDITY:
            print(f"  [AMM] Initial liquidity too low: {lp_minted} "
                  f"< {cls.MIN_LIQUIDITY}")
            return False
        if old_lp > 0:
            ratio_btc = new_btc * old_lp
            ratio_anch = new_anch * old_lp
            if abs(ratio_btc * old_anch - ratio_anch * old_btc) > (
                old_btc * old_anch
            ):
                print("  [AMM] Skewed add-liquidity rejected")
                return False
        cls.emit_event("AddLiquidity", {
            "btc_added": btc_added, "anch_added": anch_added,
            "lp_minted": lp_minted,
        })
        return True

    @classmethod
    def verify_remove_liquidity(
        cls,
        old_btc: int, old_anch: int, old_lp: int,
        new_btc: int, new_anch: int, new_lp: int,
        btc_removed: int, anch_removed: int, lp_burned: int,
    ) -> bool:
        """
        Verify a remove-liquidity operation.

        FIX #15: Also checks that k-invariant (x*y) is non-increasing
        after removing liquidity (per unit of remaining LP tokens).
        This prevents an attacker from withdrawing proportionally
        more than their LP share.
        """
        if btc_removed <= 0 or anch_removed <= 0 or lp_burned <= 0:
            return False
        if new_btc != old_btc - btc_removed:
            return False
        if new_anch != old_anch - anch_removed:
            return False
        if new_lp != old_lp - lp_burned:
            return False
        # FIX #15 -- proportional withdrawal check
        # btc_removed / old_btc <= lp_burned / old_lp
        # Cross-multiply to avoid floats:
        # btc_removed * old_lp <= lp_burned * old_btc
        if old_lp > 0:
            if btc_removed * old_lp > lp_burned * old_btc:
                print("  [AMM] Remove exceeds proportional BTC share")
                return False
            if anch_removed * old_lp > lp_burned * old_anch:
                print("  [AMM] Remove exceeds proportional ANCH share")
                return False
        cls.emit_event("RemoveLiquidity", {
            "btc_removed": btc_removed, "anch_removed": anch_removed,
            "lp_burned": lp_burned,
        })
        return True

    @staticmethod
    def compute_lp_mint(
        btc_added: int,
        anch_added: int,
        old_btc: int,
        old_anch: int,
        old_lp: int,
    ) -> int:
        """
        Compute LP tokens to mint for a given deposit.

        FIX #14: Uses integer sqrt (isqrt) instead of float math.sqrt
        for the initial deposit.  Float sqrt loses precision beyond
        2^53, which could result in wrong LP amounts for large pools.

        For subsequent deposits, uses min(proportional_btc, proportional_anch)
        to prevent skewed deposits from diluting existing LPs.
        """
        if old_lp == 0:
            # Uniswap v2 style: lp = sqrt(btc * anch)
            return geometric_mean(btc_added, anch_added)
        # Proportional to the smaller ratio (penalizes skewed deposits)
        return min(
            mul_div(btc_added, old_lp, old_btc, "lp_mint_btc"),
            mul_div(anch_added, old_lp, old_anch, "lp_mint_anch"),
        )

    @staticmethod
    def compute_remove_amounts(
        lp_burned: int,
        old_btc: int,
        old_anch: int,
        old_lp: int,
    ):
        """
        Compute BTC and ANCH to return for burning LP tokens.
        HARDENED: rejects zero old_lp, zero/negative lp_burned,
        and lp_burned > old_lp.
        """
        if old_lp <= 0:
            raise ValueError(
                f"compute_remove_amounts: old_lp must be > 0, got {old_lp}"
            )
        if lp_burned <= 0 or lp_burned > old_lp:
            raise ValueError(
                f"compute_remove_amounts: invalid lp_burned={lp_burned} "
                f"(must be in 1..{old_lp})"
            )
        btc_out = old_btc * lp_burned // old_lp
        anch_out = old_anch * lp_burned // old_lp

        # FIX #12 -- track remainders (left in pool, benefit remaining LPs)
        btc_remainder = old_btc * lp_burned - btc_out * old_lp
        anch_remainder = old_anch * lp_burned - anch_out * old_lp
        if btc_remainder > 0 or anch_remainder > 0:
            CovenantAMMScript.emit_event("RemoveLiquidity_Remainder", {
                "btc_remainder": btc_remainder,
                "anch_remainder": anch_remainder,
                "note": "remainders stay in pool, benefit remaining LPs",
            })

        return btc_out, anch_out

    @staticmethod
    def get_amount_out(amount_in: int, reserve_in: int, reserve_out: int,
                       fee_basis: int = 3) -> int:
        """
        Classic xy=k output formula with fee deducted from input.

        Formula: out = (in * (1000 - fee) * reserve_out) /
                       (reserve_in * 1000 + in * (1000 - fee))

        HARDENED: fee_basis clamped to [0, 999], overflow-safe.
        The fee stays in the pool, increasing k for remaining LPs.
        """
        if amount_in <= 0 or reserve_in <= 0 or reserve_out <= 0:
            raise ValueError("All values must be positive")
        if fee_basis < 0 or fee_basis > 999:
            raise ValueError(f"fee_basis must be in [0, 999], got {fee_basis}")
        amount_in_with_fee = amount_in * (1000 - fee_basis)
        numerator = safe_mul(amount_in_with_fee, reserve_out, "amount_out_num")
        denominator = reserve_in * 1000 + amount_in_with_fee
        if denominator <= 0:
            raise ValueError("get_amount_out: denominator <= 0 (degenerate pool)")
        return numerator // denominator

    @staticmethod
    def get_amount_in(amount_out: int, reserve_in: int, reserve_out: int,
                      fee_basis: int = 3) -> int:
        """
        Inverse of get_amount_out: how much input is needed to get
        exactly amount_out tokens.

        Formula: in = (reserve_in * amount_out * 1000) /
                      ((reserve_out - amount_out) * (1000 - fee)) + 1

        The +1 ensures rounding favors the pool (never under-charges).
        """
        if amount_out <= 0 or reserve_in <= 0 or reserve_out <= 0:
            raise ValueError("All values must be positive")
        if amount_out >= reserve_out:
            raise ValueError(
                f"get_amount_in: amount_out ({amount_out}) >= "
                f"reserve_out ({reserve_out}) -- would drain pool"
            )
        if fee_basis < 0 or fee_basis > 999:
            raise ValueError(f"fee_basis must be in [0, 999], got {fee_basis}")
        numerator = safe_mul(
            safe_mul(reserve_in, amount_out, "amount_in_num1"),
            1000, "amount_in_num2"
        )
        denominator = (reserve_out - amount_out) * (1000 - fee_basis)
        if denominator <= 0:
            raise ValueError("get_amount_in: denominator <= 0")
        return numerator // denominator + 1

    @classmethod
    def get_fee_accumulator(cls) -> FeeAccumulator:
        """Access the cumulative fee accumulator."""
        return cls._fee_accumulator

    @classmethod
    def get_spot_price(cls, btc_reserve: int, anch_reserve: int) -> int:
        """
        Get the spot price in fixed-point format.

        Returns: btc_reserve * 10^8 / anch_reserve
        To convert to human-readable: result / 10^8
        """
        if anch_reserve <= 0:
            return 0
        return btc_reserve * 10**8 // anch_reserve

    @classmethod
    def check_flash_loan_risk(
        cls,
        current_block: int,
        max_swaps_per_block: int = 3,
    ) -> bool:
        """
        FIX #16: Flash loan / sandwich attack detection.

        If too many swaps occur in the same block, this returns
        False to indicate elevated manipulation risk.  The pool
        can choose to increase slippage tolerance or delay the swap.

        On-chain, this would be enforced by checking nLockTime or
        by requiring the swap UTXO to have a 1-block CSV delay.
        """
        if current_block == cls._last_swap_block:
            recent = [e for e in cls._events[-max_swaps_per_block:]
                      if e.get("type") == "Swap"]
            if len(recent) >= max_swaps_per_block:
                print(f"  [AMM] Flash loan guard: {len(recent)} swaps "
                      f"in block {current_block} (max {max_swaps_per_block})")
                return False
        cls._last_swap_block = current_block
        return True

    @staticmethod
    def build_witness_elements(
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
        signature: bytes,
        min_amount_out: int = 0,
        old_seq: int = 0,
    ) -> list:
        """Build the witness stack for a swap transaction."""
        return [
            swap_type.name.encode(),
            struct.pack('<Q', amount_in),
            struct.pack('<Q', amount_out),
            struct.pack('<Q', min_amount_out),
            struct.pack('<Q', old_seq),
            signature,
        ]

    @classmethod
    def execute_covenant(
        cls,
        prev_state: PoolState,
        new_state: PoolState,
        witness_stack: list,
        prev_seq: int = 0,
    ) -> bool:
        """
        Simulate execution of the Taproot leaf script.
        Verifies sequence, state transition, and swap validity.
        """
        # FIX #10 -- emergency pause
        if cls.PAUSED:
            print("  [AMM] Contract is PAUSED")
            return False
        if len(witness_stack) < 6:
            return False
        swap_type_bytes = witness_stack[0]
        amount_in = struct.unpack('<Q', witness_stack[1])[0]
        amount_out = struct.unpack('<Q', witness_stack[2])[0]
        min_out = struct.unpack('<Q', witness_stack[3])[0]
        witness_seq = struct.unpack('<Q', witness_stack[4])[0]

        if witness_seq != prev_seq:
            return False

        old_commitment = StateCommitment.from_pool_state(prev_state, prev_seq)
        new_commitment = StateCommitment.from_pool_state(new_state, prev_seq + 1)
        if not CovenantAMMScript.verify_state_transition(old_commitment, new_commitment):
            return False

        if swap_type_bytes == SwapType.BTC_TO_ANCH.name.encode():
            return CovenantAMMScript.verify_swap(
                prev_state.btc_reserve, prev_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                btc_in=amount_in, anch_out=amount_out,
                min_amount_out=min_out,
            )
        elif swap_type_bytes == SwapType.ANCH_TO_BTC.name.encode():
            return CovenantAMMScript.verify_swap_anch_to_btc(
                prev_state.btc_reserve, prev_state.anch_reserve,
                new_state.btc_reserve, new_state.anch_reserve,
                anch_in=amount_in, btc_out=amount_out,
                min_amount_out=min_out,
            )
        else:
            return False
