"""
CovenantAMMScript -- the core AMM math engine.

Verifies swaps, state transitions, liquidity operations, and
computes outputs using the constant-product (xy=k) formula.

Security hardening:
  FIX #1: sequence-based replay protection
  FIX #2: safe_mul overflow guards
  FIX #3: min_amount_out slippage protection
  FIX #7: price impact guard (max 3%)
"""
from __future__ import annotations

import struct
from typing import List

from .math import safe_mul, safe_product, _U64_MAX
from .state import PoolState, SwapType, StateCommitment


class CovenantAMMScript:
    """
    On-chain AMM verification logic.
    All methods are static -- they represent script-level checks
    that would run inside a Taproot leaf.
    """

    FEE_BASIS = 3               # 0.3% swap fee
    LIQ_FEE_BASIS = 1           # 0.1% liquidity fee
    MAX_PRICE_IMPACT = 300      # 3% max price impact (basis points)

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
        """FIX #7: reject if price impact exceeds MAX_PRICE_IMPACT bps."""
        if old_btc <= 0 or old_anch <= 0:
            return False
        old_price = old_btc / old_anch
        new_price = new_btc / new_anch if new_anch > 0 else float('inf')
        if old_price == 0:
            return False
        impact_bps = abs(new_price - old_price) / old_price * 10_000
        if impact_bps > cls.MAX_PRICE_IMPACT:
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
    ) -> bool:
        """
        Verify a BTC -> ANCH swap.
        Checks: amounts positive, fee deducted, k non-decreasing,
        reserves consistent, slippage guard, price impact.
        """
        if btc_in <= 0 or anch_out <= 0:
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
        fee_adjusted_in = btc_in * (1000 - cls.FEE_BASIS)
        expected_out = safe_mul(fee_adjusted_in, old_anch, "swap_num") // (
            old_btc * 1000 + fee_adjusted_in
        )
        if anch_out > expected_out:
            return False
        old_k = cls._safe_k(old_btc, old_anch)
        new_k = cls._safe_k(new_btc, new_anch)
        return new_k >= old_k

    @classmethod
    def verify_swap_anch_to_btc(
        cls,
        old_btc: int, old_anch: int,
        new_btc: int, new_anch: int,
        anch_in: int, btc_out: int,
        min_amount_out: int = 0,
    ) -> bool:
        """Verify an ANCH -> BTC swap (symmetric to verify_swap)."""
        if anch_in <= 0 or btc_out <= 0:
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
        fee_adjusted_in = anch_in * (1000 - cls.FEE_BASIS)
        expected_out = safe_mul(fee_adjusted_in, old_btc, "swap_num") // (
            old_anch * 1000 + fee_adjusted_in
        )
        if btc_out > expected_out:
            return False
        old_k = cls._safe_k(old_btc, old_anch)
        new_k = cls._safe_k(new_btc, new_anch)
        return new_k >= old_k

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
        if old_lp > 0:
            ratio_btc = new_btc * old_lp
            ratio_anch = new_anch * old_lp
            if abs(ratio_btc * old_anch - ratio_anch * old_btc) > (
                old_btc * old_anch
            ):
                print("  [AMM] Skewed add-liquidity rejected")
                return False
        return True

    @classmethod
    def verify_remove_liquidity(
        cls,
        old_btc: int, old_anch: int, old_lp: int,
        new_btc: int, new_anch: int, new_lp: int,
        btc_removed: int, anch_removed: int, lp_burned: int,
    ) -> bool:
        """Verify a remove-liquidity operation."""
        if btc_removed <= 0 or anch_removed <= 0 or lp_burned <= 0:
            return False
        if new_btc != old_btc - btc_removed:
            return False
        if new_anch != old_anch - anch_removed:
            return False
        if new_lp != old_lp - lp_burned:
            return False
        return True

    @staticmethod
    def compute_lp_mint(
        btc_added: int,
        anch_added: int,
        old_btc: int,
        old_anch: int,
        old_lp: int,
    ) -> int:
        """Compute LP tokens to mint for a given deposit."""
        if old_lp == 0:
            import math
            return int(math.sqrt(btc_added * anch_added))
        return min(
            btc_added * old_lp // old_btc,
            anch_added * old_lp // old_anch,
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
        return btc_out, anch_out

    @staticmethod
    def get_amount_out(amount_in: int, reserve_in: int, reserve_out: int,
                       fee_basis: int = 3) -> int:
        """
        Classic xy=k output formula with fee deducted from input.
        HARDENED: fee_basis clamped to [0, 999], overflow-safe.
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

    @staticmethod
    def execute_covenant(
        prev_state: PoolState,
        new_state: PoolState,
        witness_stack: list,
        prev_seq: int = 0,
    ) -> bool:
        """
        Simulate execution of the Taproot leaf script.
        Verifies sequence, state transition, and swap validity.
        """
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
