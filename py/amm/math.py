"""
Safe arithmetic helpers for on-chain AMM verification.

All helpers operate on unsigned 64-bit integers (u64), matching
Bitcoin's nValue range (int64 for amounts, but reserves are always
non-negative so we treat them as u64 for overflow checking).

FIX #2: overflow guards using U64_MAX boundary checks.
Added: isqrt (integer square root), safe_div, safe_add, safe_sub,
       bps helpers, geometric mean, non_reentrant decorator.
"""
from __future__ import annotations

import functools
import threading

_U64_MAX = (1 << 64) - 1

# Basis point constants
BPS_DENOMINATOR = 10_000  # 1 basis point = 0.01%


# ---------------------------------------------------------------------------
# Core safe arithmetic
# ---------------------------------------------------------------------------

def safe_mul(a: int, b: int, label: str = "") -> int:
    """
    Multiply two u64 values with overflow detection.
    Raises ArithmeticError if either operand is negative or the
    product exceeds 2^64 - 1.
    """
    if a < 0 or b < 0:
        raise ArithmeticError(
            f"safe_mul({label}): negative operand a={a} b={b}"
        )
    result = a * b
    if result > _U64_MAX:
        raise ArithmeticError(
            f"safe_mul({label}): overflow {a} * {b} = {result} > U64_MAX"
        )
    return result


def safe_add(a: int, b: int, label: str = "") -> int:
    """Add two u64 values with overflow detection."""
    if a < 0 or b < 0:
        raise ArithmeticError(
            f"safe_add({label}): negative operand a={a} b={b}"
        )
    result = a + b
    if result > _U64_MAX:
        raise ArithmeticError(
            f"safe_add({label}): overflow {a} + {b} = {result} > U64_MAX"
        )
    return result


def safe_sub(a: int, b: int, label: str = "") -> int:
    """
    Subtract b from a with underflow detection.
    Returns a - b; raises if result would be negative.
    """
    if a < 0 or b < 0:
        raise ArithmeticError(
            f"safe_sub({label}): negative operand a={a} b={b}"
        )
    if b > a:
        raise ArithmeticError(
            f"safe_sub({label}): underflow {a} - {b} < 0"
        )
    return a - b


def safe_div(a: int, b: int, label: str = "", round_up: bool = False) -> int:
    """
    Divide a by b with zero-denominator protection.

    round_up=True uses ceiling division: (a + b - 1) // b
    This is critical for fee calculations where the protocol
    should never under-charge.
    """
    if b == 0:
        raise ArithmeticError(
            f"safe_div({label}): division by zero (a={a})"
        )
    if a < 0 or b < 0:
        raise ArithmeticError(
            f"safe_div({label}): negative operand a={a} b={b}"
        )
    if round_up:
        return (a + b - 1) // b
    return a // b


def safe_product(*args: int, label: str = "") -> int:
    """Chain-multiply an arbitrary number of u64 values safely."""
    result = 1
    for i, v in enumerate(args):
        result = safe_mul(result, v, f"{label}[{i}]")
    return result


# ---------------------------------------------------------------------------
# Integer square root (replaces float math.sqrt for LP mint)
# ---------------------------------------------------------------------------

def isqrt(n: int) -> int:
    """
    Integer square root using Newton's method.

    Returns floor(sqrt(n)) exactly, without floating-point error.
    This is critical for initial LP mint where math.sqrt can lose
    precision for large values (>2^53).

    Used by compute_lp_mint when old_lp == 0:
      lp_minted = isqrt(btc_added * anch_added)
    """
    if n < 0:
        raise ValueError(f"isqrt: negative input {n}")
    if n == 0:
        return 0
    # Initial guess using bit length
    x = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        y = (x + n // x) >> 1
        if y >= x:
            return x
        x = y


def geometric_mean(a: int, b: int) -> int:
    """
    Integer geometric mean: floor(sqrt(a * b)).

    Used for initial LP token computation (Uniswap v2 style).
    Overflow-safe: Python ints are arbitrary precision, so a*b
    never overflows; isqrt provides exact integer result.
    """
    if a < 0 or b < 0:
        raise ValueError(f"geometric_mean: negative input a={a} b={b}")
    return isqrt(a * b)


# ---------------------------------------------------------------------------
# Basis point arithmetic
# ---------------------------------------------------------------------------

def bps_mul(value: int, bps: int) -> int:
    """
    Multiply value by a basis-point fraction: value * bps / 10_000.

    Examples:
      bps_mul(1_000_000, 30)  ->  3_000    (0.3% of 1M)
      bps_mul(1_000_000, 300) -> 30_000    (3.0% of 1M)
    """
    return safe_mul(value, bps, "bps_mul") // BPS_DENOMINATOR


def bps_complement(value: int, bps: int) -> int:
    """
    Multiply value by (1 - bps/10_000): the amount remaining
    after deducting a basis-point fee.

    Example:
      bps_complement(1_000_000, 30) -> 997_000  (after 0.3% fee)
    """
    return safe_mul(value, BPS_DENOMINATOR - bps, "bps_complement") // BPS_DENOMINATOR


def mul_div(a: int, b: int, c: int, label: str = "") -> int:
    """
    Compute a * b / c without intermediate overflow in Python
    (Python ints are arbitrary precision) but with zero-div guard.

    In a real Bitcoin script context, this would need 128-bit
    intermediate arithmetic or a OP_CAT-based decomposition.
    """
    if c == 0:
        raise ArithmeticError(
            f"mul_div({label}): division by zero"
        )
    return (a * b) // c


def mul_div_round_up(a: int, b: int, c: int, label: str = "") -> int:
    """mul_div with ceiling rounding (for protocol fee collection)."""
    if c == 0:
        raise ArithmeticError(
            f"mul_div_round_up({label}): division by zero"
        )
    return (a * b + c - 1) // c


# ---------------------------------------------------------------------------
# Non-reentrant decorator
# ---------------------------------------------------------------------------

def non_reentrant(func):
    """
    Decorator that prevents re-entrant calls on the same object.
    The decorated method's *self* must expose (or will get) a
    ``_non_reentrant_lock`` attribute (a ``threading.Lock``).

    This simulates Bitcoin's UTXO model where a coin can only
    be spent once per block — re-entrancy is impossible because
    the input is consumed.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        lock = getattr(self, '_non_reentrant_lock', None)
        if lock is None:
            self._non_reentrant_lock = threading.Lock()
            lock = self._non_reentrant_lock
        if not lock.acquire(blocking=False):
            raise RuntimeError(f"{func.__name__}: re-entrant call blocked")
        try:
            return func(self, *args, **kwargs)
        finally:
            lock.release()
    return wrapper
