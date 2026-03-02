"""
Safe arithmetic helpers and the non_reentrant decorator.

FIX #2: overflow guards using U64_MAX boundary checks.
"""
from __future__ import annotations

import functools
import threading

_U64_MAX = (1 << 64) - 1


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


def safe_product(*args: int, label: str = "") -> int:
    """Chain-multiply an arbitrary number of u64 values safely."""
    result = 1
    for i, v in enumerate(args):
        result = safe_mul(result, v, f"{label}[{i}]")
    return result


def non_reentrant(func):
    """
    Decorator that prevents re-entrant calls on the same object.
    The decorated method's *self* must expose (or will get) a
    ``_non_reentrant_lock`` attribute (a ``threading.Lock``).
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
