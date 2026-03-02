# SECURITY — ANCHOR DEX

Seven security fixes plus adversarial hardening, all verified by the R-8
test battery in `demo.py`.

---

## FIX #1 — Oracle NaN / Zero / Negative / Inf Rejection

**File:** `amm/oracle.py` — `SimpleOracle.update_price()`

```python
if math.isnan(new_price) or math.isinf(new_price) or new_price <= 0:
    raise ValueError(f"Invalid price: {new_price}")
```

An attacker could inject `NaN`, `Inf`, `0`, or negative prices to break
the AMM invariant.  Every call to `update_price()` now validates the input
before accepting it.

**Tested:** R-8a

---

## FIX #2 — Oracle Deviation Guard (MAX_UPDATE_DEVIATION = 50 %)

**File:** `amm/oracle.py` — `SimpleOracle.update_price()`

```python
MAX_UPDATE_DEVIATION = 5000  # basis points = 50 %
deviation_bps = abs(new_price - self.price) * 10000 // self.price
if deviation_bps > MAX_UPDATE_DEVIATION:
    raise ValueError(...)
```

A compromised oracle feed could set a price 10× higher to drain the pool
in a single swap.  The 50 % per-update cap forces multi-step manipulation,
giving defenders time to react.

**Tested:** R-8b, P-4

---

## FIX #3 — Division-by-Zero Guards in LP Removal

**File:** `amm/covenant_amm.py` — `CovenantAMMScript.compute_remove_amounts()`

```python
if old_lp_total <= 0:
    raise ValueError("old_lp_total must be > 0")
if lp_burned <= 0:
    raise ValueError("lp_burned must be > 0")
if lp_burned > old_lp_total:
    raise ValueError("lp_burned > old_lp_total")
```

Without these checks, `lp_burned / old_lp_total` could divide by zero or
produce nonsensical withdrawal amounts.

**Tested:** R-8c

---

## FIX #4 — `fee_basis` Range Validation

**File:** `amm/covenant_amm.py` — `CovenantAMMScript.get_amount_out()`

```python
if fee_basis < 0 or fee_basis > 999:
    raise ValueError(f"fee_basis must be 0..999, got {fee_basis}")
```

Values ≥ 1000 would produce negative effective input (`amount_in_with_fee`
becomes ≤ 0), allowing free withdrawals.  Negative values would flip the
fee direction, giving swappers more than the constant-product formula
allows.

**Tested:** R-8d

---

## FIX #5 — Zero / Negative Amount Rejection in Swap Verification

**File:** `amm/covenant_amm.py` — `verify_swap()`, `verify_swap_anch_to_btc()`

```python
if btc_in <= 0 or anch_out <= 0:
    return False
```

Without this, a swap with `btc_in=0` and a positive `anch_out` would pass
the constant-product check (0 multiplied by anything still satisfies
`new_k ≥ old_k` when `anch_out` is small enough due to integer rounding).

**Tested:** R-8e

---

## FIX #6 — U64 Overflow Guard (`safe_mul`)

**File:** `amm/math.py` — `safe_mul()`, `safe_product()`

```python
_U64_MAX = (1 << 64) - 1

def safe_mul(a: int, b: int, label: str = "") -> int:
    if a < 0 or b < 0:
        raise ArithmeticError(f"Negative operand in safe_mul ({label})")
    result = a * b
    if result > _U64_MAX:
        raise ArithmeticError(f"Overflow in safe_mul ({label})")
    return result
```

Python integers are arbitrary-precision, but the on-chain Script
environment is limited to 64-bit. Values exceeding `2^64 – 1` would be
valid in Python but impossible to verify on-chain, creating a
simulation/chain divergence.

**Tested:** R-8f

---

## FIX #7 — `cancel_swap` Partial Refund Safety

**File:** `production.py` — `ProductionDEX.cancel_swap()`

```python
if swap_id not in self._pending:
    return False
```

Without this check, repeatedly cancelling an already-completed swap would
re-credit the user's balance each time (double-refund attack).

**Tested:** R-8j

---

## Additional Hardening

| Area | Protection | Test |
|------|-----------|------|
| HTLC double-settle | Contract deleted after first settle | R-8g |
| RGB double-spend | Single-use seal prevents re-settlement | R-8h |
| Pending DoS limit | `MAX_PENDING_SWAPS = 1000` per pool | R-8i |
| Thread safety | `@non_reentrant` on 7 DEX mutation methods | N/A (structural) |
| Flask input validation | `_safe_int()` rejects non-numeric input | Endpoint guards |
| ClaimRegistry anti-replay | 3 indexes: proof_id, outpoint, child_txid | R-7e |
| AnchorVerifier | 5 checks: TRUC v3, OP_TRUE, child→anchor, sig, registry | R-7c |

---

## Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| Oracle manipulation | FIX #1 + #2: reject bad values, cap per-update deviation |
| Arithmetic errors | FIX #3 + #4 + #5 + #6: range checks, overflow guard |
| Double-credit | FIX #7, R-8g, R-8h: idempotent settlements |
| DoS (spam swaps) | R-8i: bounded pending queue |
| Replay attacks | ClaimRegistry with 3-index anti-replay |
| Race conditions | `@non_reentrant` decorator + `_mutex` Lock |
