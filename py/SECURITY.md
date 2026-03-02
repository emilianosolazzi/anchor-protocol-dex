# SECURITY — ANCHOR DEX

Seven core security fixes, protocol-layer hardening across all four
layers, and a comprehensive adversarial test battery (R-8a → R-8j in
`demo.py`).

---

## Core Security Fixes

### FIX #1 — Oracle NaN / Zero / Negative / Inf Rejection

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

### FIX #2 — Oracle Deviation Guard (MAX_UPDATE_DEVIATION = 50 %)

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

### FIX #3 — Division-by-Zero Guards in LP Removal

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

### FIX #4 — `fee_basis` Range Validation

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

### FIX #5 — Zero / Negative Amount Rejection in Swap Verification

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

### FIX #6 — U64 Overflow Guard (`safe_mul`)

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

### FIX #7 — `cancel_swap` Partial Refund Safety

**File:** `production.py` — `ProductionDEX.cancel_swap()`

```python
if swap_id not in self._pending:
    return False
```

Without this check, repeatedly cancelling an already-completed swap would
re-credit the user's balance each time (double-refund attack).

**Tested:** R-8j

---

## Layer 4 — ANCHOR Protocol Hardening

### AnchorProof Immutability

**File:** `anchor/truc.py`

`AnchorProof` is now `@dataclass(frozen=True)`.  The verified flag is set
via `object.__setattr__()` only in the verifier, preventing accidental or
malicious mutation after creation.  The `create()` factory validates
`block_height > 0`, `fee_rate >= 0`, and non-empty `creator`.

### TRUC Package Validation

**File:** `anchor/truc.py`

`validate_truc_package()` checks full BIP-431 compliance:

| Check | Description |
|-------|-------------|
| Parent nVersion = 3 | Must be TRUC v3 |
| Parent output count ≤ MAX_PARENT_OUTPUTS (256) | Policy limit |
| Child nVersion = 3 | Child must also be v3 |
| Child weight ≤ MAX_CHILD_WEIGHT (4000) | 1P1C relay policy |
| Exactly 1 anchor output | Multi-anchor rejection |

### Verifier Hardening

**File:** `anchor/verifier.py`

- Child transaction is now also checked for TRUC v3 (was only parent)
- Multiple-anchor detection in parent via `count_anchor_outputs()`
- Pre-checks outpoint + child reuse *before* claim registration
- Configurable `min_fee_rate` parameter
- `ClaimRegistry` caps: `max_claims_per_creator` (100K default),
  `max_reward_per_claim` (10M default)
- Per-creator `_claim_counts` tracking with `creator_claim_count()` query
- `summary()` method for monitoring

### BRC-20 Spec Compliance

**File:** `anchor/brc20.py`

- Tick validation: exactly 4 bytes, printable ASCII, no whitespace
- Amounts stringified per BRC-20 spec
- Nonce support for sealed-bid auctions
- New `burn()` and `delegate()` operations
- `inscription_content_id()` hash helper for dedup

### RGB Asset Overflow Protection

**File:** `anchor/rgb.py`

- Balance overflow guard: `MAX_BALANCE = 2^63 - 1`
- Independent `_total_supply` tracking
- History capped via ring buffer (`MAX_HISTORY = 10_000`)
- `pending_escrow` property for monitoring unrevealed transfers
- Address length validation, amount bounds

### HTLC Bounds & DoS Protection

**File:** `anchor/htlc.py`

- Amount bounds: 1 sat → 21M BTC (`MAX_BTC_SATS`)
- Timelock range: `MIN_TIMELOCK` (1) → `MAX_TIMELOCK` (1M blocks)
- Hashlock format: 64-character hex string (`HASHLOCK_RE`)
- Sender ≠ recipient check
- Per-sender pending cap: `MAX_PENDING_PER_SENDER` (1,000)
- `is_terminal` property prevents double-settle/double-refund

### Minter Anti-Sybil

**File:** `anchor/minter.py`

- Per-creator minting cap: `max_per_creator` (default 5M ANCH)
- Cooldown between proofs: `cooldown_sec` (default 0, configurable)
- Reward auto-reduced when creator nears cap
- History capped: `MAX_HISTORY = 10_000`
- `creator_stats()` per-creator query
- `current_era` and `proofs_until_halving` properties

### Auction Fairness

**File:** `anchor/auction.py`

- Three auction types: English, Dutch, sealed-bid
- Anti-sniping: deadline extension on late bids
- Anti-griefing: minimum bid increment
- Anti-sybil: `ReputationProfile` with success/failure tracking
- Rate limiter: per-bidder bid frequency cap

---

## API Hardening

**File:** `api/flask_app.py`

| Protection | Detail |
|------------|--------|
| Rate limiting | Token-bucket (60 req/min per IP) with 429 response |
| CORS | `Access-Control-Allow-Origin: *` + preflight OPTIONS |
| Request-ID | UUID `X-Request-ID` header on every response |
| API versioning | All routes under `/api/v1` prefix |
| Input validation | Length caps, range checks, enum allowlists |
| Pagination | `limit` + `offset` on collection endpoints (max 500) |
| Error format | Structured `{"error", "code", "request_id"}` JSON |
| Logging | Per-request method/path/status/duration via `logger` |

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
| AnchorVerifier | 6 checks: TRUC v3 parent, v3 child, OP_TRUE, child→anchor, sig, registry | R-7c |
| Price impact ceiling | 1500 bps max single-swap impact | Scenario 1 |
| FEE_BASIS correctness | Fixed to 3 (0.3%) — was incorrectly 30 (3%) | AMM layer |

---

## Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| Oracle manipulation | FIX #1 + #2: reject bad values, cap per-update deviation |
| Arithmetic errors | FIX #3 + #4 + #5 + #6: range checks, overflow guard |
| Double-credit | FIX #7, R-8g, R-8h: idempotent settlements |
| DoS (spam swaps) | R-8i: bounded pending queue |
| DoS (HTLC spam) | Per-sender pending cap (`MAX_PENDING_PER_SENDER`) |
| DoS (claim spam) | Per-creator claim cap in `ClaimRegistry` |
| Replay attacks | ClaimRegistry with 3-index anti-replay |
| Race conditions | `@non_reentrant` decorator + `_mutex` Lock |
| Pool drain (large swap) | 1500 bps price-impact ceiling |
| Sybil minting | Per-creator cap + cooldown in `ProofOfAnchorMinter` |
| Proof mutation | Frozen `AnchorProof` dataclass |
| TRUC policy violation | `validate_truc_package()` full BIP-431 check |
| Balance inflation | RGB overflow guard (`MAX_BALANCE = 2^63 - 1`) |
| Malformed BRC-20 | Tick validation, amount stringification |
| API abuse | Rate limiting, input validation, CORS, versioned routes |
| Auction manipulation | Anti-sniping, anti-griefing, reputation tracking |
