# ANCHOR Protocol DEX

Fully on-chain Bitcoin DEX simulation with real cryptographic primitives, 5 covenant strategies, and the novel **ANCHOR protocol** — a BRC-20 fee-market minting mechanism powered by ephemeral anchors.
By Emiliano Solazzi 2026

```
python -m py demo          # run all tests (R-1 → R-8)
python -m py interactive   # command-line REPL
python -m py serve         # Flask REST API on :5000
```

---

## What This Is

A working simulation of a Bitcoin-native decentralized exchange that uses:

- **Real secp256k1** cryptography (coincurve / libsecp256k1)
- **Real Bitcoin transactions** (python-bitcoinlib, regtest-broadcastable)
- **Real HTLC scripts** (OP_IF / OP_SHA256 / OP_CHECKLOCKTIMEVERIFY)
- **5 covenant mechanisms** with automatic network-aware selection
- **ANCHOR protocol** — a novel token minting scheme where ANCH tokens are earned by proving you created ephemeral anchor outputs in TRUC (v3) transactions
- **Production-grade hardening** — overflow guards, anti-replay, DoS caps, frozen proofs, rate-limited API

No real funds are involved. All keys, addresses, and transactions target `regtest`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 4 — ANCHOR Protocol                                   │
│    Proof-of-Anchor minting (21M, halving, per-creator caps)  │
│    SlotAuction (English, Dutch, sealed-bid, anti-sniping)    │
│    BRC-20 inscriptions (deploy/mint/burn/delegate)           │
│    TRUC v3 ephemeral anchors · frozen AnchorProof            │
├──────────────────────────────────────────────────────────────┤
│  Layer 3 — Covenant AMM                                      │
│    Constant-product x·y=k · LP ledger · Fraud proofs         │
│    CTV · CAT · APO · CSFS · Pre-signed trees                │
│    safe_mul overflow guards · price-impact ceiling            │
├──────────────────────────────────────────────────────────────┤
│  Layer 2 — HTLC + Atomic Swaps                               │
│    Real HTLC scripts · 2-of-3 multisig · RGB seals           │
│    Per-sender DoS caps · timelock/hashlock validation         │
├──────────────────────────────────────────────────────────────┤
│  Layer 1 — Real Bitcoin Crypto                               │
│    secp256k1 · P2WSH · P2WPKH · OP_RETURN · DER sigs        │
└──────────────────────────────────────────────────────────────┘
```

See [py/ARCHITECTURE.md](py/ARCHITECTURE.md) for the full package map, import hierarchy, and design decisions.

---

## Install

```bash
pip install python-bitcoinlib==0.12.2 coincurve==21.0.0 flask==3.1.2
```

Python 3.10+ required.

---

## Package Structure

```
py/
├── crypto/         keys.py · scripts.py · transactions.py
├── covenants/      opcodes.py · ctv.py · cat.py · apo.py · csfs.py · presigned.py · engine.py
├── amm/            math.py · state.py · covenant_amm.py · pool.py · dex.py · oracle.py
├── anchor/         truc.py · verifier.py · brc20.py · rgb.py · htlc.py · auction.py · minter.py · protocol.py
├── api/            flask_app.py (19 endpoints, rate-limit, CORS, request-ID)
├── demo.py         Full test suite (R-1 → R-8)
├── quickstart.py   100-line fund → swap → withdraw
├── production.py   4-layer ProductionDEX wrapper
├── persistence.py  SQLite WAL + PersistentDEX
├── __main__.py     CLI entry point (demo | interactive | serve)
└── __init__.py     bitcoin.SelectParams('regtest')
```

---

## The ANCHOR Protocol

The novel contribution: **Proof-of-Anchor minting**.

1. A user creates a **TRUC (v3) transaction** with an **OP_TRUE ephemeral anchor** output
2. A child transaction spends that anchor (CPFP fee-bumping)
3. The user submits both transactions as an `AnchorProof` (immutable, frozen dataclass) to the protocol
4. `AnchorVerifier` validates: TRUC v3 parent **and** child, OP_TRUE anchor present, exactly one anchor output, child spends anchor, creator signature, no replay (3-index anti-replay registry)
5. `ProofOfAnchorMinter` rewards **ANCH tokens** (21M max supply, halving every 5,250 proofs, per-creator cap, configurable cooldown)
6. `SlotAuction` creates a fee-market where users bid ANCH for the right to anchor in specific block ranges (English, Dutch, or sealed-bid auctions with anti-sniping and anti-griefing)

```
Submit TRUC v3 parent+child  →  Verify anchor proof  →  Mint ANCH reward
                                                      →  Bid on SlotAuction
                                                      →  Win slot → Prove anchor → Bonus reward
```

### BRC-20 Token

The ANCH token is inscribed as a BRC-20 with full spec compliance:

- 4-byte tick validation, stringified amounts
- Operations: `deploy`, `mint`, `transfer`, `proof`, `bid`, `claim`, `burn`, `delegate`
- Content hash deduplication via `inscription_content_id()`

---

## Covenant Strategies

The hybrid engine auto-selects the best available mechanism per network:

| Mechanism | Mainnet | Inquisition Signet | Liquid | Regtest |
|-----------|---------|-------------------|--------|---------|
| **Pre-signed trees** | ✓ | ✓ | ✓ | ✓ |
| **OP_CTV** (BIP-119) | — | ✓ | — | ✓ |
| **OP_CAT** (BIP-347) | — | ✓ | ✓ | ✓ |
| **APO** (BIP-118) | — | ✓ | — | ✓ |
| **CSFS** (Elements) | — | — | ✓ | ✓ |

---

## Security

7 core security fixes + protocol-layer hardening across all 4 layers, verified by the R-8 test battery:

### Core Fixes

| Fix | Threat | Protection |
|-----|--------|-----------|
| #1 | Oracle NaN/Inf/zero injection | Input validation on every price update |
| #2 | Oracle price manipulation | 50% max deviation per update |
| #3 | LP removal div-by-zero | Range checks on lp_burned and old_lp_total |
| #4 | Fee basis exploitation | Clamp fee_basis to 0–999 |
| #5 | Zero-amount free withdrawal | Reject zero/negative swap amounts |
| #6 | U64 overflow divergence | `safe_mul` guards all multiplications |
| #7 | Cancel-swap double refund | Idempotent settlement checks |

### Protocol-Layer Hardening

| Layer | Protection |
|-------|-----------|
| **AnchorProof** | `@dataclass(frozen=True)` — immutable after creation |
| **TRUC validation** | Full BIP-431 package checks (parent+child v3, weight, output limits) |
| **Verifier** | Child v3 check, multi-anchor rejection, per-creator claim cap (100K) |
| **BRC-20** | 4-byte tick validation, burn/delegate ops, inscription content hash |
| **RGB asset** | Balance overflow guard (2⁶³−1), supply tracking, history ring buffer |
| **HTLC** | Amount bounds (1 sat → 21M BTC), timelock range, hashlock regex, per-sender DoS cap |
| **Minter** | Per-creator minting cap (5M), configurable cooldown, era/halving tracking |
| **Auction** | Anti-sniping, anti-griefing, reputation tracking, rate limiting |
| **AMM** | 1500 bps price-impact ceiling, `@non_reentrant` on 7 mutation methods |
| **API** | Rate limiting (60 req/min), CORS, request-ID, versioned routes, input validation |

See [py/SECURITY.md](py/SECURITY.md) for full details and threat model.

---

## API Endpoints

Start with `python -m py serve --port 5000`. All routes are under `/api/v1`.

### Core

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check + pool snapshot |
| GET | `/pool` | Pool reserves + LP info |
| GET | `/pool/spot-price` | Current spot price (fixed-point) |
| GET | `/pool/twap` | TWAP oracle price |
| GET | `/pool/fees` | Cumulative fee breakdown |
| GET | `/pool/info` | Full pool detail (config, fees, TWAP) |
| GET | `/quote?direction=BTC_TO_ANCH&amount=1000000` | Swap quote |
| POST | `/fund` | Fund user `{"user","btc_sats","anch"}` |
| POST | `/swap` | Execute swap `{"user","direction","amount"}` |
| GET | `/balances/<user>` | User balances |
| GET | `/history?limit=20&offset=0` | Paginated swap history (max 500) |
| POST | `/rgb/save` | Anchor RGB state commitment |
| GET | `/dex/summary` | DEX-wide summary (TVL, volume, fees) |

### ANCHOR Protocol

| Method | Path | Description |
|--------|------|-------------|
| GET | `/anchor/stats` | Protocol statistics (minter, registry, slots) |
| GET | `/anchor/balance/<user>` | ANCH balance |
| GET | `/anchor/slots` | List auction slots |
| POST | `/anchor/slot` | Create slot `{"block_start","block_end","min_fee_rate"}` |
| POST | `/anchor/bid` | Place bid `{"slot_id","user","amount"}` |

Direction aliases: `BTC_TO_ANCH` / `BTC` / `B2A`, `ANCH_TO_BTC` / `ANCH` / `A2B`.

---

## Demo Output

```
python -m py demo
```

Runs scenarios 1–4 (AMM + price-impact), P-1–P-4 (production + oracle guard), R-1–R-5 (real crypto), R-6a–R-6g (covenants), R-7a–R-7i (ANCHOR protocol), R-8a–R-8j (adversarial hardening). All pass.

---

## Quickstart

```python
from py.production import ProductionDEX

dex = ProductionDEX(initial_btc=100_000_000, initial_anch=10_000_000)
dex.fund_user_btc("alice", 20_000_000)

swap_id, btc_used, anch_received = dex.swap_btc_for_anch("alice", 5_000_000)
dex.complete_swap(swap_id)

print(dex.get_balances("alice"))
# {'btc_sats': 15000000, 'anch': 474829}
```

---

## Documentation

| File | Contents |
|------|----------|
| [py/ARCHITECTURE.md](py/ARCHITECTURE.md) | Package map, import hierarchy, 18 design decisions |
| [py/SECURITY.md](py/SECURITY.md) | 7 core fixes, protocol hardening, API hardening, threat model (16 threats) |
| [py/RUNNING.md](py/RUNNING.md) | Install, 3 run modes, 19 API endpoints, regtest details |

---

## License

MIT
