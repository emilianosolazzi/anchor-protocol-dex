# RUNNING — ANCHOR DEX

## Prerequisites

```
Python 3.10+
pip install python-bitcoinlib==0.12.2 coincurve==21.0.0 flask==3.1.2
```

All three are available on PyPI with no platform-specific build issues on
Windows, macOS, and Linux.

---

## Quick Test

```bash
cd c:\Users\comar\Downloads
python -m py.quickstart          # 100-line fund→swap→withdraw demo
```

---

## Three Run Modes

### 1. Demo (default) — Full Test Suite

```bash
python -m py                     # or: python -m py demo
```

Runs all scenarios:

| Group | What it tests |
|-------|--------------|
| Scenarios 1-4 | AMM swaps, liquidity add/remove, fraud proofs |
| P-1 → P-4 | ProductionDEX (RGB + HTLC + BitVM layer) |
| R-1 → R-5 | Real crypto: secp256k1, HTLC scripts, transactions, OP_RETURN, multisig |
| R-6a → R-6g | Hybrid covenant engine: CTV, CAT, APO, CSFS, pre-signed trees |
| R-7a → R-7i | ANCHOR protocol: BRC-20, TRUC v3, minting, auctions, anti-replay |
| R-8a → R-8j | Adversarial hardening (10 attack vectors) |

### 2. Interactive — Command-Line REPL

```bash
python -m py interactive         # optional: --db mystate.db
```

Commands:

```
pool                       Show pool reserves and price
quote <BTC|ANCH> <amount>  Get swap quote
fund <user> <btc> <anch>   Fund user (sats, ANCH units)
swap <user> <BTC|ANCH> <n> Execute swap
balance <user>             Show one user
balances                   Show all users
history [limit]            Show swap history
rgb save                   Anchor RGB state to chain
reset                      Reset pool to defaults
demo                       Run built-in demo
quit                       Exit
```

State is persisted in SQLite (default `anchor_dex.db`).

### 3. Serve — Flask REST API

```bash
python -m py serve                         # default: 127.0.0.1:5000
python -m py serve --host 0.0.0.0 --port 8080
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/pool` | Pool reserves + LP info |
| GET | `/quote?direction=BTC_TO_ANCH&amount=1000000` | Swap quote |
| POST | `/fund` | `{"user","btc_sats","anch"}` — fund user |
| POST | `/swap` | `{"user","direction","amount"}` — execute swap |
| GET | `/balances/<user>` | User balances |
| GET | `/history?limit=20` | Swap history |
| POST | `/rgb/save` | Anchor RGB state |
| GET | `/anchor/stats` | ANCHOR protocol statistics |
| GET | `/anchor/balance/<user>` | User ANCH balance (protocol) |
| GET | `/anchor/slots` | List auction slots |
| POST | `/anchor/slot` | `{"block_start","block_end","min_fee_rate"}` — create slot |
| POST | `/anchor/bid` | `{"slot_id","user","amount"}` — place bid |

All error responses are JSON `{"error": "..."}` with appropriate HTTP codes.

---

## Regtest Network

The package initialises `bitcoin.SelectParams('regtest')` on import.
All keys, addresses, and transactions use regtest parameters:

- Address prefix: `bcrt1`
- P2WSH: witness version 0
- Transactions are serialisation-valid and can be broadcast to a local
  `bitcoind -regtest` node.

No real funds are ever at risk.

---

## File Layout Reference

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full package map and
import hierarchy.

See [SECURITY.md](SECURITY.md) for the seven security fixes and
adversarial hardening details.
