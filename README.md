# ANCHOR Protocol DEX

Fully on-chain Bitcoin DEX simulation with real cryptographic primitives, 5 covenant strategies, and the novel **ANCHOR protocol** — a BRC-20 fee-market minting mechanism powered by ephemeral anchors.

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

No real funds are involved. All keys, addresses, and transactions target `regtest`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 4 — ANCHOR Protocol                                   │
│    Proof-of-Anchor minting · SlotAuction fee-market          │
│    BRC-20 inscriptions · TRUC v3 ephemeral anchors           │
├──────────────────────────────────────────────────────────────┤
│  Layer 3 — Covenant AMM                                      │
│    Constant-product x·y=k · LP ledger · Fraud proofs         │
│    CTV · CAT · APO · CSFS · Pre-signed trees                │
├──────────────────────────────────────────────────────────────┤
│  Layer 2 — HTLC + Atomic Swaps                               │
│    Real HTLC scripts · 2-of-3 multisig · RGB seals           │
├──────────────────────────────────────────────────────────────┤
│  Layer 1 — Real Bitcoin Crypto                               │
│    secp256k1 · P2WSH · OP_RETURN · DER sigs · regtest        │
└──────────────────────────────────────────────────────────────┘
```

See [py/ARCHITECTURE.md](py/ARCHITECTURE.md) for the full package map and import hierarchy.

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
├── api/            flask_app.py
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
3. The user submits both transactions as an `AnchorProof` to the protocol
4. `AnchorVerifier` validates: TRUC version 3, OP_TRUE anchor present, child spends anchor, creator signature, no replay
5. `ProofOfAnchorMinter` rewards **ANCH tokens** (21M max supply, halving every 5,250 proofs)
6. `SlotAuction` creates a fee-market where users bid ANCH for the right to anchor in specific block ranges

```
Submit TRUC v3 parent+child  →  Verify anchor proof  →  Mint ANCH reward
                                                      →  Bid on SlotAuction
                                                      →  Win slot → Prove anchor → Bonus reward
```

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

7 security fixes + adversarial hardening, all verified by the R-8 test battery:

| Fix | Threat | Protection |
|-----|--------|-----------|
| #1 | Oracle NaN/Inf/zero injection | Input validation on every price update |
| #2 | Oracle price manipulation | 50% max deviation per update |
| #3 | LP removal div-by-zero | Range checks on lp_burned and old_lp_total |
| #4 | Fee basis exploitation | Clamp fee_basis to 0–999 |
| #5 | Zero-amount free withdrawal | Reject zero/negative swap amounts |
| #6 | U64 overflow divergence | `safe_mul` guards all multiplications |
| #7 | Cancel-swap double refund | Idempotent settlement checks |

Additional: HTLC double-settle prevention, RGB single-use seals, pending swap DoS limit (1000), `@non_reentrant` thread safety, Flask input validation, ClaimRegistry anti-replay (3 indexes).

See [py/SECURITY.md](py/SECURITY.md) for details.

---

## API Endpoints

Start with `python -m py serve --port 5000`:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/pool` | Pool reserves + LP |
| GET | `/quote?direction=BTC_TO_ANCH&amount=1000000` | Swap quote |
| POST | `/fund` | Fund user `{"user","btc_sats","anch"}` |
| POST | `/swap` | Execute swap `{"user","direction","amount"}` |
| GET | `/balances/<user>` | User balances |
| GET | `/history` | Swap history |
| POST | `/rgb/save` | Anchor RGB state |
| GET | `/anchor/stats` | Protocol statistics |
| GET | `/anchor/balance/<user>` | ANCH balance |
| GET | `/anchor/slots` | Auction slots |
| POST | `/anchor/slot` | Create slot |
| POST | `/anchor/bid` | Place bid |

---

## Demo Output

```
python -m py demo
```

Runs scenarios 1–4 (AMM), P-1–P-4 (production), R-1–R-5 (real crypto), R-6a–R-6g (covenants), R-7a–R-7i (ANCHOR protocol), R-8a–R-8j (adversarial hardening). All pass.

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

## License

MIT
