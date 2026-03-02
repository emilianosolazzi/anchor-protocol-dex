# ARCHITECTURE — ANCHOR DEX

Fully on-chain Bitcoin DEX simulation with real cryptographic primitives,
5 covenant strategies, and the novel **ANCHOR protocol** (BRC-20
fee-market minting via ephemeral anchors).

---

## Four-Layer Stack

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 4 — ANCHOR Protocol                                   │
│    Proof-of-Anchor minting (21 M supply, halving),           │
│    SlotAuction fee-market, BRC-20 inscriptions,              │
│    TRUC (v3) transactions with OP_TRUE ephemeral anchors     │
├──────────────────────────────────────────────────────────────┤
│  Layer 3 — BitVM / Covenant AMM                              │
│    Constant-product AMM (x·y=k), LP ledger, fraud proofs,    │
│    5 covenant strategies (CTV, CAT, APO, CSFS, PreSigned),   │
│    Hybrid engine auto-selects per network                    │
├──────────────────────────────────────────────────────────────┤
│  Layer 2 — HTLC + Atomic Swaps                               │
│    Real HTLC scripts, 2-of-3 multisig, RGB single-use seals, │
│    Cross-layer atomic settlement                             │
├──────────────────────────────────────────────────────────────┤
│  Layer 1 — Real Bitcoin Crypto                               │
│    secp256k1 (coincurve), real transactions (python-          │
│    bitcoinlib), P2WSH, OP_RETURN, DER sigs, regtest          │
└──────────────────────────────────────────────────────────────┘
```

---

## Package Map

```
py/
├── __init__.py          # bitcoin.SelectParams('regtest')
├── __main__.py          # argparse: demo | interactive | serve
├── quickstart.py        # 100-line fund→swap→withdraw
├── demo.py              # Full test suite (R-1 → R-8)
├── production.py        # ProductionDEX (4-layer wrapper)
├── persistence.py       # StateStore (SQLite) + PersistentDEX
│
├── crypto/              # Layer 1 — Real Bitcoin primitives
│   ├── keys.py          # BitcoinKeyStore (secp256k1, KEYSTORE)
│   ├── scripts.py       # RealHTLCScript, RealMultiSigScript
│   └── transactions.py  # RealTransactionBuilder (funding/claim/refund/OP_RETURN)
│
├── covenants/           # Layer 3 — Covenant mechanisms
│   ├── opcodes.py       # OpCode enum, CovenantNetwork, sha256, taproot_tweak
│   ├── ctv.py           # CTVTemplate (BIP-119)
│   ├── cat.py           # CATCovenant (BIP-347)
│   ├── apo.py           # APOCovenant (BIP-118)
│   ├── csfs.py          # CSFSCovenant (Liquid/Elements)
│   ├── presigned.py     # PreSignedTree (mainnet-ready)
│   └── engine.py        # HybridCovenantEngine (auto-select)
│
├── amm/                 # Layer 3 — AMM core
│   ├── math.py          # safe_mul, safe_product, non_reentrant
│   ├── state.py         # PoolState, SwapType, FraudProof, …
│   ├── covenant_amm.py  # CovenantAMMScript (x·y=k, fees)
│   ├── pool.py          # OnChainPool (proposals, challenges)
│   ├── dex.py           # FullyOnChainDEX (@non_reentrant)
│   └── oracle.py        # SimpleOracle, BitVMPool
│
├── anchor/              # Layer 4 — ANCHOR protocol
│   ├── truc.py          # TRUCTransactionBuilder, AnchorProof
│   ├── verifier.py      # AnchorVerifier, ClaimRegistry
│   ├── brc20.py         # BRC20Inscription (deploy/mint/proof/…)
│   ├── rgb.py           # SingleUseSeal, RGBTransfer, RGBAsset
│   ├── htlc.py          # MultiSigPool, HTLCContract, HTLCAtomicSwap
│   ├── auction.py       # SlotState, AnchorSlot, SlotAuction
│   ├── minter.py        # ProofOfAnchorMinter (21M, halving)
│   └── protocol.py      # AnchorProtocol orchestrator
│
└── api/                 # REST API
    └── flask_app.py     # create_flask_app (12+ endpoints)
```

---

## Import Hierarchy (no circular deps)

```
Level 0:  amm.math, amm.state, covenants.opcodes        (leaf modules)
Level 1:  crypto.*                                       (keys, scripts, txs)
Level 2:  amm.covenant_amm                               (uses math)
Level 3:  covenants.ctv/cat/apo/csfs/presigned/engine    (uses crypto, opcodes)
Level 4:  amm.pool, amm.dex, amm.oracle                 (uses L0-L2)
Level 5:  anchor.*                                       (uses crypto, amm, covenants)
Level 6:  production, persistence, api                   (uses everything)
Level 7:  demo, __main__                                 (entry points)
```

---

## Key Design Decisions

| Area | Decision | Reason |
|------|----------|--------|
| Network | regtest | Deterministic, no real funds at risk |
| Crypto | coincurve (libsecp256k1) | Same curve library as Bitcoin Core |
| Transactions | python-bitcoinlib | Real CTransaction, real opcodes |
| AMM | Constant-product (x·y=k) | Proven model (Uniswap V2 style) |
| Covenants | 5 strategies + auto-select | Future-proof across Bitcoin forks |
| Persistence | SQLite WAL | Simple, no external DB server |
| Threading | `@non_reentrant` decorator + `_mutex` Lock | Prevents concurrent pool mutation |
| Token supply | 21 M with halving | Mirrors Bitcoin's supply schedule |
