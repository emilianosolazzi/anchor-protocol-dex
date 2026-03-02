#!/usr/bin/env python3
"""
quickstart.py — ANCHOR DEX in ~100 lines: fund → swap → withdraw

Run:
    cd c:\\Users\\comar\\Downloads
    python -m py.quickstart
"""
from __future__ import annotations

import json

# -- initialise package (selects regtest) --
import py  # noqa: F401

from py.production import ProductionDEX


def main():
    SEP = "=" * 60
    print(SEP)
    print("  ANCHOR DEX — Quickstart Demo")
    print(SEP)

    # 1. Boot a production DEX (100 M sats BTC, 10 M ANCH)
    dex = ProductionDEX(initial_btc=100_000_000, initial_anch=10_000_000)
    print("\n  Pool created:")
    print(f"    BTC reserve : {dex.pool.state.btc_reserve:>12,} sats")
    print(f"    ANCH reserve: {dex.pool.state.anch_reserve:>12,}")
    print(f"    LP total    : {dex.pool.state.lp_total:>12,}")

    # 2. Fund two users
    dex.fund_user_btc("alice", 20_000_000)
    dex.fund_user_anch("bob", 2_000_000)
    print("\n  Users funded:")
    print(f"    alice : {json.dumps(dex.get_balances('alice'))}")
    print(f"    bob   : {json.dumps(dex.get_balances('bob'))}")

    # 3. Alice swaps 5 M sats → ANCH
    print(f"\n{'_'*60}")
    print("  Alice: 5,000,000 sats → ANCH")
    print(f"{'_'*60}")
    swap_id, btc_used, anch_received = dex.swap_btc_for_anch("alice", 5_000_000)
    dex.complete_swap(swap_id)
    bal_a = dex.get_balances("alice")
    print(f"    BTC spent  : {btc_used:>12,} sats")
    print(f"    ANCH gained: {anch_received:>12,}")
    print(f"    alice now  : {bal_a['btc_sats']:>12,} sats / {bal_a['anch']:>12,} ANCH")

    # 4. Bob swaps 500 k ANCH → BTC
    print(f"\n{'_'*60}")
    print("  Bob: 500,000 ANCH → sats")
    print(f"{'_'*60}")
    swap_id2, anch_used, btc_received = dex.swap_anch_for_btc("bob", 500_000)
    dex.complete_swap(swap_id2)
    bal_b = dex.get_balances("bob")
    print(f"    ANCH spent : {anch_used:>12,}")
    print(f"    BTC gained : {btc_received:>12,} sats")
    print(f"    bob now    : {bal_b['btc_sats']:>12,} sats / {bal_b['anch']:>12,} ANCH")

    # 5. Cancel an in-progress swap (HTLC timeout refund)
    print(f"\n{'_'*60}")
    print("  Alice: start swap then cancel (HTLC timeout)")
    print(f"{'_'*60}")
    sid3, _, _ = dex.swap_btc_for_anch("alice", 1_000_000)
    cancelled = dex.cancel_swap(sid3, current_block=999_999)
    bal_a2 = dex.get_balances("alice")
    print(f"    Cancelled  : {cancelled}")
    print(f"    alice now  : {bal_a2['btc_sats']:>12,} sats / {bal_a2['anch']:>12,} ANCH")

    # 6. Final pool state
    print(f"\n{'_'*60}")
    print("  Final Pool State")
    print(f"{'_'*60}")
    info = dex.get_pool_info()
    print(f"    BTC reserve : {info['btc_reserve']:>12,} sats")
    print(f"    ANCH reserve: {info['anch_reserve']:>12,}")
    print(f"    LP total    : {info['lp_total']:>12,}")

    print(f"\n{SEP}")
    print("  Done. Run 'python -m py' for the full test suite.")
    print(SEP)


if __name__ == "__main__":
    main()
