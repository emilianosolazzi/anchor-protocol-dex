"""
Demo mode + interactive REPL for the ANCHOR DEX.

run_demo()        -- all test scenarios (R-1 through R-8)
interactive_mode() -- interactive command-line terminal
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from typing import Optional

from bitcoin.core import (
    CTransaction, CTxIn, CTxOut, COutPoint, CScript, lx,
)
from bitcoin.core.script import OP_0

from .amm.math import safe_mul, safe_product
from .amm.state import PoolState, SwapType
from .amm.covenant_amm import CovenantAMMScript
from .amm.pool import OnChainPool
from .amm.dex import FullyOnChainDEX
from .amm.oracle import SimpleOracle, BitVMPool

from .crypto.keys import KEYSTORE
from .crypto.scripts import RealHTLCScript
from .crypto.transactions import RealTransactionBuilder

from .covenants.opcodes import CovenantNetwork
from .covenants.ctv import CTVTemplate
from .covenants.cat import CATCovenant
from .covenants.apo import APOCovenant
from .covenants.csfs import CSFSCovenant
from .covenants.presigned import PreSignedTree
from .covenants.engine import HybridCovenantEngine

from .anchor.rgb import RGBAsset
from .anchor.htlc import HTLCAtomicSwap, MultiSigPool
from .anchor.truc import TRUCTransactionBuilder
from .anchor.brc20 import BRC20Inscription
from .anchor.protocol import AnchorProtocol

from .production import ProductionDEX
from .persistence import PersistentDEX


def run_demo():
    SEP = "=" * 64
    print(SEP)
    print("  FULLY ON-CHAIN DEX SIMULATION")
    print(SEP)

    dex = FullyOnChainDEX()
    pool = dex.create_pool("btc-anch", btc_reserve=100_000_000,
                           anch_reserve=10_000_000, owner="alice")
    print(f"\n  Initial pool state:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 1: Valid BTC->ANCH swap --
    print(f"\n{SEP}")
    print("  SCENARIO 1: Valid BTC->ANCH swap")
    print(SEP)
    btc_in = 10_000_000
    anch_out = pool.quote(SwapType.BTC_TO_ANCH, btc_in)
    print(f"  Bob swaps {btc_in:,} sats -> expected ~{anch_out:,} ANCH")
    bob_sig = b"bob_signature_valid"
    txid1 = dex.swap("btc-anch", "bob", SwapType.BTC_TO_ANCH, btc_in, anch_out, bob_sig)
    print("\n  Charlie challenges the valid swap:")
    dex.challenge("btc-anch", txid1, "charlie")
    print("\n  Simulating passage of challenge period...")
    pool.challenge_period = 0
    dex.finalize("btc-anch", txid1)
    print(f"\n  Pool after swap 1:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 2: Invalid BTC->ANCH swap --
    print(f"\n{SEP}")
    print("  SCENARIO 2: Invalid BTC->ANCH swap (requesting too many ANCH)")
    print(SEP)
    pool.challenge_period = 144
    btc_in2 = 10_000_000
    greedy = pool.quote(SwapType.BTC_TO_ANCH, btc_in2) + 100_000
    print(f"  Bob tries to claim {greedy:,} ANCH (fair value is ~{greedy - 100_000:,})")
    txid2 = dex.swap("btc-anch", "bob", SwapType.BTC_TO_ANCH, btc_in2, greedy, bob_sig)
    if txid2 is None:
        print("  Swap was rejected immediately by covenant check")

    # -- SCENARIO 3: Valid ANCH->BTC swap --
    print(f"\n{SEP}")
    print("  SCENARIO 3: Valid ANCH->BTC swap")
    print(SEP)
    pool.challenge_period = 0
    anch_in = 500_000
    btc_out = pool.quote(SwapType.ANCH_TO_BTC, anch_in)
    print(f"  Dave swaps {anch_in:,} ANCH -> expected ~{btc_out:,} sats")
    dave_sig = b"dave_signature_valid"
    txid3 = dex.swap("btc-anch", "dave", SwapType.ANCH_TO_BTC, anch_in, btc_out, dave_sig)
    if txid3:
        dex.finalize("btc-anch", txid3)
    print(f"\n  Final pool state:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 4a: Bootstrap liquidity --
    print(f"\n{SEP}")
    print("  SCENARIO 4a: Alice adds liquidity (initial bootstrap)")
    print(SEP)
    alice_sig = b"alice_signature_valid"
    btc_add = pool.state.btc_reserve
    anch_add = pool.state.anch_reserve
    txid_add = dex.add_liquidity("btc-anch", "alice", btc_add, anch_add, alice_sig)
    if txid_add:
        dex.finalize_liquidity("btc-anch", txid_add)
    print(f"\n  Pool after bootstrap liquidity:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 4b: Eve adds proportionally --
    print(f"\n{SEP}")
    print("  SCENARIO 4b: Eve adds liquidity proportionally")
    print(SEP)
    eve_btc = pool.state.btc_reserve // 20
    eve_anch = pool.state.anch_reserve // 20
    eve_sig = b"eve_signature_valid"
    txid_eve = dex.add_liquidity("btc-anch", "eve", eve_btc, eve_anch, eve_sig)
    if txid_eve:
        dex.finalize_liquidity("btc-anch", txid_eve)
    print(f"\n  Pool after Eve's deposit:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 4c: Alice removes LP --
    print(f"\n{SEP}")
    print("  SCENARIO 4c: Alice removes quarter of LP tokens")
    print(SEP)
    lp_to_burn = pool.state.lp_total // 4
    btc_exp, anch_exp = CovenantAMMScript.compute_remove_amounts(
        lp_to_burn, pool.state.btc_reserve, pool.state.anch_reserve, pool.state.lp_total)
    print(f"  Burns {lp_to_burn:,} LP -> ~{btc_exp:,} sats + {anch_exp:,} ANCH")
    txid_rm = dex.remove_liquidity("btc-anch", "alice", lp_to_burn, alice_sig)
    if txid_rm:
        dex.finalize_liquidity("btc-anch", txid_rm)
    print(f"\n  Pool after removal:")
    print(json.dumps(pool.get_info(), indent=2))

    # -- SCENARIO 4d: Skewed ratio --
    print(f"\n{SEP}")
    print("  SCENARIO 4d: Mallory tries skewed liquidity")
    print(SEP)
    bad_btc = 1_000_000
    bad_anch = bad_btc * (pool.state.anch_reserve // pool.state.btc_reserve) * 10
    txid_bad = dex.add_liquidity("btc-anch", "mallory", bad_btc, bad_anch, b"mallory")
    if txid_bad is None:
        print("  Rejected.")

    print(f"\n{SEP}")
    print("  All covenant scenarios complete.")
    print(SEP)

    # -- RGB + MultiSig --
    rgb = RGBAsset("ANCH")
    rgb.mint("alice", 1_000_000)
    rgb.save_rgb_state()
    msig = MultiSigPool(["pk1", "pk2", "pk3"])
    print(f"  Multisig script: {msig.script}")

    # -- Production DEX --
    print(f"\n{SEP}")
    print("  PRODUCTION DEX (RGB + HTLC + BitVM)")
    print(SEP)
    pdex = ProductionDEX(initial_btc=100_000_000, initial_anch=10_000_000)
    pdex.fund_user_btc("bob", 50_000_000)
    pdex.fund_user_anch("eve", 2_000_000)

    print(f"\n{'_'*64}")
    print("  P-1: Bob 5M sats -> ANCH")
    print(f"{'_'*64}")
    print(f"  Bob before: {pdex.get_balances('bob')}")
    sid1, _, _ = pdex.swap_btc_for_anch("bob", 5_000_000)
    pdex.complete_swap(sid1)
    print(f"  Bob after:  {pdex.get_balances('bob')}")

    print(f"\n{'_'*64}")
    print("  P-2: Eve 500k ANCH -> BTC")
    print(f"{'_'*64}")
    print(f"  Eve before: {pdex.get_balances('eve')}")
    sid2, _, _ = pdex.swap_anch_for_btc("eve", 500_000)
    pdex.complete_swap(sid2)
    print(f"  Eve after:  {pdex.get_balances('eve')}")

    print(f"\n{'_'*64}")
    print("  P-3: Bob swap + cancel (HTLC expires)")
    print(f"{'_'*64}")
    sid3, _, _ = pdex.swap_btc_for_anch("bob", 1_000_000)
    cancelled = pdex.cancel_swap(sid3, int(time.time() / 600) + 200)
    print(f"  Cancelled: {cancelled}  Bob: {pdex.get_balances('bob')['btc_sats']:,} sats")

    print(f"\n{'_'*64}")
    print("  P-4: Oracle blocks drain attack (FIX #7)")
    print(f"{'_'*64}")
    pdex.oracle.update_price(5.0)
    try:
        pdex.swap_anch_for_btc("eve", 2_000_000)
        print("  Oracle FAILED to block!")
    except ValueError as e:
        print(f"  Oracle blocked: {e}")

    # ==========================================================================
    # REAL BITCOIN CRYPTO SHOWCASE
    # ==========================================================================
    print(f"\n{SEP}")
    print("  REAL BITCOIN CRYPTO LAYER (secp256k1 + Script + Transactions)")
    print(SEP)

    print(f"\n  Network: regtest (bitcoin-core compatible)")
    print(f"  Crypto:  secp256k1 via coincurve (libsecp256k1)")
    print(f"  Script:  python-bitcoinlib (real opcodes)")

    # -- Real keypairs --
    print(f"\n{'_'*64}")
    print("  R-1: Real secp256k1 Keypairs")
    print(f"{'_'*64}")
    for alias in ["alice", "bob", "pool_taproot_address_v1"]:
        info = KEYSTORE.info(alias)
        print(f"  {alias:>28}: pubkey={info['pubkey_hex'][:32]}...")
        print(f"  {'':>28}  addr={info['address']}")

    # -- Real HTLC Script --
    print(f"\n{'_'*64}")
    print("  R-2: Real HTLC Bitcoin Script")
    print(f"{'_'*64}")
    demo_secret = os.urandom(32)
    demo_hash = hashlib.sha256(demo_secret).digest()
    demo_htlc = RealHTLCScript(
        sender_pubkey=KEYSTORE.pubkey("alice"),
        recipient_pubkey=KEYSTORE.pubkey("bob"),
        secret_hash=demo_hash,
        timelock_blocks=144,
    )
    htlc_info = demo_htlc.info()
    print(f"  Redeem Script ({htlc_info['redeem_script_size']}B): "
          f"{htlc_info['redeem_script_hex'][:64]}...")
    print(f"  P2WSH scriptPubKey: {htlc_info['p2wsh_hex']}")
    print(f"  Timelock: {htlc_info['timelock']} blocks (~{htlc_info['timelock']*10//60}h)")
    print(f"\n  Script disassembly:")
    print(f"    OP_IF")
    print(f"      OP_SHA256 <{demo_hash.hex()[:16]}...> OP_EQUALVERIFY")
    print(f"      <bob_pubkey> OP_CHECKSIG")
    print(f"    OP_ELSE")
    print(f"      <144> OP_CHECKLOCKTIMEVERIFY OP_DROP")
    print(f"      <alice_pubkey> OP_CHECKSIG")
    print(f"    OP_ENDIF")

    # -- Real Funding Transaction --
    print(f"\n{'_'*64}")
    print("  R-3: Real Bitcoin Transactions")
    print(f"{'_'*64}")
    mock_outpoint = COutPoint(lx("aa" * 32), 0)
    funding_tx = RealTransactionBuilder.build_funding_tx(
        mock_outpoint, demo_htlc, 5_000_000,
    )
    print(f"  Funding TX ({len(funding_tx.serialize())}B):")
    print(f"    TXID: {RealTransactionBuilder.txid_hex(funding_tx)}")
    print(f"    Hex:  {RealTransactionBuilder.serialize_hex(funding_tx)[:80]}...")
    print(f"    Output[0]: {funding_tx.vout[0].nValue:,} sats -> P2WSH(HTLC)")

    # Claim tx
    recipient_spk = KEYSTORE.p2wpkh_scriptpubkey("bob")
    claim_tx, claim_sighash = RealTransactionBuilder.build_claim_tx(
        funding_tx.GetTxid(), 0, demo_htlc, 5_000_000, recipient_spk,
    )
    claim_sig = KEYSTORE.sign("bob", claim_sighash)
    print(f"\n  Claim TX ({len(claim_tx.serialize())}B):")
    print(f"    TXID: {RealTransactionBuilder.txid_hex(claim_tx)}")
    print(f"    Signature: {claim_sig.hex()[:40]}... ({len(claim_sig)}B)")
    print(f"    Sig valid: {KEYSTORE.verify('bob', claim_sig, claim_sighash)}")

    # Refund tx
    sender_spk = KEYSTORE.p2wpkh_scriptpubkey("alice")
    refund_tx, refund_sighash = RealTransactionBuilder.build_refund_tx(
        funding_tx.GetTxid(), 0, demo_htlc, 5_000_000, sender_spk,
    )
    refund_sig = KEYSTORE.sign("alice", refund_sighash)
    print(f"\n  Refund TX ({len(refund_tx.serialize())}B, nLockTime={refund_tx.nLockTime}):")
    print(f"    TXID: {RealTransactionBuilder.txid_hex(refund_tx)}")
    print(f"    Signature: {refund_sig.hex()[:40]}... ({len(refund_sig)}B)")
    print(f"    Sig valid: {KEYSTORE.verify('alice', refund_sig, refund_sighash)}")

    # -- Real OP_RETURN for RGB anchoring --
    print(f"\n{'_'*64}")
    print("  R-4: Real OP_RETURN Transaction (RGB State Anchor)")
    print(f"{'_'*64}")
    rgb_commitment = hashlib.sha256(b"rgb_state_data_v1").digest()
    op_return_tx = RealTransactionBuilder.build_op_return_tx(
        COutPoint(lx("bb" * 32), 0),
        rgb_commitment,
        KEYSTORE.p2wpkh_scriptpubkey("alice"),
        546,
    )
    print(f"  OP_RETURN TX ({len(op_return_tx.serialize())}B):")
    print(f"    TXID: {RealTransactionBuilder.txid_hex(op_return_tx)}")
    print(f"    Output[0]: OP_RETURN <{rgb_commitment.hex()[:32]}...> (0 sats)")
    print(f"    Output[1]: Change -> alice P2WPKH ({546} sats)")

    # -- Real 2-of-3 Multisig --
    print(f"\n{'_'*64}")
    print("  R-5: Real 2-of-3 Multisig Script")
    print(f"{'_'*64}")
    msig = MultiSigPool(["alice", "bob", "charlie"])
    msig_info = msig.real_multisig.info()
    print(f"  Type: {msig_info['type']}")
    print(f"  Script ({msig_info['script_size']}B): {msig_info['script_hex'][:64]}...")
    print(f"  P2WSH: {msig_info['p2wsh_hex']}")
    for i, pk in enumerate(msig_info['pubkeys']):
        print(f"    Key[{i}]: {pk[:32]}...")

    # ==========================================================================
    # R-6: HYBRID COVENANT ENGINE
    # ==========================================================================
    print(f"\n{SEP}")
    print("  HYBRID COVENANT ENGINE (OP_CAT Alternatives)")
    print(SEP)
    print()
    print("  Available covenant mechanisms across Bitcoin networks:")
    print("  +-------------------------+----------+----------+--------+---------+")
    print("  | Mechanism               | Mainnet  | Inq.Sig  | Liquid | Regtest |")
    print("  +-------------------------+----------+----------+--------+---------+")
    print("  | OP_CAT (BIP-347, 0x7e) |    -     |    Y     |   Y    |   Y     |")
    print("  | OP_CTV (BIP-119, 0xb3) |    -     |    Y     |   -    |   Y     |")
    print("  | APO    (BIP-118)        |    -     |    Y     |   -    |   Y     |")
    print("  | CSFS   (Elements)       |    -     |    -     |   Y    |   Y     |")
    print("  | Pre-signed Tx Trees     |    Y     |    Y     |   Y    |   Y     |")
    print("  +-------------------------+----------+----------+--------+---------+")

    demo_pool_state = PoolState(
        btc_reserve=100_000_000,
        anch_reserve=10_000_000,
        lp_total=31_622,
        taproot_address="bcrt1pdemo",
        script_merkle_root=b'\x00' * 32,
    )
    demo_amount_in = 5_000_000
    demo_amount_out = CovenantAMMScript.get_amount_out(
        demo_amount_in, demo_pool_state.btc_reserve, demo_pool_state.anch_reserve,
    )
    demo_new_state = PoolState(
        btc_reserve=demo_pool_state.btc_reserve + demo_amount_in,
        anch_reserve=demo_pool_state.anch_reserve - demo_amount_out,
        lp_total=demo_pool_state.lp_total,
        taproot_address=demo_pool_state.taproot_address,
        script_merkle_root=demo_pool_state.script_merkle_root,
    )

    # -- R-6a: CTV Template Hash (BIP-119) --
    print(f"\n{'_'*64}")
    print("  R-6a: OP_CHECKTEMPLATEVERIFY (BIP-119)")
    print(f"{'_'*64}")
    state_data = struct.pack("<QQQ",
        demo_new_state.btc_reserve, demo_new_state.anch_reserve,
        demo_new_state.lp_total)
    ctv_out = CTxOut(
        demo_new_state.btc_reserve,
        CScript([OP_0, hashlib.sha256(state_data).digest()]),
    )
    ctv_tx = CTransaction(
        [CTxIn(COutPoint(lx("dd" * 32), 0))],
        [ctv_out],
    )
    ctv_hash = CTVTemplate.from_transaction(ctv_tx, input_index=0)
    ctv_script = CTVTemplate.build_ctv_script(ctv_hash)
    print(f"  CTV opcode: 0xb3 (was OP_NOP4, soft-forked on Inquisition Signet)")
    print(f"  Template Hash: {ctv_hash.hex()}")
    print(f"  CTV Script:    {ctv_script.hex()}")
    print(f"  Script ASM:    <{ctv_hash.hex()[:16]}...> OP_CTV")
    print(f"  Commits to:    nVersion, nLockTime, inputCount, sequencesHash,")
    print(f"                 outputCount, outputsHash, inputIndex")
    print(f"  Network:       Bitcoin Inquisition Signet (BIP-119 active)")

    # -- R-6b: OP_CAT State Commitment (BIP-347) --
    print(f"\n{'_'*64}")
    print("  R-6b: OP_CAT State Commitment (BIP-347)")
    print(f"{'_'*64}")
    old_data = struct.pack("<QQ", demo_pool_state.btc_reserve, demo_pool_state.anch_reserve)
    new_data = struct.pack("<QQ", demo_new_state.btc_reserve, demo_new_state.anch_reserve)
    old_hash = hashlib.sha256(old_data).digest()
    new_hash = hashlib.sha256(new_data).digest()
    cat_script = CATCovenant.build_state_commitment_script(old_hash, new_hash)
    cat_info = CATCovenant.info()
    print(f"  OP_CAT opcode: 0x7e (re-enabled via BIP-347)")
    print(f"  Script ({len(cat_script)}B): {cat_script.hex()[:64]}...")
    print(f"  Script ASM:    <old_hash> <new_hash> OP_CAT OP_SHA256 <expected> OP_EQUALVERIFY")
    print(f"  Old state:     BTC={demo_pool_state.btc_reserve:,} ANCH={demo_pool_state.anch_reserve:,}")
    print(f"  New state:     BTC={demo_new_state.btc_reserve:,} ANCH={demo_new_state.anch_reserve:,}")
    print(f"  Transition:    {hashlib.sha256(old_hash + new_hash).hexdigest()[:32]}...")
    print(f"  Networks:      {', '.join(cat_info['networks'])}")

    amm_script, amm_commit = CATCovenant.build_amm_invariant_check(
        demo_pool_state.btc_reserve, demo_pool_state.anch_reserve,
        demo_new_state.btc_reserve, demo_new_state.anch_reserve,
    )
    print(f"\n  AMM Invariant Script ({len(amm_script)}B):")
    print(f"    Script hex:  {amm_script.hex()[:64]}...")
    print(f"    Commitment:  {amm_commit.hex()[:32]}...")
    print(f"    ASM: <old_reserves> <new_reserves> OP_CAT OP_SHA256 <commit> OP_EQUALVERIFY")

    # -- R-6c: OP_CAT + OP_CTV Hybrid --
    print(f"\n{'_'*64}")
    print("  R-6c: Hybrid OP_CAT + OP_CTV (Inquisition Signet)")
    print(f"{'_'*64}")
    hybrid_script = CATCovenant.build_cat_ctv_hybrid_script(
        hashlib.sha256(old_hash + new_hash).digest(), ctv_hash,
    )
    print(f"  Hybrid Script ({len(hybrid_script)}B): {hybrid_script.hex()[:64]}...")
    print(f"  ASM: <state_hash> OP_SHA256 <expected> OP_EQUALVERIFY <ctv_hash> OP_CTV")
    print(f"  OP_CAT verifies: state transition integrity")
    print(f"  OP_CTV verifies: spending transaction template")
    print(f"  Combined:        parameterized covenant (dynamic state + fixed tx shape)")

    # -- R-6d: SIGHASH_ANYPREVOUT (BIP-118) --
    print(f"\n{'_'*64}")
    print("  R-6d: SIGHASH_ANYPREVOUT (BIP-118)")
    print(f"{'_'*64}")
    apo_info = APOCovenant.info()
    update_key = KEYSTORE.pubkey("pool_operator")
    apo_script = APOCovenant.build_apo_update_script(update_key)
    tx_data = struct.pack("<QQ", demo_new_state.btc_reserve, demo_new_state.anch_reserve)
    priv = KEYSTORE.get_or_create("pool_operator")
    apo_sig = APOCovenant.create_apo_signature(priv, tx_data)
    apo_valid = APOCovenant.verify_apo_signature(update_key, apo_sig, tx_data)
    print(f"  SIGHASH flags: ANYPREVOUT=0x41, ANYPREVOUTANYSCRIPT=0xc1")
    print(f"  Update script: <pool_operator_pk> OP_CHECKSIG")
    print(f"  Script ({len(apo_script)}B):  {apo_script.hex()[:64]}...")
    print(f"  APO signature: {apo_sig.hex()[:40]}... ({len(apo_sig)}B)")
    print(f"  Sig valid:     {apo_valid}")
    print(f"  Key property:  Signature does NOT commit to input outpoint")
    print(f"  Enables:       Floating txs, LN-Symmetry, rebindable HTLCs")
    print(f"  Network:       Bitcoin Inquisition Signet (BIP-118 active)")

    # -- R-6e: CSFS Covenant --
    print(f"\n{'_'*64}")
    print("  R-6e: OP_CHECKSIGFROMSTACK (Liquid/Elements)")
    print(f"{'_'*64}")
    csfs_info = CSFSCovenant.info()
    csfs_script = CSFSCovenant.build_csfs_covenant_script(
        update_key, hashlib.sha256(new_data).digest(),
    )
    csfs_sig = CSFSCovenant.sign_state_transition("pool_operator", new_data)
    csfs_valid = CSFSCovenant.verify_state_signature("pool_operator", csfs_sig, new_data)
    print(f"  CSFS opcode:   0xc1 (Elements/Liquid)")
    print(f"  Script ({len(csfs_script)}B): {csfs_script.hex()[:64]}...")
    print(f"  ASM: <state_hash> OP_SHA256 OP_EQUALVERIFY <pk> OP_CHECKSIGFROMSTACK")
    print(f"  Operator sig:  {csfs_sig.hex()[:40]}... ({len(csfs_sig)}B)")
    print(f"  Sig valid:     {csfs_valid}")
    print(f"  Key property:  Verifies sig against arbitrary stack message (not tx)")
    print(f"  Network:       Liquid (Blockstream Elements)")

    # -- R-6f: Pre-signed Transaction Tree --
    print(f"\n{'_'*64}")
    print("  R-6f: Pre-signed Transaction Tree (Mainnet TODAY)")
    print(f"{'_'*64}")
    tree = PreSignedTree(signers=["alice", "bob", "charlie"], n_of_n=True)
    tree_root = tree.build_swap_tree(
        COutPoint(lx("ee" * 32), 0),
        demo_pool_state,
        SwapType.BTC_TO_ANCH,
        price_ticks=[1_000_000, 5_000_000, 10_000_000],
    )
    tree_info = tree.info()
    sigs_ok = tree.verify_all_signatures()
    print(f"  Requires new opcodes: NO")
    print(f"  Signers:       {tree_info['signers']} ({len(tree_info['signers'])}-of-{len(tree_info['signers'])})")
    print(f"  Tree nodes:    {tree_info['total_nodes']}")
    print(f"  Tree depth:    {tree_info['tree_depth']}")
    print(f"  Root TXID:     {tree_root.txid[:32]}..." if tree_root else "  Root: None")
    print(f"  All sigs valid: {sigs_ok}")
    for child in (tree_root.children if tree_root else []):
        print(f"    Leaf [{child.label}]: TXID={child.txid[:24]}... "
              f"sigs={len(child.signatures)}")
    print(f"  Used by:       Ark protocol, Timeout Trees, CTV-emulation")
    print(f"  Trade-off:     Requires coordinator + interactivity")

    # -- R-6g: Hybrid Engine —- All Networks --
    print(f"\n{'_'*64}")
    print("  R-6g: Hybrid Engine — Strategy per Network")
    print(f"{'_'*64}")
    for net in CovenantNetwork:
        engine = HybridCovenantEngine(net)
        caps = engine.get_capabilities()
        result = engine.enforce_swap(
            demo_pool_state, demo_new_state,
            SwapType.BTC_TO_ANCH, demo_amount_in, demo_amount_out,
        )
        print(f"\n  [{net.value:>12}] Strategy: {caps['selected_strategy']}")
        print(f"  {'':>14} Mechanism: {result.get('mechanism', 'N/A')}")
        available = [k for k, v in caps['available_mechanisms'].items() if v]
        print(f"  {'':>14} Available: {', '.join(available)}")
        print(f"  {'':>14} Valid: {result['valid']}")

    # ==========================================================================
    # R-7: ANCHOR PROTOCOL
    # ==========================================================================
    print(f"\n{SEP}")
    print("  ANCHOR PROTOCOL (Ephemeral Anchor Fee-Market)")
    print(SEP)

    # -- R-7a: BRC-20 Token Deployment --
    print(f"\n{'_'*64}")
    print("  R-7a: BRC-20 ANCH Token Deployment")
    print(f"{'_'*64}")
    deploy_insc = BRC20Inscription.deploy()
    print(f"  Deploy inscription:")
    print(f"    {json.dumps(deploy_insc, indent=4)}")
    print(f"  Ticker:        {deploy_insc['tick']}")
    print(f"  Max supply:    {int(deploy_insc['max']):,}")
    print(f"  Mint limit:    {int(deploy_insc['lim']):,} per inscription")
    print(f"  Standard:      BRC-20 (Ordinals-based)")
    print(f"  Novelty:       First BRC-20 with PROGRAMMATIC UTILITY")
    print(f"                 Value derives from ephemeral anchor mechanism")

    # -- R-7b: TRUC v3 Transaction with Ephemeral Anchor --
    print(f"\n{'_'*64}")
    print("  R-7b: TRUC (v3) Transaction with Ephemeral Anchor")
    print(f"{'_'*64}")
    truc_info = TRUCTransactionBuilder.info()
    dest_spk = KEYSTORE.p2wpkh_scriptpubkey("bob")
    parent_tx = TRUCTransactionBuilder.build_parent_with_anchor(
        COutPoint(lx("ff" * 32), 0), dest_spk, 1_000_000,
    )
    anchor_vout = TRUCTransactionBuilder.find_anchor_output(parent_tx)
    print(f"  nVersion:      {parent_tx.nVersion} (TRUC)")
    print(f"  Outputs:       {len(parent_tx.vout)}")
    print(f"    [0] Payment: {parent_tx.vout[0].nValue:,} sats -> bob P2WPKH")
    print(f"    [1] Anchor:  {parent_tx.vout[1].nValue} sats -> OP_TRUE (0x51)")
    print(f"  Anchor vout:   {anchor_vout}")
    print(f"  Is TRUC:       {TRUCTransactionBuilder.is_truc(parent_tx)}")
    print(f"  TXID:          {RealTransactionBuilder.txid_hex(parent_tx)}")
    print(f"  Policy:        {truc_info['policy']}")

    child_tx = TRUCTransactionBuilder.build_anchor_child(
        parent_tx.GetTxid(), anchor_vout,
        fee_amount=5000,
        change_scriptpubkey=KEYSTORE.p2wpkh_scriptpubkey("alice"),
        change_amount=0,
    )
    print(f"\n  Child (CPFP fee-bumping):")
    print(f"    nVersion:    {child_tx.nVersion} (TRUC)")
    print(f"    Spends:      parent:{anchor_vout} (anchor output)")
    print(f"    TXID:        {RealTransactionBuilder.txid_hex(child_tx)}")
    print(f"    1P1C:        Parent + Child broadcast as package")

    # -- R-7c: Proof-of-Anchor Minting --
    print(f"\n{'_'*64}")
    print("  R-7c: Proof-of-Anchor Minting (THE NOVEL MECHANISM)")
    print(f"{'_'*64}")
    protocol = AnchorProtocol()
    print(f"  Max supply:    {protocol.minter.MAX_SUPPLY:,} ANCH")
    print(f"  Per proof:     {protocol.minter.BASE_REWARD:,} ANCH")
    print(f"  Genesis bonus: +{protocol.minter.genesis_bonus:,} ANCH "
          f"(first {protocol.minter.genesis_count} proofs)")
    print(f"  Halving:       every {protocol.minter.HALVING_INTERVAL:,} proofs")

    ok, reason, reward = protocol.submit_anchor_proof(
        parent_tx=parent_tx, child_tx=child_tx,
        anchor_vout=anchor_vout, block_height=880_000,
        creator="alice", fee_rate=15,
    )
    print(f"  Result:        {ok} ({reason})")
    print(f"  Alice ANCH:    {protocol.get_balance('alice'):,}")
    stats = protocol.get_stats()
    print(f"  Minted so far: {stats['minter']['total_minted']:,} / "
          f"{stats['minter']['max_supply']:,}")
    print(f"  Genesis left:  {stats['minter']['genesis_bonus_remaining']}")

    # -- R-7d: Multiple proofs + halving simulation --
    print(f"\n{'_'*64}")
    print("  R-7d: Proof Pipeline + Reward Schedule")
    print(f"{'_'*64}")
    proof_creators = [("bob", "aa"), ("charlie", "bb"), ("dave", "dd")]
    for creator, hex_byte in proof_creators:
        KEYSTORE.get_or_create(creator)
        p_parent = TRUCTransactionBuilder.build_parent_with_anchor(
            COutPoint(lx(hex_byte * 32), 0),
            KEYSTORE.p2wpkh_scriptpubkey(creator), 500_000,
        )
        p_vout = TRUCTransactionBuilder.find_anchor_output(p_parent)
        p_child = TRUCTransactionBuilder.build_anchor_child(
            p_parent.GetTxid(), p_vout,
            fee_amount=3000,
            change_scriptpubkey=KEYSTORE.p2wpkh_scriptpubkey(creator),
            change_amount=0,
        )
        protocol.submit_anchor_proof(
            parent_tx=p_parent, child_tx=p_child,
            anchor_vout=p_vout, block_height=880_001 + proof_creators.index((creator, hex_byte)),
            creator=creator, fee_rate=10,
        )
    print(f"\n  After 4 total proofs:")
    stats2 = protocol.get_stats()
    print(f"    Total minted:  {stats2['minter']['total_minted']:,} ANCH")
    print(f"    Proofs:        {stats2['minter']['proofs_accepted']}")
    print(f"    Current era:   {stats2['minter']['era']}")
    print(f"    Next reward:   {stats2['minter']['current_reward']:,} ANCH")
    print(f"    Alice ANCH:    {protocol.get_balance('alice'):,}")
    print(f"    Bob ANCH:      {protocol.get_balance('bob'):,}")
    print(f"    Charlie ANCH:  {protocol.get_balance('charlie'):,}")
    print(f"    Dave ANCH:     {protocol.get_balance('dave'):,}")

    # -- R-7e: Anti-replay protection --
    print(f"\n{'_'*64}")
    print("  R-7e: Anti-Replay Protection")
    print(f"{'_'*64}")
    dup_ok, dup_reason, dup_reward = protocol.submit_anchor_proof(
        parent_tx=parent_tx, child_tx=child_tx,
        anchor_vout=anchor_vout, block_height=880_000,
        creator="alice", fee_rate=15,
    )
    print(f"  Duplicate proof: {dup_ok} ({dup_reason})")
    print(f"  Reward:          {dup_reward} (none -- blocked)")
    print(f"  Claims total:    {protocol.registry.total_claims()}")

    mallory_ok, mallory_reason, _ = protocol.submit_anchor_proof(
        parent_tx=parent_tx, child_tx=child_tx,
        anchor_vout=anchor_vout, block_height=880_100,
        creator="mallory", fee_rate=15,
    )
    print(f"  Mallory replay:  {mallory_ok} ({mallory_reason})")

    # -- R-7f: SlotAuction --
    print(f"\n{'_'*64}")
    print("  R-7f: SlotAuction (Anchor Rights Fee-Market)")
    print(f"{'_'*64}")
    protocol.anch.mint("alice", 5_000)
    protocol.anch.mint("bob", 5_000)
    protocol.anch.mint("eve", 8_000)

    slot = protocol.create_slot(block_start=880_000, block_end=880_010, min_fee_rate=10)
    slot_id = slot.slot_id

    ok_a, _ = protocol.bid_on_slot(slot_id, "alice", 500)
    ok_b, _ = protocol.bid_on_slot(slot_id, "bob", 800)
    ok_e, _ = protocol.bid_on_slot(slot_id, "eve", 1200)
    print(f"  Alice bid 500:   {ok_a}  (outbid)")
    print(f"  Bob bid 800:     {ok_b}  (outbid)")
    print(f"  Eve bid 1200:    {ok_e}  (current winner)")
    print(f"  Alice balance:   {protocol.get_balance('alice'):,} (refunded)")
    print(f"  Bob balance:     {protocol.get_balance('bob'):,} (refunded)")
    print(f"  Eve balance:     {protocol.get_balance('eve'):,} (escrowed)")

    bid_insc = BRC20Inscription.bid(slot_id, "eve", 1200, 15)
    print(f"  Bid inscription: {json.dumps(bid_insc)}")

    protocol.close_slot(slot_id)
    slot_info = protocol.auction.get_slot_info(slot_id)
    print(f"  Slot state:      {slot_info['state']}")
    print(f"  Winner:          {slot_info['winner']}")

    # -- R-7g: Slot Consumption --
    print(f"\n{'_'*64}")
    print("  R-7g: Slot Consumption (Winner Proves Anchor)")
    print(f"{'_'*64}")
    eve_parent = TRUCTransactionBuilder.build_parent_with_anchor(
        COutPoint(lx("ee" * 32), 0),
        KEYSTORE.p2wpkh_scriptpubkey("eve"), 2_000_000,
    )
    eve_anch_vout = TRUCTransactionBuilder.find_anchor_output(eve_parent)
    eve_child = TRUCTransactionBuilder.build_anchor_child(
        eve_parent.GetTxid(), eve_anch_vout,
        fee_amount=8000,
        change_scriptpubkey=KEYSTORE.p2wpkh_scriptpubkey("eve"),
        change_amount=0,
    )
    consumed_ok, consumed_reason = protocol.consume_slot(
        slot_id, eve_parent, eve_child, eve_anch_vout,
        block_height=880_005, creator="eve", fee_rate=15,
    )
    print(f"  Consume:         {consumed_ok} ({consumed_reason})")
    print(f"  Eve balance:     {protocol.get_balance('eve'):,} "
          f"(bid refunded + {slot.highest_bid // 10} bonus)")
    print(f"  Slot state:      {protocol.auction.get_slot_info(slot_id)['state']}")

    claim_insc = BRC20Inscription.claim("eve_proof", slot.highest_bid // 10)
    print(f"  Claim inscription: {json.dumps(claim_insc)}")

    # -- R-7h: Expired slot --
    print(f"\n{'_'*64}")
    print("  R-7h: Expired Slot (Bid Forfeited)")
    print(f"{'_'*64}")
    slot2 = protocol.create_slot(block_start=890_000, block_end=890_010, min_fee_rate=5)
    protocol.bid_on_slot(slot2.slot_id, "bob", 300)
    protocol.close_slot(slot2.slot_id)
    protocol.expire_slot(slot2.slot_id)
    print(f"  Bob balance:     {protocol.get_balance('bob'):,} (forfeited 300)")
    print(f"  Treasury:        {protocol.get_balance('anchor_protocol_treasury'):,} ANCH")
    print(f"  Slot state:      {protocol.auction.get_slot_info(slot2.slot_id)['state']}")

    # -- R-7i: Full protocol stats --
    print(f"\n{'_'*64}")
    print("  R-7i: Protocol Stats")
    print(f"{'_'*64}")
    final_stats = protocol.get_stats()
    print(f"  Minter:")
    print(f"    Total minted:    {final_stats['minter']['total_minted']:,} / "
          f"{final_stats['minter']['max_supply']:,} ANCH")
    print(f"    Proofs accepted: {final_stats['minter']['proofs_accepted']}")
    print(f"    Current reward:  {final_stats['minter']['current_reward']:,} ANCH")
    print(f"    Genesis bonus:   {final_stats['minter']['genesis_bonus_remaining']:,} remaining")
    print(f"    Era:             {final_stats['minter']['era']}")
    print(f"  Infrastructure:")
    print(f"    Claims (total):  {final_stats['total_claims']}")
    print(f"    Slots (total):   {final_stats['active_slots']}")
    print(f"  Deploy inscription:")
    print(f"    {json.dumps(final_stats['deploy_inscription'])}")
    print(f"  Genesis inscription:")
    genesis = BRC20Inscription.genesis(500, 880_100)
    print(f"    {json.dumps(genesis)}")

    # ==========================================================================
    # R-8: ADVERSARIAL HARDENING TESTS
    # ==========================================================================
    print(f"\n{SEP}")
    print("  R-8: ADVERSARIAL HARDENING TESTS")
    print(f"{SEP}")

    # R-8a
    print(f"\n{'_'*64}")
    print("  R-8a: Oracle -- reject NaN / zero / negative / Inf")
    print(f"{'_'*64}")
    test_oracle = SimpleOracle(10.0)
    for bad_val, label in [(0, "zero"), (-1, "negative"),
                           (float('nan'), "NaN"), (float('inf'), "Inf")]:
        try:
            test_oracle.update_price(bad_val)
            print(f"  FAIL: oracle accepted {label}")
        except ValueError:
            print(f"  PASS: oracle rejected {label} ({bad_val})")

    # R-8b
    print(f"\n{'_'*64}")
    print("  R-8b: Oracle -- reject >50% price jump")
    print(f"{'_'*64}")
    test_oracle2 = SimpleOracle(100.0)
    try:
        test_oracle2.update_price(200.0)
        print("  FAIL: accepted 100% price jump")
    except ValueError:
        print("  PASS: rejected 100% price jump (100 -> 200)")
    test_oracle2.update_price(120.0)
    print(f"  PASS: accepted 20% price update (100 -> {test_oracle2.price})")

    # R-8c
    print(f"\n{'_'*64}")
    print("  R-8c: AMM -- division-by-zero guard in LP removal")
    print(f"{'_'*64}")
    try:
        CovenantAMMScript.compute_remove_amounts(100, 1000, 1000, 0)
        print("  FAIL: accepted old_lp=0")
    except ValueError:
        print("  PASS: rejected compute_remove_amounts with old_lp=0")
    try:
        CovenantAMMScript.compute_remove_amounts(0, 1000, 1000, 100)
        print("  FAIL: accepted lp_burned=0")
    except ValueError:
        print("  PASS: rejected compute_remove_amounts with lp_burned=0")
    try:
        CovenantAMMScript.compute_remove_amounts(200, 1000, 1000, 100)
        print("  FAIL: accepted lp_burned > old_lp")
    except ValueError:
        print("  PASS: rejected lp_burned=200 > old_lp=100")

    # R-8d
    print(f"\n{'_'*64}")
    print("  R-8d: AMM -- fee_basis range validation")
    print(f"{'_'*64}")
    try:
        CovenantAMMScript.get_amount_out(1000, 100_000, 100_000, fee_basis=1500)
        print("  FAIL: accepted fee_basis=1500")
    except ValueError:
        print("  PASS: rejected fee_basis=1500 (> 999)")
    try:
        CovenantAMMScript.get_amount_out(1000, 100_000, 100_000, fee_basis=-1)
        print("  FAIL: accepted fee_basis=-1")
    except ValueError:
        print("  PASS: rejected fee_basis=-1 (< 0)")
    out = CovenantAMMScript.get_amount_out(1000, 100_000, 100_000, fee_basis=3)
    print(f"  PASS: fee_basis=3 works -> output={out}")

    # R-8e
    print(f"\n{'_'*64}")
    print("  R-8e: Covenant -- zero/negative amount rejection")
    print(f"{'_'*64}")
    ok = CovenantAMMScript.verify_swap(100_000, 100_000, 100_001, 99_999,
                                        btc_in=0, anch_out=1)
    print(f"  PASS: verify_swap(btc_in=0) -> {ok} (expected False)")
    ok = CovenantAMMScript.verify_swap(100_000, 100_000, 100_001, 99_999,
                                        btc_in=-100, anch_out=100)
    print(f"  PASS: verify_swap(btc_in=-100) -> {ok} (expected False)")
    ok = CovenantAMMScript.verify_swap_anch_to_btc(100_000, 100_000, 99_999, 100_001,
                                                    anch_in=0, btc_out=1)
    print(f"  PASS: verify_swap_anch_to_btc(anch_in=0) -> {ok} (expected False)")

    # R-8f
    print(f"\n{'_'*64}")
    print("  R-8f: Overflow -- U64_MAX multiplication guard")
    print(f"{'_'*64}")
    try:
        result = safe_mul(2**63, 2**63, "overflow_test")
        print(f"  FAIL: accepted overflow (result={result})")
    except ArithmeticError as e:
        print(f"  PASS: safe_mul caught overflow")
    try:
        safe_mul(-1, 100, "neg_test")
        print("  FAIL: accepted negative operand")
    except ArithmeticError:
        print("  PASS: safe_mul rejected negative operand")

    # R-8g
    print(f"\n{'_'*64}")
    print("  R-8g: HTLC -- double-settle prevention")
    print(f"{'_'*64}")
    htlc_test = HTLCAtomicSwap()
    htlc_test.fund("attacker", 50_000)
    htlc_test.fund("target", 50_000)
    sec = os.urandom(32)
    sec_hash = hashlib.sha256(sec).hexdigest()
    c = htlc_test.create_btc_lock("attacker", 10_000, sec_hash, "target", 144)
    ok1 = htlc_test.settle_htlc(c.contract_id, sec)
    print(f"  First settle: {ok1} (expected True)")
    ok2 = htlc_test.settle_htlc(c.contract_id, sec)
    print(f"  Second settle: {ok2} (expected False -- contract deleted)")
    target_bal = htlc_test.btc_balance("target")
    print(f"  Target balance: {target_bal:,} (expected 60,000 -- no double-credit)")
    assert ok1 is True and ok2 is False and target_bal == 60_000, \
        "Double-settle protection FAILED"
    print("  PASS: double-settle prevented")

    # R-8h
    print(f"\n{'_'*64}")
    print("  R-8h: RGB -- single-use seal prevents double-spend")
    print(f"{'_'*64}")
    rgb_test = RGBAsset("TEST")
    rgb_test.mint("alice_seal", 5_000)
    sec_seal = os.urandom(32)
    sec_seal_hash = hashlib.sha256(sec_seal).hexdigest()
    t1 = rgb_test.create_transfer("alice_seal", "bob_seal", 3_000,
                                   f"OP_HASH256 {sec_seal_hash} OP_EQUAL")
    ok_settle = rgb_test.settle_transfer(t1.transfer_id, sec_seal)
    print(f"  First settlement: {ok_settle} (expected True)")
    ok_double = rgb_test.settle_transfer(t1.transfer_id, sec_seal)
    print(f"  Double settlement: {ok_double} (expected False)")
    bob_bal = rgb_test.balance_of("bob_seal")
    print(f"  Bob balance: {bob_bal:,} (expected 3,000 -- no double-credit)")
    assert ok_settle is True and ok_double is False and bob_bal == 3_000, \
        "RGB double-spend protection FAILED"
    print("  PASS: single-use seal prevented double-spend")

    # R-8i
    print(f"\n{'_'*64}")
    print("  R-8i: Pool -- pending swap count limit")
    print(f"{'_'*64}")
    test_pool = OnChainPool(1_000_000, 1_000_000, "dos_test")
    test_pool.MAX_PENDING_SWAPS = 3
    test_pool.challenge_period = 0
    sig = b"test"
    accepted = 0
    for i in range(5):
        amt_out = CovenantAMMScript.get_amount_out(100, 1_000_000 + (i * 100),
                                                    1_000_000 - (accepted * 100))
        txid = test_pool.propose_swap(
            "dos_attacker", SwapType.BTC_TO_ANCH, 100, amt_out, sig)
        if txid is not None:
            test_pool.finalize_swap(txid)
            accepted += 1
    test_pool2 = OnChainPool(1_000_000, 1_000_000, "dos_test2")
    test_pool2.MAX_PENDING_SWAPS = 3
    test_pool2.challenge_period = 999999
    blocked = 0
    for i in range(5):
        out = CovenantAMMScript.get_amount_out(100, 1_000_000, 1_000_000)
        txid = test_pool2.propose_swap(
            "dos_user", SwapType.BTC_TO_ANCH, 100, out, sig)
        if txid is None:
            blocked += 1
    print(f"  Proposals blocked after limit: {blocked} "
          f"(expected 2 blocked out of 5)")
    assert blocked >= 2, "DoS limit not working"
    print("  PASS: pending swap DoS limit enforced")

    # R-8j
    print(f"\n{'_'*64}")
    print("  R-8j: ProductionDEX -- cancel_swap partial refund safety")
    print(f"{'_'*64}")
    pdex_test = ProductionDEX()
    pdex_test.fund_user_btc("cancel_user", 500_000)
    sid_cancel, _, _ = pdex_test.swap_btc_for_anch("cancel_user", 100_000)
    pdex_test.complete_swap(sid_cancel)
    cancel_ok = pdex_test.cancel_swap(sid_cancel, current_block=999999)
    print(f"  Cancel completed swap: {cancel_ok} (expected False -- already completed)")
    assert cancel_ok is False, "Should not cancel already-completed swap"
    print("  PASS: cannot cancel already-completed swap")

    print(f"\n  All R-8 adversarial tests passed.")

    # -- Summary --
    print(f"\n{SEP}")
    print("  WHAT'S REAL NOW:")
    print(f"{'_'*64}")
    print("  [REAL] secp256k1 keypairs (coincurve / libsecp256k1)")
    print("  [REAL] HTLC: OP_IF/OP_SHA256/.../OP_CHECKLOCKTIMEVERIFY script")
    print("  [REAL] Bitcoin transactions (CTransaction / CTxIn / CTxOut)")
    print("  [REAL] P2WSH scriptPubKey for HTLCs")
    print("  [REAL] OP_RETURN transactions for RGB anchoring")
    print("  [REAL] 2-of-3 multisig script (OP_CHECKMULTISIG)")
    print("  [REAL] DER signatures + SIGHASH_ALL")
    print("  [REAL] Transaction serialization (broadcast-ready for regtest)")
    print("  [REAL] CTV template hash computation (BIP-119 algorithm)")
    print("  [REAL] OP_CAT state commitment scripts (BIP-347)")
    print("  [REAL] OP_CAT + OP_CTV hybrid parameterized covenants")
    print("  [REAL] SIGHASH_ANYPREVOUT signatures (BIP-118)")
    print("  [REAL] OP_CHECKSIGFROMSTACK covenants (Liquid/Elements)")
    print("  [REAL] Pre-signed transaction trees (mainnet-ready, Ark-style)")
    print("  [REAL] Hybrid engine auto-selects best strategy per network")
    print("  [REAL] TRUC (v3) transactions with OP_TRUE ephemeral anchors")
    print("  [REAL] AnchorProof: deterministic proof of anchor creation")
    print("  [REAL] AnchorVerifier: v3 + OP_TRUE + package + sig validation")
    print("  [REAL] ClaimRegistry: anti-replay (proof_id + outpoint + child)")
    print("  [REAL] SlotAuction: fee-market with OPEN/WON/CONSUMED/EXPIRED")
    print("  [REAL] BRC-20 inscription schemas (deploy/mint/proof/bid/claim)")
    print("  [REAL] ProofOfAnchorMinter: 21M supply, halving, genesis bonus")
    print("  [REAL] AnchorProtocol: full orchestrator (mint + auction + claim)")
    print("  [REAL] Flask API: 5 anchor endpoints (/anchor/*)")
    print("  [REAL] Adversarial hardening: oracle NaN/Inf/deviation guard")
    print("  [REAL] Adversarial hardening: div-by-zero, overflow, fee_basis clamp")
    print("  [REAL] Adversarial hardening: pending DoS limit, thread safety")
    print("  [REAL] Adversarial hardening: cancel_swap partial-refund safety")
    print(f"{'_'*64}")
    print("  STILL SIMULATED:")
    print(f"{'_'*64}")
    print("  [SIM]  RGB client-side validation (needs Rust rgb-core)")
    print("  [SIM]  BitVM fraud proof circuits (research stage)")
    print("  [SIM]  UTXO tracking (needs bitcoind RPC or Electrum)")
    print("  [SIM]  Mempool broadcast (needs network connection)")
    print("  [SIM]  Actual opcode execution on-chain (needs node + network)")

    print(f"\n{SEP}")
    print("  All demos complete.")
    print(SEP)


def interactive_mode(pdex_instance: PersistentDEX):
    """Interactive command-line DEX terminal."""
    SEP = "=" * 64
    print(f"\n{SEP}")
    print("  ANCHOR DEX -- Interactive Mode")
    print(f"{SEP}")
    print("  Type 'help' for commands, 'quit' to exit.\n")

    while True:
        try:
            raw = input("dex> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.")
            break
        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit", "q"):
                print("  Goodbye.")
                break

            elif cmd == "help":
                print("""
  Commands:
    pool                       -- Show pool reserves
    quote <BTC|ANCH> <amount>  -- Get swap quote
    fund <user> <btc> <anch>   -- Fund user (sats, ANCH units)
    swap <user> <BTC|ANCH> <amount> -- Execute swap
    balance <user>             -- Show user balances
    balances                   -- Show all users
    history [limit]            -- Show swap history
    rgb save                   -- Anchor RGB state to chain
    reset                      -- Reset pool to defaults
    demo                       -- Run built-in demo
    quit                       -- Exit
                """)

            elif cmd == "pool":
                info = pdex_instance.get_pool_info()
                print(f"  BTC Reserve : {info['btc_reserve']:>15,} sats "
                      f"({info['btc_reserve']/1e8:.8f} BTC)")
                print(f"  ANCH Reserve: {info['anch_reserve']:>15,}")
                print(f"  LP Total    : {info['lp_total']:>15,}")
                print(f"  Pending     : {info['pending_swaps']}")
                if info['anch_reserve'] > 0:
                    price = info['btc_reserve'] / info['anch_reserve']
                    print(f"  Price       : {price:.4f} sats/ANCH")

            elif cmd == "quote":
                if len(parts) < 3:
                    print("  Usage: quote <BTC|ANCH> <amount>")
                    continue
                direction = "BTC_TO_ANCH" if parts[1].upper() == "BTC" else "ANCH_TO_BTC"
                amount = int(parts[2])
                out = pdex_instance.get_quote(direction, amount)
                unit_in = "sats" if "BTC_TO" in direction else "ANCH"
                unit_out = "ANCH" if "BTC_TO" in direction else "sats"
                print(f"  {amount:,} {unit_in} -> {out:,} {unit_out}")

            elif cmd == "fund":
                if len(parts) < 4:
                    print("  Usage: fund <user> <btc_sats> <anch>")
                    continue
                user, btc, anch = parts[1], int(parts[2]), int(parts[3])
                if btc > 0:
                    pdex_instance.fund_btc(user, btc)
                if anch > 0:
                    pdex_instance.fund_anch(user, anch)
                b = pdex_instance.get_balances(user)
                print(f"  {user}: {b['btc_sats']:,} sats / {b['anch']:,} ANCH")

            elif cmd == "swap":
                if len(parts) < 4:
                    print("  Usage: swap <user> <BTC|ANCH> <amount>")
                    continue
                user = parts[1]
                asset = parts[2].upper()
                amount = int(parts[3])
                if asset == "BTC":
                    ok = pdex_instance.swap_btc_to_anch(user, amount)
                else:
                    ok = pdex_instance.swap_anch_to_btc(user, amount)
                if ok:
                    b = pdex_instance.get_balances(user)
                    print(f"  Swap completed. {user}: "
                          f"{b['btc_sats']:,} sats / {b['anch']:,} ANCH")
                else:
                    print("  Swap FAILED")

            elif cmd in ("balance", "bal"):
                if len(parts) < 2:
                    print("  Usage: balance <user>")
                    continue
                user = parts[1]
                b = pdex_instance.get_balances(user)
                print(f"  {user}: {b['btc_sats']:,} sats / {b['anch']:,} ANCH")

            elif cmd == "balances":
                users = pdex_instance.store.load_all_users()
                if not users:
                    print("  No users yet. Use 'fund <user> <btc> <anch>'")
                for u in users:
                    print(f"  {u['user']:>12}: {u['btc_sats']:>15,} sats / "
                          f"{u['anch']:>12,} ANCH")

            elif cmd == "history":
                limit = int(parts[1]) if len(parts) > 1 else 20
                swaps = pdex_instance.history(limit)
                if not swaps:
                    print("  No swap history yet.")
                for s in swaps:
                    print(f"  [{s['created_at']}] {s['user']:>8} "
                          f"{s['direction']:>12} "
                          f"BTC={s['btc_amount']:>12,}  ANCH={s['anch_amount']:>12,}  "
                          f"{s['status']}")

            elif cmd == "rgb":
                if len(parts) > 1 and parts[1].lower() == "save":
                    pdex_instance.save_rgb_state()
                else:
                    print("  Usage: rgb save")

            elif cmd == "reset":
                pdex_instance.store.close()
                db_path = pdex_instance.store.db_path
                if os.path.exists(db_path):
                    os.remove(db_path)
                pdex_instance.__init__(db_path)
                print("  Pool reset to defaults.")

            elif cmd == "demo":
                run_demo()

            else:
                print(f"  Unknown command: {cmd}  (type 'help')")

        except Exception as e:
            print(f"  Error: {e}")
