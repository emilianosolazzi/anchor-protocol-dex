"""
OnChainPool -- the on-chain AMM pool (simulated).

Represents a pool UTXO with a Taproot covenant that enforces
AMM rules via the HybridCovenantEngine.
"""
from __future__ import annotations

import hashlib
import time
from typing import Dict, Optional

from .state import (
    PoolState, SwapType, LiquidityType, LiquidityChange,
    FraudProof, PendingSwap, StateCommitment,
)
from .covenant_amm import CovenantAMMScript
from ..covenants.opcodes import sha256
from ..covenants.engine import HybridCovenantEngine
from ..covenants.opcodes import CovenantNetwork
from ..crypto.keys import KEYSTORE


class OnChainPool:
    """
    Represents a pool UTXO with a Taproot covenant that enforces AMM rules.
    """
    MAX_PENDING_SWAPS = 1000      # DoS guard
    MAX_PENDING_LIQUIDITY = 100   # DoS guard

    def __init__(self, btc_reserve: int, anch_reserve: int, owner: str,
                 network: CovenantNetwork = CovenantNetwork.REGTEST):
        self.state = PoolState(
            btc_reserve=btc_reserve,
            anch_reserve=anch_reserve,
            lp_total=0,
            taproot_address="",
            script_merkle_root=b'',
        )
        self.owner = owner
        self.network = network
        self.challenge_period = 144  # blocks (~1 day)
        self.pending_swaps: Dict[str, PendingSwap] = {}
        self.pending_liquidity: Dict[str, LiquidityChange] = {}
        self._seq: int = 0
        self._bonds: Dict[str, int] = {}
        self._lp_ledger: Dict[str, int] = {}
        self.covenant_engine = HybridCovenantEngine(network)
        self._generate_taproot_address()

    # ------------------------------------------------------------------
    def _generate_taproot_address(self):
        internal_key = KEYSTORE.pubkey(self.owner)
        leaves = [
            self._create_swap_leaf(SwapType.BTC_TO_ANCH),
            self._create_swap_leaf(SwapType.ANCH_TO_BTC),
            self._create_liquidity_leaf(),
            self._create_remove_liquidity_leaf(),
            self._create_challenge_leaf(),
        ]
        leaf_hashes = [sha256(leaf) for leaf in leaves]
        merkle_root = leaf_hashes[0]
        for h in leaf_hashes[1:]:
            merkle_root = sha256(merkle_root + h)
        self.state.script_merkle_root = merkle_root
        tweak = sha256(internal_key + merkle_root)
        tweaked_key = sha256(internal_key + tweak)
        addr_hash = hashlib.sha256(tweaked_key).hexdigest()[:40]
        self.state.taproot_address = f"bcrt1p{addr_hash}"
        self._internal_pubkey = internal_key
        self._tweaked_key = tweaked_key

    def _create_swap_leaf(self, swap_type: SwapType) -> bytes:
        return b'SWAP_LEAF_' + swap_type.name.encode()

    def _create_liquidity_leaf(self) -> bytes:
        return b'LIQUIDITY_LEAF_ADD'

    def _create_remove_liquidity_leaf(self) -> bytes:
        return b'LIQUIDITY_LEAF_REMOVE'

    def _create_challenge_leaf(self) -> bytes:
        return b'CHALLENGE_LEAF'

    def _current_block(self) -> int:
        return int(time.time() / 600)

    def _proposal_block(self, timestamp: float) -> int:
        return int(timestamp / 600)

    def _make_new_state(self, new_btc: int, new_anch: int) -> PoolState:
        return PoolState(
            btc_reserve=new_btc,
            anch_reserve=new_anch,
            lp_total=self.state.lp_total,
            taproot_address=self.state.taproot_address,
            script_merkle_root=self.state.script_merkle_root,
        )

    # -- Bond management (FIX #5) --
    def _lock_bond(self, addr: str, amount: int):
        self._bonds[addr] = self._bonds.get(addr, 0) + amount

    def _release_bond(self, addr: str, amount: int):
        self._bonds[addr] = max(0, self._bonds.get(addr, 0) - amount)

    def _slash_bond(self, from_addr: str, to_addr: str, amount: int):
        self._bonds[from_addr] = max(0, self._bonds.get(from_addr, 0) - amount)
        self._bonds[to_addr] = self._bonds.get(to_addr, 0) + amount
        print(f"  [BOND] Slashed {amount:,} sats from {from_addr[:12]}... "
              f"-> rewarded {to_addr[:12]}...")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def propose_swap(
        self,
        user: str,
        swap_type: SwapType,
        amount_in: int,
        amount_out: int,
        signature: bytes,
        min_amount_out: int = 0,
    ) -> Optional[str]:
        if len(self.pending_swaps) >= self.MAX_PENDING_SWAPS:
            print(f"  [POOL] Too many pending swaps ({self.MAX_PENDING_SWAPS}); "
                  f"rejecting proposal")
            return None

        if swap_type == SwapType.BTC_TO_ANCH:
            new_btc = self.state.btc_reserve + amount_in
            new_anch = self.state.anch_reserve - amount_out
        else:
            new_btc = self.state.btc_reserve - amount_out
            new_anch = self.state.anch_reserve + amount_in

        new_state = self._make_new_state(new_btc, new_anch)

        witness = CovenantAMMScript.build_witness_elements(
            swap_type, amount_in, amount_out, signature,
            min_amount_out=min_amount_out,
            old_seq=self._seq,
        )

        if not CovenantAMMScript.execute_covenant(
            self.state, new_state, witness, prev_seq=self._seq
        ):
            print("  Swap rejected by covenant (invariant, slippage, or price impact)")
            return None

        covenant_result = self.covenant_engine.enforce_swap(
            self.state, new_state, swap_type, amount_in, amount_out,
        )
        strategy = covenant_result.get("strategy", "unknown")
        mechanism = covenant_result.get("mechanism", "")
        print(f"  [HYBRID COVENANT] Strategy: {strategy}")
        print(f"  [HYBRID COVENANT] {mechanism}")
        if "template_hash" in covenant_result:
            print(f"  [HYBRID COVENANT] CTV hash: {covenant_result['template_hash'][:32]}...")
        print(f"  [HYBRID COVENANT] State: {covenant_result['old_state_hash'][:16]}... "
              f"-> {covenant_result['new_state_hash'][:16]}...")

        txid = hashlib.sha256(
            f"{user}{swap_type.name}{amount_in}{amount_out}"
            f"{self._seq}{time.time()}".encode()
        ).hexdigest()

        self.pending_swaps[txid] = PendingSwap(
            old_state=self.state,
            new_state=new_state,
            btc_in=amount_in if swap_type == SwapType.BTC_TO_ANCH else -amount_out,
            anch_delta=-amount_out if swap_type == SwapType.BTC_TO_ANCH else amount_in,
            swap_type=swap_type,
            timestamp=time.time(),
            min_amount_out=min_amount_out,
            old_seq=self._seq,
        )
        print(f"  Swap proposal {txid[:16]}... submitted (seq={self._seq}). "
              f"Challenge window: {self.challenge_period} blocks.")
        return txid

    def challenge_swap(
        self,
        txid: str,
        challenger: str,
        fraud_proof: FraudProof,
    ) -> bool:
        if txid not in self.pending_swaps:
            print("  No such pending swap")
            return False

        pending = self.pending_swaps[txid]
        blocks_elapsed = self._current_block() - self._proposal_block(pending.timestamp)
        if blocks_elapsed > self.challenge_period:
            print("  Challenge period expired -- swap can be finalised")
            return False

        challenge_age = self._current_block() - self._proposal_block(fraud_proof.submitted_at)
        if challenge_age > fraud_proof.RESPONSE_WINDOW:
            print(f"  Challenger {challenger[:12]}... exceeded response window "
                  f"({challenge_age} > {fraud_proof.RESPONSE_WINDOW} blocks) -- ignored")
            return False

        self._lock_bond(challenger, fraud_proof.bond)
        pending.challenges.append(fraud_proof)

        old = pending.old_state
        new = pending.new_state

        if pending.swap_type == SwapType.BTC_TO_ANCH:
            btc_in = new.btc_reserve - old.btc_reserve
            anch_out = old.anch_reserve - new.anch_reserve
            valid = CovenantAMMScript.verify_swap(
                old.btc_reserve, old.anch_reserve,
                new.btc_reserve, new.anch_reserve,
                btc_in=btc_in, anch_out=anch_out,
                min_amount_out=pending.min_amount_out,
            )
        else:
            anch_in = new.anch_reserve - old.anch_reserve
            btc_out = old.btc_reserve - new.btc_reserve
            valid = CovenantAMMScript.verify_swap_anch_to_btc(
                old.btc_reserve, old.anch_reserve,
                new.btc_reserve, new.anch_reserve,
                anch_in=anch_in, btc_out=btc_out,
                min_amount_out=pending.min_amount_out,
            )

        if not valid:
            self._release_bond(challenger, fraud_proof.bond)
            reward = fraud_proof.bond // 2
            self._bonds[challenger] = self._bonds.get(challenger, 0) + reward
            print(f"  Challenge by {challenger[:12]}... succeeded! "
                  f"Swap {txid[:16]}... removed. "
                  f"Reward: +{reward:,} sats (from proposer penalty).")
            del self.pending_swaps[txid]
            return True
        else:
            self._slash_bond(challenger, "POOL_PENALTY_RESERVE", fraud_proof.bond)
            print(f"  Challenge by {challenger[:12]}... failed -- swap is valid. "
                  f"Bond of {fraud_proof.bond:,} sats slashed.")
            return False

    def finalize_swap(self, txid: str) -> Optional[PoolState]:
        """
        After the challenge period the swap becomes final.

        NOTE: When challenge_period == 0 (BitVMPool instant finality),
        the check passes immediately.  This is intentional.
        """
        if txid not in self.pending_swaps:
            print("  No such pending swap (may have been challenged already)")
            return None

        pending = self.pending_swaps[txid]
        blocks_elapsed = self._current_block() - self._proposal_block(pending.timestamp)
        if blocks_elapsed < self.challenge_period:
            print(f"  Challenge period not yet over "
                  f"({blocks_elapsed}/{self.challenge_period} blocks elapsed)")
            return None

        self.state = pending.new_state
        self._seq += 1
        del self.pending_swaps[txid]
        print(f"  Swap {txid[:16]}... finalised (seq->{self._seq}). "
              f"New reserves -> BTC={self.state.btc_reserve:,} "
              f"ANCH={self.state.anch_reserve:,}")
        return self.state

    def propose_liquidity_change(
        self,
        user: str,
        liq_type: LiquidityType,
        btc_amount: int,
        anch_amount: int,
        signature: bytes,
    ) -> Optional[str]:
        if len(self.pending_liquidity) >= self.MAX_PENDING_LIQUIDITY:
            print(f"  [POOL] Too many pending liquidity changes "
                  f"({self.MAX_PENDING_LIQUIDITY}); rejecting")
            return None

        old = self.state
        if liq_type == LiquidityType.ADD:
            lp_minted = CovenantAMMScript.compute_lp_mint(
                btc_amount, anch_amount,
                old.btc_reserve, old.anch_reserve, old.lp_total,
            )
            new_btc = old.btc_reserve + btc_amount
            new_anch = old.anch_reserve + anch_amount
            new_lp = old.lp_total + lp_minted
            valid = CovenantAMMScript.verify_add_liquidity(
                old.btc_reserve, old.anch_reserve, old.lp_total,
                new_btc, new_anch, new_lp,
                btc_amount, anch_amount, lp_minted,
            )
            if not valid:
                print("  ADD_LIQUIDITY violates pool invariant -- rejected")
                return None
            lc = LiquidityChange(
                user=user, liq_type=liq_type,
                btc_amount=btc_amount, anch_amount=anch_amount,
                lp_delta=lp_minted, timestamp=time.time(),
            )
            label = f"ADD {btc_amount:,} sats + {anch_amount:,} ANCH -> mint {lp_minted:,} LP"
        else:  # REMOVE
            lp_burned = btc_amount
            if lp_burned <= 0 or lp_burned > old.lp_total:
                print("  REMOVE_LIQUIDITY: invalid LP burn amount")
                return None
            btc_out, anch_out = CovenantAMMScript.compute_remove_amounts(
                lp_burned, old.btc_reserve, old.anch_reserve, old.lp_total,
            )
            new_btc = old.btc_reserve - btc_out
            new_anch = old.anch_reserve - anch_out
            new_lp = old.lp_total - lp_burned
            valid = CovenantAMMScript.verify_remove_liquidity(
                old.btc_reserve, old.anch_reserve, old.lp_total,
                new_btc, new_anch, new_lp,
                btc_out, anch_out, lp_burned,
            )
            if not valid:
                print("  REMOVE_LIQUIDITY violates pool invariant -- rejected")
                return None
            lc = LiquidityChange(
                user=user, liq_type=liq_type,
                btc_amount=btc_out, anch_amount=anch_out,
                lp_delta=-lp_burned, timestamp=time.time(),
            )
            label = (f"REMOVE {lp_burned:,} LP -> "
                     f"return {btc_out:,} sats + {anch_out:,} ANCH")

        txid = hashlib.sha256(
            f"{user}{liq_type.name}{btc_amount}{anch_amount}{time.time()}".encode()
        ).hexdigest()
        self.pending_liquidity[txid] = lc
        print(f"  Liquidity proposal {txid[:16]}... submitted: {label}")
        print(f"  Challenge window: {self.challenge_period} blocks.")
        return txid

    def challenge_liquidity(self, txid: str, challenger: str) -> bool:
        if txid not in self.pending_liquidity:
            print("  No such pending liquidity change")
            return False
        lc = self.pending_liquidity[txid]
        blocks_elapsed = self._current_block() - self._proposal_block(lc.timestamp)
        if blocks_elapsed > self.challenge_period:
            print("  Challenge period expired -- liquidity change can be finalised")
            return False
        old = self.state
        if lc.liq_type == LiquidityType.ADD:
            lp_minted = lc.lp_delta
            new_btc = old.btc_reserve + lc.btc_amount
            new_anch = old.anch_reserve + lc.anch_amount
            new_lp = old.lp_total + lp_minted
            valid = CovenantAMMScript.verify_add_liquidity(
                old.btc_reserve, old.anch_reserve, old.lp_total,
                new_btc, new_anch, new_lp,
                lc.btc_amount, lc.anch_amount, lp_minted,
            )
        else:
            lp_burned = -lc.lp_delta
            new_btc = old.btc_reserve - lc.btc_amount
            new_anch = old.anch_reserve - lc.anch_amount
            new_lp = old.lp_total - lp_burned
            valid = CovenantAMMScript.verify_remove_liquidity(
                old.btc_reserve, old.anch_reserve, old.lp_total,
                new_btc, new_anch, new_lp,
                lc.btc_amount, lc.anch_amount, lp_burned,
            )
        if not valid:
            print(f"  Challenge by {challenger} succeeded! "
                  f"Liquidity proposal {txid[:16]}... was invalid and removed.")
            del self.pending_liquidity[txid]
            return True
        else:
            print(f"  Challenge by {challenger} failed -- proposal is valid. "
                  f"Challenger would forfeit their bond.")
            return False

    def finalize_liquidity(self, txid: str) -> Optional[PoolState]:
        if txid not in self.pending_liquidity:
            print("  No such pending liquidity change (may already be resolved)")
            return None
        lc = self.pending_liquidity[txid]
        blocks_elapsed = self._current_block() - self._proposal_block(lc.timestamp)
        if blocks_elapsed < self.challenge_period:
            print(f"  Challenge period not yet over "
                  f"({blocks_elapsed}/{self.challenge_period} blocks elapsed)")
            return None
        old = self.state
        if lc.liq_type == LiquidityType.ADD:
            new_btc = old.btc_reserve + lc.btc_amount
            new_anch = old.anch_reserve + lc.anch_amount
            new_lp = old.lp_total + lc.lp_delta
            action = f"added {lc.btc_amount:,} sats + {lc.anch_amount:,} ANCH, minted {lc.lp_delta:,} LP"
        else:
            lp_burned = -lc.lp_delta
            new_btc = old.btc_reserve - lc.btc_amount
            new_anch = old.anch_reserve - lc.anch_amount
            new_lp = old.lp_total - lp_burned
            action = f"removed {lp_burned:,} LP, returned {lc.btc_amount:,} sats + {lc.anch_amount:,} ANCH"
        new_state = PoolState(
            btc_reserve=new_btc,
            anch_reserve=new_anch,
            lp_total=new_lp,
            taproot_address=self.state.taproot_address,
            script_merkle_root=self.state.script_merkle_root,
        )
        self.state = new_state
        if lc.liq_type == LiquidityType.ADD:
            self._lp_ledger[lc.user] = self._lp_ledger.get(lc.user, 0) + lc.lp_delta
        else:
            lp_burned = -lc.lp_delta
            current_lp = self._lp_ledger.get(lc.user, 0)
            self._lp_ledger[lc.user] = max(0, current_lp - lp_burned)
        del self.pending_liquidity[txid]
        print(f"  Liquidity change {txid[:16]}... finalised ({lc.user} {action}).")
        print(f"  Reserves -> BTC={new_btc:,} ANCH={new_anch:,} LP={new_lp:,}")
        return new_state

    def lp_balance_of(self, user: str) -> int:
        return self._lp_ledger.get(user, 0)

    def get_info(self) -> dict:
        return {
            "address": self.state.taproot_address,
            "btc_reserve": self.state.btc_reserve,
            "anch_reserve": self.state.anch_reserve,
            "lp_total": self.state.lp_total,
            "pending_swaps": len(self.pending_swaps),
            "pending_liquidity": len(self.pending_liquidity),
        }

    def quote(self, swap_type: SwapType, amount_in: int) -> int:
        if swap_type == SwapType.BTC_TO_ANCH:
            return CovenantAMMScript.get_amount_out(
                amount_in, self.state.btc_reserve, self.state.anch_reserve
            )
        else:
            return CovenantAMMScript.get_amount_out(
                amount_in, self.state.anch_reserve, self.state.btc_reserve
            )
