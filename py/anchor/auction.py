"""
Slot auction -- hardened fee-market for anchor-right reservations.

Auction types:
  - ENGLISH   : ascending open outcry (default)
  - DUTCH     : descending price, first-claim-wins
  - SEALED    : commit-reveal sealed-bid first-price
  - VICKREY   : commit-reveal sealed-bid second-price
  - BATCH     : uniform-price clearing for multiple slots

Anti-Sybil:
  - Identity commitment via Bitcoin pubkey hash
  - Minimum ANCH stake to participate (configurable)
  - Per-identity bid-rate limiter (rolling window)
  - Reputation scoring tied to on-chain behavior

Anti-Sniping:
  - Bid-extension window: any bid in the last N seconds extends deadline
  - Candle auction mode: hard-random cutoff (hash-derived)
  - Commit-reveal phases prevent last-second information advantages

Anti-Griefing:
  - Non-refundable bid bonds (% of bid)
  - Minimum bid increments (absolute + percentage)
  - Winner-must-consume deadline with escalating slashing
  - Cooldown for serial non-consumers

Economic Incentives:
  - Dynamic base pricing from slot utilization
  - Loyalty multiplier for repeat consumers
  - Referral rewards for bringing new participants
  - Volume-tiered fee discounts
  - Revenue sharing: portion of fees redistributed to LP stakers

Lifecycle: OPEN -> REVEAL -> WON -> CONSUMED | EXPIRED | SLASHED
"""
from __future__ import annotations

import hashlib
import math
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .truc import AnchorProof
from .verifier import ClaimRegistry

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .rgb import RGBAsset


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SlotState(Enum):
    OPEN = "open"
    REVEAL = "reveal"          # sealed/vickrey: reveal phase
    WON = "won"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    SLASHED = "slashed"        # winner penalized for non-consumption


class AuctionType(Enum):
    ENGLISH = "english"        # ascending open outcry
    DUTCH = "dutch"            # descending price, first-claim
    SEALED = "sealed"          # commit-reveal first-price
    VICKREY = "vickrey"        # commit-reveal second-price
    BATCH = "batch"            # uniform-price clearing


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BidRecord:
    bidder: str
    amount: int
    ts: float
    bond: int = 0              # non-refundable bid bond
    commitment: str = ""       # hash(amount || nonce) for sealed bids
    nonce: str = ""            # revealed nonce
    revealed: bool = False     # whether sealed bid has been revealed


@dataclass
class ReputationProfile:
    """Per-identity reputation ledger."""
    identity: str
    total_bids: int = 0
    total_wins: int = 0
    total_consumed: int = 0
    total_expired: int = 0       # wins not consumed -> slashed
    total_slashed_amount: int = 0
    referral_count: int = 0
    first_seen: float = 0.0
    last_activity: float = 0.0
    consecutive_consumes: int = 0  # streak for loyalty bonus

    @property
    def consume_rate(self) -> float:
        if self.total_wins == 0:
            return 1.0
        return self.total_consumed / self.total_wins

    @property
    def reputation_score(self) -> int:
        """0-1000 reputation score."""
        if self.total_bids == 0:
            return 500  # neutral for new participants
        base = int(self.consume_rate * 600)
        loyalty = min(200, self.consecutive_consumes * 20)
        referral = min(100, self.referral_count * 10)
        penalty = min(300, self.total_expired * 75)
        return max(0, min(1000, base + loyalty + referral - penalty + 100))

    @property
    def loyalty_tier(self) -> int:
        """0-4 tier based on reputation."""
        if self.reputation_score >= 900:
            return 4
        elif self.reputation_score >= 700:
            return 3
        elif self.reputation_score >= 500:
            return 2
        elif self.reputation_score >= 300:
            return 1
        return 0

    @property
    def fee_discount_bps(self) -> int:
        """Basis-point discount on bond fees (0-500 = 0-5%)."""
        return self.loyalty_tier * 100  # tier 4 = 400 bps = 4% discount

    @property
    def is_on_cooldown(self) -> bool:
        """Cooldown for serial non-consumers (2+ consecutive expirations)."""
        return self.total_expired >= 2 and self.consecutive_consumes == 0


@dataclass
class AnchorSlot:
    slot_id: str
    block_start: int
    block_end: int
    min_fee_rate: int
    auction_type: AuctionType = AuctionType.ENGLISH
    state: SlotState = SlotState.OPEN
    highest_bid: int = 0
    second_bid: int = 0          # for Vickrey auction
    winner: Optional[str] = None
    proof_id: Optional[str] = None
    bids: List[BidRecord] = field(default_factory=list)
    commitments: Dict[str, str] = field(default_factory=dict)  # sealed bids
    created_at: float = 0.0
    deadline: float = 0.0       # auction end time
    reveal_deadline: float = 0.0  # sealed/vickrey reveal end
    consume_deadline: float = 0.0  # must consume by this time
    extension_count: int = 0     # how many times deadline was extended
    max_extensions: int = 5      # cap on anti-snipe extensions
    dutch_start_price: int = 0   # Dutch: starting price
    dutch_floor_price: int = 0   # Dutch: minimum price
    dutch_decrement: int = 0     # Dutch: per-tick decrease
    dutch_tick_seconds: float = 30.0  # Dutch: time between price drops
    total_bonds_collected: int = 0
    referrer: Optional[str] = None  # who created/referred this slot


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class AuctionConfig:
    """Tunable parameters for the auction engine."""
    # Anti-Sybil
    min_stake: int = 100                  # minimum ANCH balance to bid
    max_bids_per_window: int = 20         # max bids per identity per window
    rate_limit_window: float = 300.0      # 5-minute rolling window (seconds)
    require_identity: bool = False        # set True for strict anti-Sybil

    # Anti-Sniping
    snipe_window: float = 60.0            # last 60s = snipe zone
    extension_duration: float = 120.0     # extend by 2 min on snipe
    max_extensions: int = 5               # max extensions per auction
    candle_entropy_source: str = "block"  # "block" | "hash"

    # Anti-Griefing
    bond_rate_bps: int = 200              # 2% non-refundable bid bond
    min_increment_abs: int = 10           # minimum absolute bid increment
    min_increment_pct: int = 5            # minimum % bid increment
    consume_deadline_seconds: float = 3600.0  # 1 hour to consume after winning
    slash_rate_bps: int = 5000            # 50% of bid slashed on non-consume
    escalating_slash: bool = True         # worse slash for repeat offenders
    cooldown_threshold: int = 2           # expirations before cooldown

    # Sealed/Vickrey
    commit_phase_seconds: float = 600.0   # 10 min commit phase
    reveal_phase_seconds: float = 300.0   # 5 min reveal phase

    # Dutch
    dutch_default_start: int = 10000      # default start price
    dutch_default_floor: int = 100        # default floor
    dutch_default_decrement: int = 100    # price drop per tick
    dutch_tick_seconds: float = 30.0      # seconds between price drops

    # Economic incentives
    loyalty_bonus_bps: int = 1000         # 10% extra reward for top-tier
    referral_reward_bps: int = 500        # 5% reward for referrals
    protocol_fee_bps: int = 500           # 5% protocol fee on winning bids
    lp_share_bps: int = 3000             # 30% of protocol fees to LP stakers
    dynamic_pricing: bool = True          # adjust min price by utilization
    utilization_lookback: int = 50        # slots to look back for utilization


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Per-identity sliding-window rate limiter."""

    def __init__(self, max_actions: int, window: float):
        self.max_actions = max_actions
        self.window = window
        self._actions: Dict[str, List[float]] = {}

    def check(self, identity: str) -> bool:
        now = time.time()
        history = self._actions.get(identity, [])
        # prune old entries
        history = [t for t in history if now - t < self.window]
        self._actions[identity] = history
        return len(history) < self.max_actions

    def record(self, identity: str):
        now = time.time()
        history = self._actions.setdefault(identity, [])
        history.append(now)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SlotAuction:
    """
    Hardened fee-market for anchor-right reservations.

    Lifecycle:
      1. OPEN     -- operator creates slot; users bid ANCH
      2. REVEAL   -- (sealed/vickrey only) commitments revealed
      3. WON      -- bidding closes; winner determined
      4. CONSUMED -- winner submits AnchorProof; slot fulfilled
      5. EXPIRED  -- consume deadline passes; bid partially slashed
      6. SLASHED  -- repeat offenders fully slashed

    Anti-Sybil:   stake gate, rate limiter, identity commitment
    Anti-Sniping: bid extension, candle randomness, commit-reveal
    Anti-Griefing: bonds, min increments, slashing, cooldowns
    """
    PROTOCOL_ADDRESS = "anchor_protocol_treasury"
    LP_POOL_ADDRESS = "anchor_lp_pool"

    def __init__(
        self,
        anch_asset: 'RGBAsset',
        claim_registry: ClaimRegistry,
        config: Optional[AuctionConfig] = None,
    ):
        self.slots: Dict[str, AnchorSlot] = {}
        self.anch = anch_asset
        self.registry = claim_registry
        self.config = config or AuctionConfig()
        self._slot_seq = 0
        self._identity_commitments: Dict[str, str] = {}  # pubkey -> commitment
        self._reputations: Dict[str, ReputationProfile] = {}
        self._referrals: Dict[str, str] = {}  # referee -> referrer
        self._rate_limiter = _RateLimiter(
            self.config.max_bids_per_window,
            self.config.rate_limit_window,
        )
        self._completed_slots: List[AnchorSlot] = []  # for utilization calc

    # ------------------------------------------------------------------
    # Identity & reputation
    # ------------------------------------------------------------------

    def register_identity(self, pubkey: str, commitment: str) -> Tuple[bool, str]:
        """
        Anti-Sybil: register a unique identity commitment tied to a Bitcoin
        pubkey. The commitment should be hash(pubkey || nonce) where nonce
        is a secret the user retains. One pubkey = one identity.
        """
        if pubkey in self._identity_commitments:
            return False, "identity already registered"
        if commitment in self._identity_commitments.values():
            return False, "duplicate commitment (possible Sybil)"
        self._identity_commitments[pubkey] = commitment
        self._reputations[pubkey] = ReputationProfile(
            identity=pubkey,
            first_seen=time.time(),
            last_activity=time.time(),
        )
        print(f"  [ID] Registered identity {pubkey[:12]}... "
              f"commitment={commitment[:16]}...")
        return True, "registered"

    def register_referral(self, referee: str, referrer: str) -> Tuple[bool, str]:
        """Track referral relationship for reward distribution."""
        if referee == referrer:
            return False, "cannot refer yourself"
        if referee in self._referrals:
            return False, "already has a referrer"
        if referrer not in self._reputations:
            return False, "referrer not registered"
        self._referrals[referee] = referrer
        self._reputations[referrer].referral_count += 1
        print(f"  [REF] {referee[:12]}... referred by {referrer[:12]}...")
        return True, "referral registered"

    def get_reputation(self, identity: str) -> Optional[dict]:
        rep = self._reputations.get(identity)
        if rep is None:
            return None
        return {
            "identity": rep.identity[:12],
            "score": rep.reputation_score,
            "tier": rep.loyalty_tier,
            "consume_rate": f"{rep.consume_rate:.1%}",
            "bids": rep.total_bids,
            "wins": rep.total_wins,
            "consumed": rep.total_consumed,
            "expired": rep.total_expired,
            "streak": rep.consecutive_consumes,
            "fee_discount": f"{rep.fee_discount_bps} bps",
            "cooldown": rep.is_on_cooldown,
        }

    def _check_identity(self, bidder: str) -> Tuple[bool, str]:
        """Validate identity requirements."""
        if not self.config.require_identity:
            # auto-register if identity not required
            if bidder not in self._reputations:
                self._reputations[bidder] = ReputationProfile(
                    identity=bidder,
                    first_seen=time.time(),
                    last_activity=time.time(),
                )
            return True, "ok"
        if bidder not in self._identity_commitments:
            return False, "identity not registered (anti-Sybil)"
        rep = self._reputations.get(bidder)
        if rep and rep.is_on_cooldown:
            return False, (f"identity on cooldown (expired {rep.total_expired} slots, "
                           f"consume to rebuild reputation)")
        return True, "ok"

    def _check_stake(self, bidder: str) -> Tuple[bool, str]:
        """Anti-Sybil: ensure minimum balance to participate."""
        balance = self.anch.balance_of(bidder)
        if balance < self.config.min_stake:
            return False, (f"insufficient stake: {balance:,} < "
                           f"{self.config.min_stake:,} ANCH minimum")
        return True, "ok"

    def _check_rate_limit(self, bidder: str) -> Tuple[bool, str]:
        """Anti-Sybil: rate limit bids per identity."""
        if not self._rate_limiter.check(bidder):
            return False, (f"rate limited: max {self.config.max_bids_per_window} "
                           f"bids per {self.config.rate_limit_window:.0f}s window")
        return True, "ok"

    # ------------------------------------------------------------------
    # Dynamic pricing
    # ------------------------------------------------------------------

    def _dynamic_min_price(self, base_min: int) -> int:
        """
        Adjust minimum price based on recent slot utilization.
        High utilization -> higher minimum price.
        Low utilization  -> lower minimum price (floor = base_min // 2).
        """
        if not self.config.dynamic_pricing:
            return base_min
        lookback = self.config.utilization_lookback
        recent = self._completed_slots[-lookback:] if self._completed_slots else []
        if not recent:
            return base_min
        consumed = sum(1 for s in recent if s.state == SlotState.CONSUMED)
        utilization = consumed / len(recent)
        # Scale: 0.5 util -> 0.75x, 1.0 util -> 1.5x base
        multiplier = 0.5 + utilization
        return max(base_min // 2, int(base_min * multiplier))

    # ------------------------------------------------------------------
    # Bond calculation
    # ------------------------------------------------------------------

    def _compute_bond(self, amount: int, bidder: str) -> int:
        """
        Non-refundable bid bond = bond_rate_bps of bid amount,
        minus any loyalty discount.
        """
        rep = self._reputations.get(bidder)
        discount = rep.fee_discount_bps if rep else 0
        effective_rate = max(0, self.config.bond_rate_bps - discount)
        return max(1, (amount * effective_rate) // 10_000)

    # ------------------------------------------------------------------
    # Slot creation
    # ------------------------------------------------------------------

    def create_slot(
        self,
        block_start: int,
        block_end: int,
        min_fee_rate: int = 5,
        auction_type: AuctionType = AuctionType.ENGLISH,
        duration: float = 600.0,
        dutch_start_price: int = 0,
        dutch_floor_price: int = 0,
        dutch_decrement: int = 0,
        referrer: Optional[str] = None,
    ) -> AnchorSlot:
        self._slot_seq += 1
        slot_id = hashlib.sha256(
            f"slot:{block_start}:{block_end}:{self._slot_seq}".encode()
        ).hexdigest()

        now = time.time()
        deadline = now + duration

        # sealed/vickrey: split time into commit + reveal
        reveal_deadline = 0.0
        if auction_type in (AuctionType.SEALED, AuctionType.VICKREY):
            deadline = now + self.config.commit_phase_seconds
            reveal_deadline = deadline + self.config.reveal_phase_seconds

        # Dutch-specific defaults
        d_start = dutch_start_price or self.config.dutch_default_start
        d_floor = dutch_floor_price or self.config.dutch_default_floor
        d_decrement = dutch_decrement or self.config.dutch_default_decrement

        # Dynamic minimum pricing
        effective_min = self._dynamic_min_price(min_fee_rate)

        slot = AnchorSlot(
            slot_id=slot_id,
            block_start=block_start,
            block_end=block_end,
            min_fee_rate=effective_min,
            auction_type=auction_type,
            state=SlotState.OPEN,
            created_at=now,
            deadline=deadline,
            reveal_deadline=reveal_deadline,
            consume_deadline=0.0,  # set when WON
            max_extensions=self.config.max_extensions,
            dutch_start_price=d_start,
            dutch_floor_price=d_floor,
            dutch_decrement=d_decrement,
            dutch_tick_seconds=self.config.dutch_tick_seconds,
            referrer=referrer,
        )
        self.slots[slot_id] = slot
        extra = ""
        if auction_type == AuctionType.DUTCH:
            extra = f" dutch_start={d_start:,} floor={d_floor:,}"
        print(f"  [SLOT] Created {auction_type.value} slot {slot_id[:16]}... "
              f"blocks {block_start}-{block_end} min_fee={effective_min} sat/vB"
              f"{extra}")
        return slot

    # ------------------------------------------------------------------
    # English auction (ascending)
    # ------------------------------------------------------------------

    def place_bid(
        self,
        slot_id: str,
        bidder: str,
        anch_amount: int,
    ) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"

        # Route to type-specific handler
        if slot.auction_type == AuctionType.DUTCH:
            return self._dutch_claim(slot, bidder, anch_amount)
        if slot.auction_type in (AuctionType.SEALED, AuctionType.VICKREY):
            return False, f"use commit_bid() for {slot.auction_type.value} auctions"
        if slot.auction_type == AuctionType.BATCH:
            return self._batch_bid(slot, bidder, anch_amount)

        # English auction logic
        return self._english_bid(slot, bidder, anch_amount)

    def _english_bid(
        self,
        slot: AnchorSlot,
        bidder: str,
        anch_amount: int,
    ) -> Tuple[bool, str]:
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}, not open"

        # Anti-Sybil checks
        ok, reason = self._check_identity(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_stake(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_rate_limit(bidder)
        if not ok:
            return False, reason

        # Minimum increment enforcement (anti-griefing)
        if slot.highest_bid > 0:
            min_abs = slot.highest_bid + self.config.min_increment_abs
            min_pct = slot.highest_bid + (
                slot.highest_bid * self.config.min_increment_pct // 100
            )
            min_bid = max(min_abs, min_pct)
            if anch_amount < min_bid:
                return False, (f"bid {anch_amount:,} below minimum increment "
                               f"(need >= {min_bid:,})")
        elif anch_amount <= 0:
            return False, "bid must be positive"

        # Bond calculation
        bond = self._compute_bond(anch_amount, bidder)
        total_needed = anch_amount + bond

        if self.anch.balance_of(bidder) < total_needed:
            return False, (f"insufficient ANCH: need {total_needed:,} "
                           f"(bid {anch_amount:,} + bond {bond:,})")

        # Refund previous winner (bid only, bond already collected)
        if slot.winner is not None:
            self.anch.balances[slot.winner] = (
                self.anch.balances.get(slot.winner, 0) + slot.highest_bid
            )
            print(f"  [SLOT] Refunded {slot.highest_bid:,} ANCH to "
                  f"{slot.winner[:12]}...")

        # Escrow bid + collect bond
        self.anch.balances[bidder] -= total_needed
        slot.highest_bid = anch_amount
        slot.winner = bidder
        slot.total_bonds_collected += bond

        # Send bond to protocol treasury
        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + bond
        )

        slot.bids.append(BidRecord(
            bidder=bidder, amount=anch_amount, bond=bond, ts=time.time(),
        ))
        self._rate_limiter.record(bidder)
        self._update_reputation_bid(bidder)

        # Anti-sniping: extend deadline if bid is in the snipe window
        now = time.time()
        if (slot.deadline - now) < self.config.snipe_window:
            if slot.extension_count < slot.max_extensions:
                old_deadline = slot.deadline
                slot.deadline += self.config.extension_duration
                slot.extension_count += 1
                print(f"  [SNIPE] Deadline extended by "
                      f"{self.config.extension_duration:.0f}s "
                      f"(extension {slot.extension_count}/{slot.max_extensions})")

        print(f"  [SLOT] Bid {anch_amount:,} ANCH (bond={bond:,}) by "
              f"{bidder[:12]}... on slot {slot.slot_id[:16]}...")
        return True, "bid accepted"

    # ------------------------------------------------------------------
    # Dutch auction (descending)
    # ------------------------------------------------------------------

    def get_dutch_price(self, slot: AnchorSlot) -> int:
        """Current price in a Dutch auction (decreasing over time)."""
        if slot.auction_type != AuctionType.DUTCH:
            return slot.highest_bid
        elapsed = time.time() - slot.created_at
        ticks = int(elapsed / slot.dutch_tick_seconds)
        price = slot.dutch_start_price - (ticks * slot.dutch_decrement)
        return max(slot.dutch_floor_price, price)

    def _dutch_claim(
        self,
        slot: AnchorSlot,
        bidder: str,
        anch_amount: int,
    ) -> Tuple[bool, str]:
        """Dutch: first bidder to accept the current price wins immediately."""
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}, not open"

        ok, reason = self._check_identity(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_stake(bidder)
        if not ok:
            return False, reason

        current_price = self.get_dutch_price(slot)
        if current_price <= slot.dutch_floor_price:
            slot.state = SlotState.EXPIRED
            self._completed_slots.append(slot)
            return False, "Dutch auction expired (floor reached)"

        if anch_amount < current_price:
            return False, (f"bid {anch_amount:,} < current Dutch price "
                           f"{current_price:,}")

        bond = self._compute_bond(anch_amount, bidder)
        total_needed = anch_amount + bond

        if self.anch.balance_of(bidder) < total_needed:
            return False, f"insufficient ANCH: need {total_needed:,}"

        # Immediate win -- Dutch auction
        self.anch.balances[bidder] -= total_needed
        slot.highest_bid = anch_amount
        slot.winner = bidder
        slot.total_bonds_collected += bond
        slot.state = SlotState.WON
        slot.consume_deadline = time.time() + self.config.consume_deadline_seconds

        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + bond
        )
        slot.bids.append(BidRecord(
            bidder=bidder, amount=anch_amount, bond=bond, ts=time.time(),
        ))
        self._rate_limiter.record(bidder)
        self._update_reputation_bid(bidder)
        self._update_reputation_win(bidder)

        print(f"  [DUTCH] {bidder[:12]}... claimed slot {slot.slot_id[:16]}... "
              f"at {anch_amount:,} ANCH (Dutch price={current_price:,})")
        return True, "dutch claim accepted -- slot WON"

    # ------------------------------------------------------------------
    # Sealed-bid / Vickrey (commit-reveal)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_commitment(amount: int, nonce: str) -> str:
        """Hash(amount || nonce) for sealed bid commitment."""
        return hashlib.sha256(f"{amount}:{nonce}".encode()).hexdigest()

    def commit_bid(
        self,
        slot_id: str,
        bidder: str,
        commitment: str,
        bond_amount: int,
    ) -> Tuple[bool, str]:
        """
        Phase 1 of sealed/Vickrey: submit a hash commitment.
        The bond is locked as collateral to prevent griefing / phantom bids.
        """
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.auction_type not in (AuctionType.SEALED, AuctionType.VICKREY):
            return False, f"commit_bid only for sealed/vickrey auctions"
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}, not in commit phase"

        ok, reason = self._check_identity(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_stake(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_rate_limit(bidder)
        if not ok:
            return False, reason

        if bidder in slot.commitments:
            return False, "already committed (one bid per identity)"

        if bond_amount < self.config.min_increment_abs:
            return False, f"bond too low (min {self.config.min_increment_abs})"

        if self.anch.balance_of(bidder) < bond_amount:
            return False, "insufficient ANCH for bond"

        # Lock bond
        self.anch.balances[bidder] -= bond_amount
        slot.commitments[bidder] = commitment
        slot.total_bonds_collected += bond_amount
        slot.bids.append(BidRecord(
            bidder=bidder, amount=0, bond=bond_amount,
            commitment=commitment, ts=time.time(),
        ))
        self._rate_limiter.record(bidder)
        self._update_reputation_bid(bidder)

        print(f"  [SEALED] Commitment from {bidder[:12]}... "
              f"bond={bond_amount:,} ANCH on slot {slot.slot_id[:16]}...")
        return True, "commitment accepted"

    def start_reveal_phase(self, slot_id: str) -> Tuple[bool, str]:
        """Transition sealed/vickrey auction to reveal phase."""
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.auction_type not in (AuctionType.SEALED, AuctionType.VICKREY):
            return False, "not a sealed/vickrey auction"
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}"
        if not slot.commitments:
            slot.state = SlotState.EXPIRED
            self._completed_slots.append(slot)
            return True, "expired (no commitments)"

        slot.state = SlotState.REVEAL
        slot.reveal_deadline = time.time() + self.config.reveal_phase_seconds
        print(f"  [SEALED] Reveal phase started for slot {slot.slot_id[:16]}...")
        return True, "reveal phase started"

    def reveal_bid(
        self,
        slot_id: str,
        bidder: str,
        amount: int,
        nonce: str,
    ) -> Tuple[bool, str]:
        """
        Phase 2: reveal the sealed bid by providing (amount, nonce).
        Must match the original commitment hash.
        """
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.REVEAL:
            return False, f"slot is {slot.state.value}, not in reveal phase"
        if bidder not in slot.commitments:
            return False, "no commitment found for this bidder"

        expected = slot.commitments[bidder]
        actual = self.compute_commitment(amount, nonce)
        if actual != expected:
            # Slash the bond for invalid reveal (griefing deterrent)
            self.anch.balances[self.PROTOCOL_ADDRESS] = (
                self.anch.balances.get(self.PROTOCOL_ADDRESS, 0)
            )
            return False, "commitment mismatch -- bid bond forfeited"

        if self.anch.balance_of(bidder) < amount:
            return False, "insufficient ANCH for revealed bid amount"

        # Mark as revealed
        for bid in slot.bids:
            if bid.bidder == bidder and bid.commitment == expected:
                bid.amount = amount
                bid.nonce = nonce
                bid.revealed = True
                break

        # Track highest and second-highest for Vickrey
        if amount > slot.highest_bid:
            slot.second_bid = slot.highest_bid
            slot.highest_bid = amount
            slot.winner = bidder
        elif amount > slot.second_bid:
            slot.second_bid = amount

        print(f"  [SEALED] Reveal: {bidder[:12]}... bid {amount:,} ANCH")
        return True, "bid revealed"

    def finalize_sealed(self, slot_id: str) -> Tuple[bool, str]:
        """Close reveal phase and determine winner."""
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.REVEAL:
            return False, f"slot is {slot.state.value}"
        if slot.winner is None:
            slot.state = SlotState.EXPIRED
            self._completed_slots.append(slot)
            return True, "expired (no valid reveals)"

        # Vickrey: winner pays second-highest price
        if slot.auction_type == AuctionType.VICKREY:
            pay = slot.second_bid if slot.second_bid > 0 else slot.highest_bid
            print(f"  [VICKREY] Winner pays second-price: {pay:,} ANCH "
                  f"(bid was {slot.highest_bid:,})")
            # Refund the difference
            refund_diff = slot.highest_bid - pay
            if refund_diff > 0:
                self.anch.balances[slot.winner] = (
                    self.anch.balances.get(slot.winner, 0) + refund_diff
                )
            slot.highest_bid = pay

        # Escrow the winning amount
        self.anch.balances[slot.winner] = (
            self.anch.balances.get(slot.winner, 0) - slot.highest_bid
        )

        slot.state = SlotState.WON
        slot.consume_deadline = time.time() + self.config.consume_deadline_seconds
        self._update_reputation_win(slot.winner)

        # Refund bonds to non-winners
        for bid in slot.bids:
            if bid.bidder != slot.winner and bid.revealed:
                self.anch.balances[bid.bidder] = (
                    self.anch.balances.get(bid.bidder, 0) + bid.bond
                )
                print(f"  [SEALED] Bond refunded to {bid.bidder[:12]}...")

        print(f"  [SLOT] {slot.auction_type.value} slot {slot.slot_id[:16]}... "
              f"won by {slot.winner[:12]}... for {slot.highest_bid:,} ANCH")
        return True, "finalized"

    # ------------------------------------------------------------------
    # Batch auction (uniform-price clearing)
    # ------------------------------------------------------------------

    def _batch_bid(
        self,
        slot: AnchorSlot,
        bidder: str,
        anch_amount: int,
    ) -> Tuple[bool, str]:
        """Batch: all bids collected, cleared at uniform price."""
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}, not open"

        ok, reason = self._check_identity(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_stake(bidder)
        if not ok:
            return False, reason
        ok, reason = self._check_rate_limit(bidder)
        if not ok:
            return False, reason

        if anch_amount <= 0:
            return False, "bid must be positive"

        bond = self._compute_bond(anch_amount, bidder)
        total_needed = anch_amount + bond

        if self.anch.balance_of(bidder) < total_needed:
            return False, f"insufficient ANCH: need {total_needed:,}"

        # Escrow full amount
        self.anch.balances[bidder] -= total_needed
        slot.total_bonds_collected += bond
        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + bond
        )
        slot.bids.append(BidRecord(
            bidder=bidder, amount=anch_amount, bond=bond, ts=time.time(),
        ))
        self._rate_limiter.record(bidder)
        self._update_reputation_bid(bidder)

        print(f"  [BATCH] Bid {anch_amount:,} ANCH by {bidder[:12]}...")
        return True, "batch bid accepted"

    def clear_batch(self, slot_id: str) -> Tuple[bool, str, int]:
        """
        Close a batch auction: uniform clearing price = lowest winning bid.
        Winner is the highest bidder; all pay the clearing price.
        Returns (ok, reason, clearing_price).
        """
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found", 0
        if slot.auction_type != AuctionType.BATCH:
            return False, "not a batch auction", 0
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}", 0
        if not slot.bids:
            slot.state = SlotState.EXPIRED
            self._completed_slots.append(slot)
            return True, "expired (no bids)", 0

        # Sort bids descending
        sorted_bids = sorted(slot.bids, key=lambda b: b.amount, reverse=True)
        winner_bid = sorted_bids[0]

        # Clearing price = second-highest bid (or winner's bid if solo)
        clearing_price = (
            sorted_bids[1].amount if len(sorted_bids) > 1
            else winner_bid.amount
        )

        slot.winner = winner_bid.bidder
        slot.highest_bid = clearing_price  # winner pays clearing price
        slot.state = SlotState.WON
        slot.consume_deadline = time.time() + self.config.consume_deadline_seconds
        self._update_reputation_win(slot.winner)

        # Refund all non-winners their full bids
        for bid in sorted_bids[1:]:
            self.anch.balances[bid.bidder] = (
                self.anch.balances.get(bid.bidder, 0) + bid.amount
            )
            print(f"  [BATCH] Refunded {bid.amount:,} ANCH to {bid.bidder[:12]}...")

        # Refund winner the difference between their bid and clearing price
        refund = winner_bid.amount - clearing_price
        if refund > 0:
            self.anch.balances[slot.winner] = (
                self.anch.balances.get(slot.winner, 0) + refund
            )
            print(f"  [BATCH] Winner overpay refund: {refund:,} ANCH")

        print(f"  [BATCH] Cleared at {clearing_price:,} ANCH, "
              f"winner={slot.winner[:12]}...")
        return True, "batch cleared", clearing_price

    # ------------------------------------------------------------------
    # Close bidding (English)
    # ------------------------------------------------------------------

    def close_bidding(self, slot_id: str) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.OPEN:
            return False, f"slot is {slot.state.value}"

        # Candle auction randomness: retroactively determine if the auction
        # ended earlier based on block-hash entropy
        if slot.bids and self.config.candle_entropy_source == "block":
            candle_cutoff = self._candle_cutoff(slot)
            if candle_cutoff is not None:
                # Re-determine winner from bids before cutoff
                valid_bids = [b for b in slot.bids if b.ts <= candle_cutoff]
                if valid_bids:
                    best = max(valid_bids, key=lambda b: b.amount)
                    # Refund actual latest winner if different
                    if slot.winner and slot.winner != best.bidder:
                        self.anch.balances[slot.winner] = (
                            self.anch.balances.get(slot.winner, 0)
                            + slot.highest_bid
                        )
                        # Re-escrow the candle winner
                        self.anch.balances[best.bidder] = (
                            self.anch.balances.get(best.bidder, 0)
                            - best.amount
                        )
                    slot.winner = best.bidder
                    slot.highest_bid = best.amount
                    print(f"  [CANDLE] Retroactive cutoff at "
                          f"{candle_cutoff:.0f}, winner={best.bidder[:12]}... "
                          f"bid={best.amount:,}")

        if slot.winner is None:
            slot.state = SlotState.EXPIRED
            self._completed_slots.append(slot)
            print(f"  [SLOT] Slot {slot.slot_id[:16]}... expired (no bids)")
            return True, "expired (no bids)"

        slot.state = SlotState.WON
        slot.consume_deadline = time.time() + self.config.consume_deadline_seconds
        self._update_reputation_win(slot.winner)
        print(f"  [SLOT] Slot {slot.slot_id[:16]}... won by "
              f"{slot.winner[:12]}... for {slot.highest_bid:,} ANCH")
        return True, "closed"

    def _candle_cutoff(self, slot: AnchorSlot) -> Optional[float]:
        """
        Derive a pseudo-random cutoff time from the slot_id hash.
        The candle ends at a random point between 50%-100% of the auction
        duration, preventing rational last-second sniping.
        """
        h = hashlib.sha256(f"candle:{slot.slot_id}".encode()).digest()
        # Use first 4 bytes as entropy (0..2^32-1)
        entropy = int.from_bytes(h[:4], 'big')
        fraction = 0.5 + (entropy / (2**32)) * 0.5  # 50-100%
        duration = slot.deadline - slot.created_at
        return slot.created_at + duration * fraction

    # ------------------------------------------------------------------
    # Consume slot
    # ------------------------------------------------------------------

    def consume_slot(
        self,
        slot_id: str,
        proof: AnchorProof,
    ) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.WON:
            return False, f"slot is {slot.state.value}, not won"
        if proof.creator != slot.winner:
            return False, f"proof creator {proof.creator} != winner {slot.winner}"
        if not (slot.block_start <= proof.block_height <= slot.block_end):
            return False, (f"block {proof.block_height} outside range "
                           f"[{slot.block_start}, {slot.block_end}]")
        if proof.fee_rate < slot.min_fee_rate:
            return False, f"fee_rate {proof.fee_rate} < min {slot.min_fee_rate}"
        if not proof.verified:
            return False, "proof not verified"

        # Register the claim
        base_reward = slot.highest_bid // 10
        ok, reason = self.registry.register_claim(proof, reward_amount=base_reward)
        if not ok:
            return False, f"claim registration failed: {reason}"

        # Compute loyalty bonus
        rep = self._reputations.get(slot.winner)
        loyalty_bonus = 0
        if rep and rep.loyalty_tier >= 3:
            loyalty_bonus = (base_reward * self.config.loyalty_bonus_bps) // 10_000

        # Protocol fee on winning bid
        protocol_fee = (slot.highest_bid * self.config.protocol_fee_bps) // 10_000
        lp_share = (protocol_fee * self.config.lp_share_bps) // 10_000
        treasury_share = protocol_fee - lp_share

        # Refund = bid - protocol_fee + base_reward + loyalty_bonus
        refund = slot.highest_bid - protocol_fee + base_reward + loyalty_bonus
        self.anch.balances[slot.winner] = (
            self.anch.balances.get(slot.winner, 0) + refund
        )

        # Protocol revenue distribution
        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + treasury_share
        )
        self.anch.balances[self.LP_POOL_ADDRESS] = (
            self.anch.balances.get(self.LP_POOL_ADDRESS, 0) + lp_share
        )

        # Referral reward
        referrer = self._referrals.get(slot.winner)
        referral_reward = 0
        if referrer:
            referral_reward = (base_reward * self.config.referral_reward_bps) // 10_000
            self.anch.balances[referrer] = (
                self.anch.balances.get(referrer, 0) + referral_reward
            )

        slot.state = SlotState.CONSUMED
        slot.proof_id = proof.proof_id
        self._completed_slots.append(slot)
        self._update_reputation_consume(slot.winner)

        print(f"  [SLOT] Slot {slot.slot_id[:16]}... consumed by "
              f"{slot.winner[:12]}...")
        print(f"         Refund: {slot.highest_bid:,} - fee {protocol_fee:,} "
              f"+ reward {base_reward:,} + loyalty {loyalty_bonus:,} "
              f"= {refund:,} ANCH")
        if referral_reward:
            print(f"         Referral reward: {referral_reward:,} ANCH "
                  f"to {referrer[:12]}...")
        print(f"         Protocol: {treasury_share:,} treasury + "
              f"{lp_share:,} LP pool")
        return True, "consumed"

    # ------------------------------------------------------------------
    # Expiration & slashing
    # ------------------------------------------------------------------

    def expire_slot(self, slot_id: str) -> Tuple[bool, str]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return False, "slot not found"
        if slot.state != SlotState.WON:
            return False, f"slot is {slot.state.value}"

        rep = self._reputations.get(slot.winner) if slot.winner else None

        # Escalating slash: worse for repeat offenders
        slash_bps = self.config.slash_rate_bps
        if self.config.escalating_slash and rep:
            # Each prior expiration adds 1000 bps (10%) more slash, up to 100%
            escalation = rep.total_expired * 1000
            slash_bps = min(10_000, slash_bps + escalation)

        slash_amount = (slot.highest_bid * slash_bps) // 10_000
        refund_amount = slot.highest_bid - slash_amount

        # Slash goes to protocol
        self.anch.balances[self.PROTOCOL_ADDRESS] = (
            self.anch.balances.get(self.PROTOCOL_ADDRESS, 0) + slash_amount
        )

        # Remainder refunded to winner
        if refund_amount > 0 and slot.winner:
            self.anch.balances[slot.winner] = (
                self.anch.balances.get(slot.winner, 0) + refund_amount
            )

        # Full slash = SLASHED state, partial = EXPIRED
        if slash_bps >= 10_000:
            slot.state = SlotState.SLASHED
        else:
            slot.state = SlotState.EXPIRED

        self._completed_slots.append(slot)
        if slot.winner:
            self._update_reputation_expire(slot.winner, slash_amount)

        print(f"  [SLOT] Slot {slot.slot_id[:16]}... {slot.state.value}. "
              f"Slashed {slash_amount:,} ANCH ({slash_bps/100:.0f}%), "
              f"refunded {refund_amount:,} ANCH.")
        if rep:
            print(f"         {slot.winner[:12]}... reputation: "
                  f"{rep.reputation_score}/1000 "
                  f"(tier {rep.loyalty_tier})")
        return True, slot.state.value

    # ------------------------------------------------------------------
    # Reputation updates
    # ------------------------------------------------------------------

    def _update_reputation_bid(self, identity: str):
        rep = self._reputations.get(identity)
        if rep:
            rep.total_bids += 1
            rep.last_activity = time.time()

    def _update_reputation_win(self, identity: str):
        rep = self._reputations.get(identity)
        if rep:
            rep.total_wins += 1
            rep.last_activity = time.time()

    def _update_reputation_consume(self, identity: str):
        rep = self._reputations.get(identity)
        if rep:
            rep.total_consumed += 1
            rep.consecutive_consumes += 1
            rep.last_activity = time.time()

    def _update_reputation_expire(self, identity: str, slashed: int):
        rep = self._reputations.get(identity)
        if rep:
            rep.total_expired += 1
            rep.total_slashed_amount += slashed
            rep.consecutive_consumes = 0  # reset streak
            rep.last_activity = time.time()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_slot_info(self, slot_id: str) -> Optional[dict]:
        slot = self.slots.get(slot_id)
        if slot is None:
            return None
        info = {
            "slot_id": slot.slot_id[:16],
            "type": slot.auction_type.value,
            "blocks": f"{slot.block_start}-{slot.block_end}",
            "state": slot.state.value,
            "highest_bid": slot.highest_bid,
            "winner": slot.winner[:12] if slot.winner else None,
            "min_fee_rate": slot.min_fee_rate,
            "num_bids": len(slot.bids),
            "bonds_collected": slot.total_bonds_collected,
            "extensions": slot.extension_count,
        }
        if slot.auction_type == AuctionType.DUTCH:
            info["dutch_current_price"] = self.get_dutch_price(slot)
        if slot.auction_type == AuctionType.VICKREY:
            info["second_price"] = slot.second_bid
        return info

    def list_slots(self, state_filter: Optional[SlotState] = None) -> List[dict]:
        results = []
        for sid in self.slots:
            slot = self.slots[sid]
            if state_filter and slot.state != state_filter:
                continue
            results.append(self.get_slot_info(sid))
        return results

    def get_utilization_stats(self) -> dict:
        """Overall auction health metrics."""
        total = len(self._completed_slots)
        if total == 0:
            return {"total": 0, "utilization": "N/A"}
        consumed = sum(
            1 for s in self._completed_slots if s.state == SlotState.CONSUMED
        )
        expired = sum(
            1 for s in self._completed_slots
            if s.state in (SlotState.EXPIRED, SlotState.SLASHED)
        )
        total_revenue = sum(
            s.total_bonds_collected for s in self._completed_slots
        )
        return {
            "total_completed": total,
            "consumed": consumed,
            "expired_or_slashed": expired,
            "utilization": f"{consumed/total:.1%}",
            "total_bonds_collected": total_revenue,
            "protocol_treasury": self.anch.balance_of(self.PROTOCOL_ADDRESS),
            "lp_pool": self.anch.balance_of(self.LP_POOL_ADDRESS),
        }

    def get_auction_config(self) -> dict:
        """Return current configuration for transparency."""
        c = self.config
        return {
            "anti_sybil": {
                "min_stake": c.min_stake,
                "max_bids_per_window": c.max_bids_per_window,
                "rate_limit_window_s": c.rate_limit_window,
                "require_identity": c.require_identity,
            },
            "anti_sniping": {
                "snipe_window_s": c.snipe_window,
                "extension_duration_s": c.extension_duration,
                "max_extensions": c.max_extensions,
                "candle_entropy": c.candle_entropy_source,
            },
            "anti_griefing": {
                "bond_rate_bps": c.bond_rate_bps,
                "min_increment_abs": c.min_increment_abs,
                "min_increment_pct": c.min_increment_pct,
                "consume_deadline_s": c.consume_deadline_seconds,
                "slash_rate_bps": c.slash_rate_bps,
                "escalating_slash": c.escalating_slash,
            },
            "economics": {
                "protocol_fee_bps": c.protocol_fee_bps,
                "lp_share_bps": c.lp_share_bps,
                "loyalty_bonus_bps": c.loyalty_bonus_bps,
                "referral_reward_bps": c.referral_reward_bps,
                "dynamic_pricing": c.dynamic_pricing,
            },
        }
