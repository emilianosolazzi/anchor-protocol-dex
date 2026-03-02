"""
Pool state dataclasses and enums.

Contains all the core data structures used across the AMM layer:
PoolState, PoolConfig, SwapType, LiquidityType, LiquidityChange,
FraudProof, StateCommitment, PendingSwap, FeeAccumulator, TWAPSnapshot.

Design notes:
  - All monetary amounts are in satoshis (int), never float.
  - Timestamps use time.time() for simulation; on-chain would use
    block height or nLockTime.
  - TWAP (time-weighted average price) is tracked per-block for
    manipulation-resistant price feeds.
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict


# ---------------------------------------------------------------------------
# Pool configuration (immutable after creation)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PoolConfig:
    """
    Immutable pool parameters set at creation time.

    These would be committed into the Taproot leaf script so they
    cannot be changed without a pool migration.
    """
    swap_fee_bps: int = 30           # 0.30% swap fee (default Uniswap-style)
    protocol_fee_bps: int = 5        # 0.05% protocol fee (from swap fee)
    liquidity_fee_bps: int = 10      # 0.10% add/remove liquidity fee
    max_price_impact_bps: int = 300  # 3% max price impact per swap
    max_swap_ratio_bps: int = 5000   # 50% max single-swap pool drain
    min_initial_liquidity: int = 1000  # min LP tokens for first deposit
    challenge_period_blocks: int = 144  # ~1 day on mainnet
    twap_window_blocks: int = 10     # TWAP averaging window

    def __post_init__(self):
        if self.swap_fee_bps < 0 or self.swap_fee_bps > 999:
            raise ValueError(
                f"swap_fee_bps must be in [0, 999], got {self.swap_fee_bps}"
            )
        if self.protocol_fee_bps < 0 or self.protocol_fee_bps > self.swap_fee_bps:
            raise ValueError(
                f"protocol_fee_bps must be in [0, {self.swap_fee_bps}], "
                f"got {self.protocol_fee_bps}"
            )


# ---------------------------------------------------------------------------
# Core enums
# ---------------------------------------------------------------------------

class SwapType(Enum):
    BTC_TO_ANCH = "btc_to_anch"
    ANCH_TO_BTC = "anch_to_btc"


class LiquidityType(Enum):
    ADD = "add"
    REMOVE = "remove"


# ---------------------------------------------------------------------------
# Pool state
# ---------------------------------------------------------------------------

@dataclass
class PoolState:
    """
    Represents the on-chain pool state at a specific point in time.

    All reserves are in satoshis.  The taproot_address and
    script_merkle_root identify the UTXO that holds these reserves.
    """
    btc_reserve: int
    anch_reserve: int
    lp_total: int
    taproot_address: str
    script_merkle_root: bytes

    @property
    def k_invariant(self) -> int:
        """Constant-product invariant: x * y."""
        return self.btc_reserve * self.anch_reserve

    @property
    def spot_price_sats_per_anch(self) -> int:
        """
        Instantaneous price in sats per ANCH (integer).

        Computed as btc_reserve * 10^8 / anch_reserve to preserve
        precision (result is in sats-per-ANCH * 10^8 fixed-point).
        For display, divide by 10^8.
        """
        if self.anch_reserve == 0:
            return 0
        return self.btc_reserve * 10**8 // self.anch_reserve

    def to_bytes(self) -> bytes:
        """Serialize state for hashing / commitment."""
        return struct.pack(
            '<QQQ',
            self.btc_reserve,
            self.anch_reserve,
            self.lp_total,
        )


# ---------------------------------------------------------------------------
# Fee accumulator
# ---------------------------------------------------------------------------

@dataclass
class FeeAccumulator:
    """
    Tracks cumulative fees earned by LPs and the protocol.

    On each swap:
      - total_swap_fee goes to LPs (left in pool, increases k)
      - protocol_fee is extracted for protocol treasury
      - These accumulate monotonically and can be queried by LPs
        to compute their share of earnings.
    """
    total_btc_fees: int = 0       # cumulative BTC fees earned by LPs
    total_anch_fees: int = 0      # cumulative ANCH fees earned by LPs
    protocol_btc_fees: int = 0    # cumulative protocol BTC fees
    protocol_anch_fees: int = 0   # cumulative protocol ANCH fees
    swap_count: int = 0           # total number of swaps executed

    def record_swap_fee(
        self,
        direction: SwapType,
        gross_fee: int,
        protocol_share: int,
    ):
        """Record fees from a swap."""
        lp_fee = gross_fee - protocol_share
        if direction == SwapType.BTC_TO_ANCH:
            self.total_btc_fees += lp_fee
            self.protocol_btc_fees += protocol_share
        else:
            self.total_anch_fees += lp_fee
            self.protocol_anch_fees += protocol_share
        self.swap_count += 1

    def total_lp_fees(self) -> Dict[str, int]:
        return {
            "btc": self.total_btc_fees,
            "anch": self.total_anch_fees,
        }

    def total_protocol_fees(self) -> Dict[str, int]:
        return {
            "btc": self.protocol_btc_fees,
            "anch": self.protocol_anch_fees,
        }


# ---------------------------------------------------------------------------
# TWAP snapshot
# ---------------------------------------------------------------------------

@dataclass
class TWAPSnapshot:
    """
    Time-weighted average price observation.

    Stores cumulative price * time so that the TWAP over any
    window [t1, t2] can be computed as:
      twap = (cumulative[t2] - cumulative[t1]) / (t2 - t1)

    This is manipulation-resistant because an attacker would
    need to sustain the manipulated price for the entire window
    to meaningfully move the TWAP.

    Based on Uniswap v2 oracle design.
    """
    timestamp: float
    btc_reserve: int
    anch_reserve: int
    # Cumulative price*time accumulators (fixed-point, *10^18)
    cumulative_price_btc: int = 0   # sum of (btc/anch * dt)
    cumulative_price_anch: int = 0  # sum of (anch/btc * dt)

    @staticmethod
    def compute_twap(
        snap_old: 'TWAPSnapshot',
        snap_new: 'TWAPSnapshot',
    ) -> Optional[int]:
        """
        Compute TWAP between two snapshots.

        Returns the time-weighted average price in fixed-point
        (sats-per-ANCH * 10^18).  Returns None if the time
        window is zero.
        """
        dt = snap_new.timestamp - snap_old.timestamp
        if dt <= 0:
            return None
        delta = snap_new.cumulative_price_btc - snap_old.cumulative_price_btc
        return int(delta / dt)


# ---------------------------------------------------------------------------
# Liquidity change
# ---------------------------------------------------------------------------

@dataclass
class LiquidityChange:
    user: str
    liq_type: LiquidityType
    btc_amount: int
    anch_amount: int
    lp_delta: int
    timestamp: float


# ---------------------------------------------------------------------------
# Fraud proof
# ---------------------------------------------------------------------------

@dataclass
class FraudProof:
    """
    BitVM-style fraud proof for challenging invalid swaps.

    FIX #5 -- includes bond amount and response window.

    In production, the proof_data would contain a BitVM
    bisection trace proving the claimed state transition is
    invalid.  The bond incentivizes honest behavior:
      - Successful challenger: gets reward from proposer's bond
      - Failed challenger: loses their own bond
    """
    claimed_state: PoolState
    swap_txid: str
    proof_data: bytes
    submitted_at: float = 0.0
    challenger: str = ""
    BOND_AMOUNT: int = 100_000       # sats
    RESPONSE_WINDOW: int = 144       # blocks (~1 day)

    def __post_init__(self):
        if self.submitted_at == 0.0:
            self.submitted_at = time.time()
        self.bond = self.BOND_AMOUNT

    @property
    def challenge_id(self) -> str:
        """Unique identifier for this challenge."""
        data = (
            self.swap_txid.encode()
            + self.challenger.encode()
            + struct.pack('<d', self.submitted_at)
        )
        return hashlib.sha256(data).hexdigest()[:16]


# ---------------------------------------------------------------------------
# State commitment (monotonic chain)
# ---------------------------------------------------------------------------

@dataclass
class StateCommitment:
    """
    FIX #1 -- monotonic commitment chain.
    Each pool state transition increments a sequence number.
    Replays are rejected because old witnesses carry stale seq.
    """
    btc_reserve: int
    anch_reserve: int
    lp_total: int
    sequence: int

    def digest(self) -> bytes:
        data = struct.pack(
            '<QQQQ',
            self.btc_reserve,
            self.anch_reserve,
            self.lp_total,
            self.sequence,
        )
        return hashlib.sha256(data).digest()

    @classmethod
    def from_pool_state(cls, state: PoolState, seq: int) -> 'StateCommitment':
        return cls(
            btc_reserve=state.btc_reserve,
            anch_reserve=state.anch_reserve,
            lp_total=state.lp_total,
            sequence=seq,
        )


# ---------------------------------------------------------------------------
# Pending swap
# ---------------------------------------------------------------------------

@dataclass
class PendingSwap:
    """
    A swap proposal waiting in the challenge window.

    Fields:
      - old_state / new_state: before/after pool states
      - btc_in / anch_delta: swap amounts (signed based on direction)
      - swap_type: direction of the swap
      - timestamp: when the swap was proposed
      - min_amount_out: slippage protection floor
      - old_seq: sequence number at proposal time (replay protection)
      - deadline_block: block height at which the swap expires
        if not finalized (0 = no deadline)
      - challenges: list of fraud proofs submitted against this swap
    """
    old_state: PoolState
    new_state: PoolState
    btc_in: int
    anch_delta: int
    swap_type: SwapType
    timestamp: float
    min_amount_out: int = 0
    old_seq: int = 0
    deadline_block: int = 0
    challenges: List[FraudProof] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Check if the swap has passed its deadline."""
        if self.deadline_block == 0:
            return False
        current_block = int(time.time() / 600)
        return current_block > self.deadline_block
