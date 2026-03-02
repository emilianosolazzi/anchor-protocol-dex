"""
Pool state dataclasses and enums.

Contains all the core data structures used across the AMM layer:
PoolState, SwapType, LiquidityType, LiquidityChange, FraudProof,
StateCommitment, PendingSwap.
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


@dataclass
class PoolState:
    btc_reserve: int
    anch_reserve: int
    lp_total: int
    taproot_address: str
    script_merkle_root: bytes


class SwapType(Enum):
    BTC_TO_ANCH = "btc_to_anch"
    ANCH_TO_BTC = "anch_to_btc"


class LiquidityType(Enum):
    ADD = "add"
    REMOVE = "remove"


@dataclass
class LiquidityChange:
    user: str
    liq_type: LiquidityType
    btc_amount: int
    anch_amount: int
    lp_delta: int
    timestamp: float


@dataclass
class FraudProof:
    """
    BitVM-style fraud proof for challenging invalid swaps.
    FIX #5 -- includes bond amount and response window.
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


@dataclass
class PendingSwap:
    old_state: PoolState
    new_state: PoolState
    btc_in: int
    anch_delta: int
    swap_type: SwapType
    timestamp: float
    min_amount_out: int = 0
    old_seq: int = 0
    challenges: List[FraudProof] = field(default_factory=list)
