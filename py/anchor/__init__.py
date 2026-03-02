"""ANCHOR protocol -- ephemeral-anchor fee-market + proof-of-anchor minting."""

# Auction layer
from .auction import (
    AuctionConfig,
    AuctionType,
    SlotState,
    AnchorSlot,
    SlotAuction,
    ReputationProfile,
)

# BRC-20 inscription builder
from .brc20 import BRC20Inscription, inscription_content_id

# TRUC (v3) transaction builder
from .truc import TRUCTransactionBuilder, AnchorProof

# Proof verification & anti-replay
from .verifier import AnchorVerifier, ClaimRegistry

# RGB client-side validated assets
from .rgb import RGBAsset, SingleUseSeal, RGBTransfer

# HTLC atomic swaps
from .htlc import HTLCAtomicSwap, HTLCContract, MultiSigPool

# Proof-of-Anchor minter
from .minter import ProofOfAnchorMinter

# Protocol orchestrator
from .protocol import AnchorProtocol
