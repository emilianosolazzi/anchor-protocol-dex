"""
BRC-20 inscription builder for on-chain ANCHOR protocol operations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .truc import AnchorProof


class BRC20Inscription:
    """
    BRC-20 inscription builder for on-chain ANCHOR protocol operations.

    Generates deterministic JSON inscriptions following the BRC-20 standard
    (deploy / mint / transfer) plus ANCHOR-specific operations
    (proof / bid / claim / genesis).
    """

    @staticmethod
    def deploy(tick: str = "ANCH", max_supply: int = 21_000_000,
               mint_limit: int = 1_000) -> dict:
        return {
            "p": "brc-20",
            "op": "deploy",
            "tick": tick,
            "max": str(max_supply),
            "lim": str(mint_limit),
        }

    @staticmethod
    def mint(tick: str, to: str, amount: int) -> dict:
        return {
            "p": "brc-20",
            "op": "mint",
            "tick": tick,
            "amt": str(amount),
            "to": to,
        }

    @staticmethod
    def transfer(tick: str, from_addr: str, to_addr: str, amount: int) -> dict:
        return {
            "p": "brc-20",
            "op": "transfer",
            "tick": tick,
            "amt": str(amount),
            "from": from_addr,
            "to": to_addr,
        }

    @staticmethod
    def proof(proof_obj: 'AnchorProof') -> dict:
        return {
            "p": "ANCH",
            "op": "proof",
            "proof_id": proof_obj.proof_id[:16],
            "txid": proof_obj.parent_txid,
            "child": proof_obj.child_txid,
            "block": proof_obj.block_height,
            "creator": proof_obj.creator,
            "sig": proof_obj.signature.hex()[:32],
        }

    @staticmethod
    def bid(slot_id: str, bidder: str, amount: int, fee_rate: int) -> dict:
        return {
            "p": "ANCH",
            "op": "bid",
            "slot": slot_id[:16],
            "bidder": bidder,
            "amount": str(amount),
            "feerate": str(fee_rate),
        }

    @staticmethod
    def claim(proof_id: str, reward: int) -> dict:
        return {
            "p": "ANCH",
            "op": "claim",
            "proof_id": proof_id[:16],
            "reward": str(reward),
        }

    @staticmethod
    def genesis(bonus: int, until_block: int) -> dict:
        return {
            "p": "ANCH",
            "op": "genesis",
            "bonus": str(bonus),
            "until_block": str(until_block),
        }
