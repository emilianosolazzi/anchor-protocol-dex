"""
ANCHOR DEX -- Fully On-Chain DEX Simulation (Python package)

A four-layer decentralized exchange built on Bitcoin Script:
  Layer 1:  RGB client-side validated tokens (ANCH)
  Layer 2:  HTLC atomic swaps (real Bitcoin Script)
  Layer 3:  BitVM / Covenant AMM (hybrid covenant engine)
  Layer 4:  ANCHOR protocol (ephemeral anchor fee-market)

Dependencies:
  pip install python-bitcoinlib coincurve flask

Network: regtest
"""
from __future__ import annotations

import bitcoin
bitcoin.SelectParams('regtest')
