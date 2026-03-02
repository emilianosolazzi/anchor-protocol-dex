"""
Flask REST API for the ANCHOR DEX.

Provides :func:`create_flask_app` -- a factory that returns a configured
Flask application wired to a :class:`~py.persistence.PersistentDEX` instance.

All endpoints live under ``/api/v1/``.  A bare ``/health`` is also registered
for load-balancer probes.

Features:
  * Per-IP rate limiting (token bucket, 60 req/min)
  * X-Request-ID correlation on every response
  * Structured JSON error bodies with error codes
  * CORS preflight support
  * Input validation (length, range, enum checks)
  * Pagination on collection endpoints (/history)
  * Pool analytics: spot price, TWAP, fees, full pool info
  * DEX summary: TVL, protocol fees, swap count
  * ANCHOR protocol: stats, balances, auction slots, bidding
"""

from .flask_app import create_flask_app

__all__ = ["create_flask_app"]
