"""
SQLite persistence layer + PersistentDEX wrapper.

Thread-safe: all mutations serialised via _mutex.
"""
from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional

from .amm.state import SwapType
from .production import ProductionDEX


class StateStore:
    """
    SQLite-backed persistence for the DEX.
    Stores user balances, pool state, swap history, and RGB history.
    """
    DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "dex_state.db")

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_PATH
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self):
        c = self._conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS pool_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                btc_reserve INTEGER NOT NULL,
                anch_reserve INTEGER NOT NULL,
                lp_total    INTEGER NOT NULL DEFAULT 0,
                seq         INTEGER NOT NULL DEFAULT 0,
                oracle_price REAL NOT NULL DEFAULT 10.0,
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS user_balances (
                user        TEXT PRIMARY KEY,
                btc_sats    INTEGER NOT NULL DEFAULT 0,
                anch        INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS swap_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                swap_id     TEXT NOT NULL,
                user        TEXT NOT NULL,
                direction   TEXT NOT NULL,
                btc_amount  INTEGER NOT NULL,
                anch_amount INTEGER NOT NULL,
                status      TEXT NOT NULL DEFAULT 'completed',
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS rgb_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type  TEXT NOT NULL,
                data        TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        c.commit()

    # -- Pool state --
    def save_pool(self, pdex: ProductionDEX):
        info = pdex.get_pool_info()
        self._conn.execute("""
            INSERT INTO pool_state (id, btc_reserve, anch_reserve, lp_total, seq, oracle_price)
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                btc_reserve=excluded.btc_reserve,
                anch_reserve=excluded.anch_reserve,
                lp_total=excluded.lp_total,
                seq=excluded.seq,
                oracle_price=excluded.oracle_price,
                updated_at=datetime('now')
        """, (info["btc_reserve"], info["anch_reserve"], info["lp_total"],
              pdex.liquidity_pool.pool._seq, pdex.oracle.price))
        self._conn.commit()

    def load_pool(self) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM pool_state WHERE id=1"
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    # -- User balances --
    def save_user(self, user: str, btc_sats: int, anch: int):
        self._conn.execute("""
            INSERT INTO user_balances (user, btc_sats, anch) VALUES (?, ?, ?)
            ON CONFLICT(user) DO UPDATE SET btc_sats=excluded.btc_sats, anch=excluded.anch
        """, (user, btc_sats, anch))
        self._conn.commit()

    def load_user(self, user: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM user_balances WHERE user=?", (user,)
        ).fetchone()
        return dict(row) if row else None

    def load_all_users(self) -> List[dict]:
        rows = self._conn.execute("SELECT * FROM user_balances").fetchall()
        return [dict(r) for r in rows]

    # -- Swap history --
    def record_swap(self, swap_id: str, user: str, direction: str,
                    btc_amount: int, anch_amount: int, status: str = "completed"):
        self._conn.execute("""
            INSERT INTO swap_history (swap_id, user, direction, btc_amount, anch_amount, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (swap_id, user, direction, btc_amount, anch_amount, status))
        self._conn.commit()

    def get_swap_history(self, limit: int = 50) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM swap_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- RGB history --
    def record_rgb_event(self, event_type: str, data: dict):
        self._conn.execute("""
            INSERT INTO rgb_history (event_type, data) VALUES (?, ?)
        """, (event_type, json.dumps(data)))
        self._conn.commit()

    def get_rgb_history(self, limit: int = 50) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM rgb_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self._conn.close()


class PersistentDEX:
    """
    Wraps ProductionDEX with automatic state persistence.
    Thread-safe: all mutations serialised via _mutex.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._mutex = threading.Lock()
        self.store = StateStore(db_path)
        saved = self.store.load_pool()
        if saved:
            self.dex = ProductionDEX(
                initial_btc=saved["btc_reserve"],
                initial_anch=saved["anch_reserve"],
            )
            self.dex.liquidity_pool.pool._seq = saved["seq"]
            self.dex.oracle._price = float(saved["oracle_price"])
            self.dex.oracle._updated_at = time.time()
            for u in self.store.load_all_users():
                if u["btc_sats"] > 0:
                    self.dex.htlc_engine._btc_balances[u["user"]] = u["btc_sats"]
                if u["anch"] > 0:
                    self.dex.anch_rgb.balances[u["user"]] = u["anch"]
            print(f"  [DB] Loaded pool state: BTC={saved['btc_reserve']:,}  "
                  f"ANCH={saved['anch_reserve']:,}  seq={saved['seq']}")
        else:
            self.dex = ProductionDEX()
            self._save_all()
            print(f"  [DB] Initialised fresh pool (1 BTC / 10M ANCH)")

    def _save_all(self):
        self.store.save_pool(self.dex)

    def _save_user(self, user: str):
        b = self.dex.get_balances(user)
        self.store.save_user(user, b["btc_sats"], b["anch"])

    def fund_btc(self, user: str, amount: int):
        with self._mutex:
            self.dex.fund_user_btc(user, amount)
            self._save_user(user)
            self._save_all()
            print(f"  Funded {user} with {amount:,} sats")

    def fund_anch(self, user: str, amount: int):
        with self._mutex:
            self.dex.fund_user_anch(user, amount)
            self._save_user(user)
            self._save_all()
            print(f"  Funded {user} with {amount:,} ANCH")

    def _sync_oracle(self):
        """Sync oracle price from pool reserves after a swap."""
        info = self.dex.get_pool_info()
        if info["anch_reserve"] > 0:
            new_price = float(info["btc_reserve"] / info["anch_reserve"])
            if new_price > 0 and not math.isnan(new_price) and not math.isinf(new_price):
                try:
                    self.dex.oracle.update_price(new_price)
                except ValueError:
                    # Deviation guard rejected the update — this can happen
                    # after a large swap.  Fall through; oracle keeps its
                    # last-known-good price which is safer than bypassing
                    # the guard.
                    pass

    def swap_btc_to_anch(self, user: str, btc_amount: int) -> bool:
        with self._mutex:
            try:
                sid, _, _ = self.dex.swap_btc_for_anch(user, btc_amount)
                # Capture the actual ANCH output from the pending swap
                anch_amount = self.dex._pending[sid]["anch_amount"]
                ok = self.dex.complete_swap(sid)
                if ok:
                    self._sync_oracle()
                    self.store.record_swap(sid, user, "BTC_TO_ANCH", btc_amount,
                                           anch_amount)
                    self._save_user(user)
                    self._save_all()
                return ok
            except (ValueError, ArithmeticError) as e:
                print(f"  Swap failed: {e}")
                return False

    def swap_anch_to_btc(self, user: str, anch_amount: int) -> bool:
        with self._mutex:
            try:
                sid, _, _ = self.dex.swap_anch_for_btc(user, anch_amount)
                # Capture the actual BTC output from the pending swap
                btc_amount = self.dex._pending[sid]["btc_amount"]
                ok = self.dex.complete_swap(sid)
                if ok:
                    self._sync_oracle()
                    self.store.record_swap(sid, user, "ANCH_TO_BTC",
                                           btc_amount,
                                           anch_amount)
                    self._save_user(user)
                    self._save_all()
                return ok
            except (ValueError, ArithmeticError) as e:
                print(f"  Swap failed: {e}")
                return False

    def get_balances(self, user: str) -> dict:
        return self.dex.get_balances(user)

    def get_pool_info(self) -> dict:
        return self.dex.get_pool_info()

    def get_quote(self, direction: str, amount: int) -> int:
        if direction.upper() in ("BTC_TO_ANCH", "BTC", "B2A"):
            return self.dex.liquidity_pool.get_quote(SwapType.BTC_TO_ANCH, amount)
        else:
            return self.dex.liquidity_pool.get_quote(SwapType.ANCH_TO_BTC, amount)

    def save_rgb_state(self):
        with self._mutex:
            commitment = self.dex.anch_rgb.save_rgb_state()
            self.store.record_rgb_event("state_commitment", {
                "commitment": commitment.hex(),
                "balances": dict(self.dex.anch_rgb.balances),
            })
        return commitment

    def history(self, limit: int = 20) -> List[dict]:
        return self.store.get_swap_history(limit)
