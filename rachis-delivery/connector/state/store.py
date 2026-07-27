"""
rachis_connector.state.store
=============================

Durable connector state, SQLite-backed. The reference core kept these in memory; a shippable
connector cannot, because losing them has specific consequences:

  * salt store (thesis Appendix A.11 D1): lose a pointer/withheld salt and you can never
    honour a callback for that field again, because you cannot reconstruct the leaf that
    verifies against the already-signed root.
  * audit (thesis §12.1, §16 local audit): the source-side record of everything asked and
    given. It must survive restart and be exportable for reconciliation with core.
  * callback queue: time-bound sealed releases waiting for their window (thesis §12.1).
  * outbound queue: packages awaiting delivery when core is unreachable (thesis §22.3
    disconnected operation).

SQLite is chosen deliberately: single-file, no server, air-gap trivial, ACID, and present
in the Python standard library. A larger deployment swaps the DAO for Postgres without
touching callers.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterator, List, Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS salts (
    record_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (record_id, field_name)
);
CREATE TABLE IF NOT EXISTS leaf_order (
    record_id TEXT PRIMARY KEY,
    ordered_names TEXT NOT NULL,      -- json list, canonical order incl __header__
    leaf_hashes TEXT NOT NULL,        -- json list of hex, same order
    root_hex TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,               -- ingest | callback | expectation | delivery | error
    detail TEXT NOT NULL              -- json
);
CREATE TABLE IF NOT EXISTS callbacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    requester TEXT NOT NULL,
    sealed TEXT NOT NULL,             -- json SealedRelease
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL,
    package TEXT NOT NULL,            -- json DisclosurePackage
    delivered INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
"""


class StateStore:
    """Thread-safe SQLite state. One instance per connector process."""

    def __init__(self, db_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ salts

    def salt_for(self, record_id: str, field_name: str) -> str:
        """Return a stable salt, minting and persisting one on first request (D1)."""
        with self._tx() as c:
            row = c.execute(
                "SELECT salt FROM salts WHERE record_id=? AND field_name=?",
                (record_id, field_name),
            ).fetchone()
            if row:
                return row[0]
            salt = os.urandom(16).hex()
            c.execute(
                "INSERT INTO salts(record_id, field_name, salt, created_at) VALUES (?,?,?,?)",
                (record_id, field_name, salt, time.time()),
            )
            return salt

    # ------------------------------------------------------------------ bound record (for callback proofs)

    def save_binding(self, record_id: str, ordered_names: List[str],
                     leaf_hashes_hex: List[str], root_hex: str, signature_hex: str) -> None:
        """Persist the leaf order and hashes so a later callback can rebuild the tree and
        prove a released field against the ORIGINAL root (thesis §12.1)."""
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO leaf_order"
                "(record_id, ordered_names, leaf_hashes, root_hex, signature_hex, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (record_id, json.dumps(ordered_names), json.dumps(leaf_hashes_hex),
                 root_hex, signature_hex, time.time()),
            )

    def get_binding(self, record_id: str) -> Optional[dict]:
        with self._tx() as c:
            row = c.execute(
                "SELECT ordered_names, leaf_hashes, root_hex, signature_hex "
                "FROM leaf_order WHERE record_id=?", (record_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "ordered_names": json.loads(row[0]),
            "leaf_hashes": json.loads(row[1]),
            "root_hex": row[2],
            "signature_hex": row[3],
        }

    # ------------------------------------------------------------------ audit

    def audit(self, kind: str, detail: dict) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO audit(ts, kind, detail) VALUES (?,?,?)",
                      (time.time(), kind, json.dumps(detail, sort_keys=True)))

    def audit_export(self, since: float = 0.0) -> List[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT ts, kind, detail FROM audit WHERE ts>=? ORDER BY id", (since,),
            ).fetchall()
        return [{"ts": r[0], "kind": r[1], "detail": json.loads(r[2])} for r in rows]

    # ------------------------------------------------------------------ callbacks

    def enqueue_callback(self, record_id: str, field_name: str, requester: str,
                         sealed_json: str, not_before: str, not_after: str) -> int:
        with self._tx() as c:
            cur = c.execute(
                "INSERT INTO callbacks(record_id, field_name, requester, sealed, "
                "not_before, not_after, created_at) VALUES (?,?,?,?,?,?,?)",
                (record_id, field_name, requester, sealed_json, not_before, not_after,
                 time.time()),
            )
            return cur.lastrowid

    def due_callbacks(self, now_iso: str) -> List[dict]:
        """Sealed releases whose window has opened and which are not yet delivered."""
        with self._tx() as c:
            rows = c.execute(
                "SELECT id, sealed, not_before, not_after FROM callbacks "
                "WHERE delivered=0 AND not_before<=?", (now_iso,),
            ).fetchall()
        return [{"id": r[0], "sealed": json.loads(r[1]),
                 "not_before": r[2], "not_after": r[3]} for r in rows]

    def mark_callback_delivered(self, callback_id: int) -> None:
        with self._tx() as c:
            c.execute("UPDATE callbacks SET delivered=1 WHERE id=?", (callback_id,))

    # ------------------------------------------------------------------ outbound

    def enqueue_outbound(self, record_id: str, package_json: str) -> int:
        with self._tx() as c:
            cur = c.execute(
                "INSERT INTO outbound(record_id, package, created_at) VALUES (?,?,?)",
                (record_id, package_json, time.time()),
            )
            return cur.lastrowid

    def pending_outbound(self, limit: int = 100) -> List[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT id, record_id, package, attempts FROM outbound "
                "WHERE delivered=0 ORDER BY id LIMIT ?", (limit,),
            ).fetchall()
        return [{"id": r[0], "record_id": r[1], "package": json.loads(r[2]),
                 "attempts": r[3]} for r in rows]

    def mark_delivered(self, outbound_id: int) -> None:
        with self._tx() as c:
            c.execute("UPDATE outbound SET delivered=1 WHERE id=?", (outbound_id,))

    def record_attempt(self, outbound_id: int) -> None:
        with self._tx() as c:
            c.execute("UPDATE outbound SET attempts=attempts+1 WHERE id=?", (outbound_id,))
