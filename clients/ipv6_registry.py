"""clients/ipv6_registry.py — SQLite-backed IPv6 allocation registry.

Stores per-site IPv6 prefixes (variable length, /32..../64) and the vvvv
segment allocations used to map legacy IPv4 networks into the hierarchical
IPv6 scheme. Conversion math lives in utils/ipv6_assembler.py; this module
is the persistence layer only.

Two tables, one DB file at data/ipv6_registry.db. Standard-library sqlite3
because the rest of the project has no ORM and the schema is two tables.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "data" / "ipv6_registry.db"

_init_lock = threading.Lock()
_initialized = False


SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    prefix        TEXT    NOT NULL UNIQUE,
    prefix_length INTEGER NOT NULL DEFAULT 48,
    role          TEXT,
    description   TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS allocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id        INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    vvvv           TEXT    NOT NULL,
    prefix_length  INTEGER NOT NULL,
    ipv4_subnet    TEXT,
    purpose        TEXT,
    status         TEXT    NOT NULL DEFAULT 'allocated',
    owner          TEXT,
    description    TEXT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (site_id, vvvv)
);

CREATE INDEX IF NOT EXISTS idx_allocations_site         ON allocations(site_id);
CREATE INDEX IF NOT EXISTS idx_allocations_site_v4      ON allocations(site_id, ipv4_subnet);
CREATE INDEX IF NOT EXISTS idx_allocations_site_status  ON allocations(site_id, status);
"""


def _connect_raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), detect_types=sqlite3.PARSE_DECLTYPES, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _migrate_sites_columns(conn: sqlite3.Connection) -> None:
    """Bring an older sites table (prefix_48 only) up to the current shape
    (prefix + prefix_length). No-op on fresh databases — the CREATE IF NOT
    EXISTS above already produces the new shape."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(sites)").fetchall()}
    if "prefix" not in cols and "prefix_48" in cols:
        conn.execute("ALTER TABLE sites RENAME COLUMN prefix_48 TO prefix")
        cols.discard("prefix_48"); cols.add("prefix")
    if "prefix_length" not in cols:
        conn.execute("ALTER TABLE sites ADD COLUMN prefix_length INTEGER NOT NULL DEFAULT 48")


def _sites_name_is_unique(conn: sqlite3.Connection) -> bool:
    """True if sites.name has a UNIQUE constraint (auto-created unique index
    covering exactly the name column). Legacy schemas had this; current
    schema does not."""
    for idx in conn.execute("PRAGMA index_list(sites)").fetchall():
        if not idx["unique"]:
            continue
        cols = [r["name"] for r in conn.execute(f"PRAGMA index_info({idx['name']})").fetchall()]
        if cols == ["name"]:
            return True
    return False


def _migrate_drop_name_unique(path: Path) -> None:
    """Drop the legacy UNIQUE constraint on sites.name. SQLite has no DDL
    for dropping a column constraint, so we recreate the table.

    FK enforcement is toggled at the connection level rather than inside a
    transaction (SQLite ignores PRAGMA foreign_keys mid-transaction). Done
    on its own connection so the outer init_schema connection isn't left
    with FKs disabled."""
    conn = _connect_raw(path)
    try:
        if not _sites_name_is_unique(conn):
            return
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            # Individual execute() calls so the transaction stays open —
            # executescript() implicitly commits any pending transaction.
            conn.execute("BEGIN")
            conn.execute(
                """
                CREATE TABLE sites_new (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    name          TEXT    NOT NULL,
                    prefix        TEXT    NOT NULL UNIQUE,
                    prefix_length INTEGER NOT NULL DEFAULT 48,
                    role          TEXT,
                    description   TEXT,
                    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            conn.execute(
                "INSERT INTO sites_new (id, name, prefix, prefix_length, role, description, created_at, updated_at) "
                "SELECT id, name, prefix, prefix_length, role, description, created_at, updated_at FROM sites"
            )
            conn.execute("DROP TABLE sites")
            conn.execute("ALTER TABLE sites_new RENAME TO sites")
            conn.execute("COMMIT")
            violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError(
                    f"FK integrity check failed after sites migration: {violations}"
                )
            logger.info("Migrated sites table: dropped UNIQUE on name")
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
    finally:
        conn.close()


def init_schema(path: Optional[Path] = None) -> None:
    """Create tables and indexes if missing. Safe to call repeatedly."""
    global _initialized
    target = path or DB_PATH
    with _init_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        with _connect_raw(target) as conn:
            conn.executescript(SCHEMA)
            _migrate_sites_columns(conn)
        _migrate_drop_name_unique(target)
        if target == DB_PATH:
            _initialized = True
        logger.info(f"IPv6 registry schema ready at {target}")


@contextmanager
def connect(path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    """Context manager yielding a connection with foreign keys enforced."""
    target = path or DB_PATH
    if target == DB_PATH and not _initialized:
        init_schema(target)
    conn = _connect_raw(target)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Sites ────────────────────────────────────────────────────────────────────

def list_sites(path: Optional[Path] = None) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute("SELECT * FROM sites ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_site(site_id: int, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def get_site_by_prefix(prefix: str, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM sites WHERE prefix = ?", (prefix,)).fetchone()
    return dict(row) if row else None


def create_site(name: str, prefix: str, prefix_length: int = 48,
                role: Optional[str] = None, description: Optional[str] = None,
                path: Optional[Path] = None) -> dict:
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO sites (name, prefix, prefix_length, role, description) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, prefix, prefix_length, role, description),
        )
        site_id = cur.lastrowid
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return dict(row)


def update_site(site_id: int, *, name: Optional[str] = None, prefix: Optional[str] = None,
                prefix_length: Optional[int] = None,
                role: Optional[str] = None, description: Optional[str] = None,
                path: Optional[Path] = None) -> Optional[dict]:
    fields, values = [], []
    for col, val in (("name", name), ("prefix", prefix),
                     ("prefix_length", prefix_length),
                     ("role", role), ("description", description)):
        if val is not None:
            fields.append(f"{col} = ?")
            values.append(val)
    if not fields:
        return get_site(site_id, path)
    fields.append("updated_at = datetime('now')")
    values.append(site_id)
    with connect(path) as conn:
        conn.execute(f"UPDATE sites SET {', '.join(fields)} WHERE id = ?", values)
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def delete_site(site_id: int, path: Optional[Path] = None) -> int:
    """Returns number of rows deleted (0 or 1). Allocations cascade."""
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        return cur.rowcount


# ── Allocations ──────────────────────────────────────────────────────────────

_ALLOC_SELECT = (
    "SELECT a.*, s.name AS site_name, s.prefix AS site_prefix, "
    "       s.prefix_length AS site_prefix_length "
    "FROM allocations a JOIN sites s ON s.id = a.site_id"
)


def list_allocations(site_id: Optional[int] = None, path: Optional[Path] = None) -> list[dict]:
    sql = _ALLOC_SELECT
    args: tuple = ()
    if site_id is not None:
        sql += " WHERE a.site_id = ?"
        args = (site_id,)
    sql += " ORDER BY s.name, a.vvvv"
    with connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def get_allocation(alloc_id: int, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute(_ALLOC_SELECT + " WHERE a.id = ?", (alloc_id,)).fetchone()
    return dict(row) if row else None


def create_allocation(site_id: int, vvvv: str, prefix_length: int, *,
                      ipv4_subnet: Optional[str] = None, purpose: Optional[str] = None,
                      status: str = "allocated", owner: Optional[str] = None,
                      description: Optional[str] = None,
                      path: Optional[Path] = None) -> dict:
    with connect(path) as conn:
        cur = conn.execute(
            """INSERT INTO allocations
               (site_id, vvvv, prefix_length, ipv4_subnet, purpose, status, owner, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (site_id, vvvv, prefix_length, ipv4_subnet, purpose, status, owner, description),
        )
        row = conn.execute(_ALLOC_SELECT + " WHERE a.id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


def update_allocation(alloc_id: int, *, vvvv: Optional[str] = None,
                      prefix_length: Optional[int] = None,
                      ipv4_subnet: Optional[str] = None, purpose: Optional[str] = None,
                      status: Optional[str] = None, owner: Optional[str] = None,
                      description: Optional[str] = None,
                      path: Optional[Path] = None) -> Optional[dict]:
    fields, values = [], []
    for col, val in (("vvvv", vvvv), ("prefix_length", prefix_length),
                     ("ipv4_subnet", ipv4_subnet), ("purpose", purpose),
                     ("status", status), ("owner", owner), ("description", description)):
        if val is not None:
            fields.append(f"{col} = ?")
            values.append(val)
    if not fields:
        return get_allocation(alloc_id, path)
    fields.append("updated_at = datetime('now')")
    values.append(alloc_id)
    with connect(path) as conn:
        conn.execute(f"UPDATE allocations SET {', '.join(fields)} WHERE id = ?", values)
    return get_allocation(alloc_id, path)


def delete_allocation(alloc_id: int, path: Optional[Path] = None) -> int:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM allocations WHERE id = ?", (alloc_id,))
        return cur.rowcount


def find_ipv4_collision(site_id: int, ipv4_subnet: str,
                        exclude_alloc_id: Optional[int] = None,
                        path: Optional[Path] = None) -> list[dict]:
    """Return allocations in the same site already mapped to this ipv4_subnet.
    Soft-warn signal; callers may still allow the insert with a confirm flag."""
    if not ipv4_subnet:
        return []
    sql = "SELECT * FROM allocations WHERE site_id = ? AND ipv4_subnet = ?"
    args: list = [site_id, ipv4_subnet]
    if exclude_alloc_id is not None:
        sql += " AND id != ?"
        args.append(exclude_alloc_id)
    with connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]
