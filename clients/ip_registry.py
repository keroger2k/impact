"""clients/ip_registry.py — Site-centric, dual-stack IPAM registry (SQLite).

This is the persistence layer for the rebuilt IP Address Registry. It replaces
the IPv6-only ``clients.ipv6_registry`` (where a "site" *was* a single IPv6
prefix). Here a **site** is the first-class entity, keyed by its short
``site_code`` (I001, K015, …), and every IPv4 *or* IPv6 network the site owns
is a row in the **prefixes** table. One physical site → one ``sites`` row →
many ``prefixes`` rows across both families.

Design notes:
  * ``site_code`` is the join key used everywhere (DNAC site paths, hostnames,
    the three seed CSVs) — so it's a real UNIQUE column, not a regex over a
    free-text name.
  * Shared infrastructure aggregates (e.g. the STIP /48 that many sites carve a
    /64 out of) are ``prefixes`` rows with ``site_id IS NULL`` and
    ``role='container'``. A site's STIP /64 then has ``site_id`` = that site
    and ``parent_id`` = the container, so the /64 is attributed to the site
    while the /48 stays shared.
  * ``prefixes.parent_id`` is a self-FK giving the hierarchy the UI renders
    (STIP /64 under STIP /48; a VLAN /64 under the site /56; a subnet under its
    aggregate).
  * ``vvvv`` is kept only as a derived convenience for IPv6 carved under a
    parent — it is NOT the table's spine (the old ``UNIQUE(site_id, vvvv)`` is
    gone). Overlap is checked on real CIDRs via ``utils.ipam_net``.
  * Audit columns (``audit_state``, ``last_seen_at``, ``last_seen_source``)
    record what the reconciliation against live sources last observed.

Stdlib ``sqlite3`` only — the codebase has no ORM and this is two tables.
Conversion math (vvvv assemble/decode) stays in ``utils.ipv6_assembler``;
family-agnostic CIDR math is in ``utils.ipam_net``.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from utils import ipam_net

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "data" / "ip_registry.db"

_init_lock = threading.Lock()
_initialized = False

# Lifecycle vocabularies (enforced at the router layer; exposed here so the
# router and importers share one source of truth).
SITE_STATUSES = ("active", "planned", "decommissioned")
PREFIX_STATUSES = ("planned", "allocated", "deployed", "reserved", "decommissioned")
PREFIX_SOURCES = ("manual", "csv", "dnac", "nexus", "panorama", "aci", "audit")
AUDIT_STATES = ("in-sync", "registry-only", "network-only", "mismatch")

# Common prefix roles (free-form text in the DB; documented here for callers).
#   site-aggregate — a site's owned IPv4 supernet/block
#   site           — a site's primary IPv6 prefix (e.g. its /56)
#   stip           — a site's STIP /64 (child of the shared STIP /48 container)
#   vlan           — a per-VLAN subnet
#   container      — shared aggregate that is not owned by a single site
#   mgmt / transit / loopback — descriptive subnet roles

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_code   TEXT    NOT NULL UNIQUE,
    name        TEXT,
    region      TEXT,
    role        TEXT,
    status      TEXT    NOT NULL DEFAULT 'active',
    description TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS prefixes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id          INTEGER REFERENCES sites(id)    ON DELETE CASCADE,
    parent_id        INTEGER REFERENCES prefixes(id) ON DELETE SET NULL,
    family           INTEGER NOT NULL,          -- 4 or 6
    network          TEXT    NOT NULL,          -- masked network address
    prefix_length    INTEGER NOT NULL,
    cidr             TEXT    NOT NULL,          -- canonical "network/len"
    role             TEXT,
    vlan_id          INTEGER,
    vvvv             TEXT,                       -- derived 4-hex for carved IPv6
    label            TEXT,
    status           TEXT    NOT NULL DEFAULT 'allocated',
    source           TEXT    NOT NULL DEFAULT 'manual',
    audit_state      TEXT,
    last_seen_at     TEXT,
    last_seen_source TEXT,
    owner            TEXT,
    description      TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (site_id, cidr)
);

CREATE INDEX IF NOT EXISTS idx_prefixes_site        ON prefixes(site_id);
CREATE INDEX IF NOT EXISTS idx_prefixes_parent      ON prefixes(parent_id);
CREATE INDEX IF NOT EXISTS idx_prefixes_family      ON prefixes(family);
CREATE INDEX IF NOT EXISTS idx_prefixes_cidr        ON prefixes(cidr);
CREATE INDEX IF NOT EXISTS idx_prefixes_site_family ON prefixes(site_id, family);
CREATE INDEX IF NOT EXISTS idx_prefixes_audit       ON prefixes(audit_state);
"""


def _connect_raw(path: Path):
    import sqlite3
    conn = sqlite3.connect(str(path), detect_types=sqlite3.PARSE_DECLTYPES, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _dedupe_containers(conn) -> None:
    """Collapse any pre-existing duplicate shared containers (rows with
    ``site_id IS NULL`` sharing a ``cidr``) before the partial unique index is
    built — keep the lowest id, re-point orphaned children's ``parent_id`` to it,
    delete the rest. No-op once the index is in force."""
    dupes = conn.execute(
        "SELECT cidr, MIN(id) AS keep FROM prefixes WHERE site_id IS NULL "
        "GROUP BY cidr HAVING COUNT(*) > 1"
    ).fetchall()
    for d in dupes:
        cidr, keep = d["cidr"], d["keep"]
        victims = [r["id"] for r in conn.execute(
            "SELECT id FROM prefixes WHERE site_id IS NULL AND cidr = ? AND id != ?",
            (cidr, keep)).fetchall()]
        if not victims:
            continue
        qmarks = ",".join("?" * len(victims))
        conn.execute(f"UPDATE prefixes SET parent_id = ? WHERE parent_id IN ({qmarks})",
                     [keep, *victims])
        conn.execute(f"DELETE FROM prefixes WHERE id IN ({qmarks})", victims)
        logger.warning("ip_registry: collapsed %d duplicate container(s) for %s into #%d",
                       len(victims), cidr, keep)


def init_schema(path: Optional[Path] = None) -> None:
    """Create tables and indexes if missing. Safe to call repeatedly."""
    global _initialized
    target = path or DB_PATH
    with _init_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        conn = _connect_raw(target)
        try:
            conn.executescript(SCHEMA)
            # Enforce one shared container per CIDR. A plain UNIQUE(site_id, cidr)
            # can't do this because SQLite treats NULL site_id as distinct, so
            # two containers with the same CIDR would slip through. De-dupe any
            # legacy rows first so the index can be built on an existing DB.
            _dedupe_containers(conn)
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_prefixes_container_cidr "
                "ON prefixes(cidr) WHERE site_id IS NULL"
            )
            conn.commit()
        finally:
            conn.close()
        if target == DB_PATH:
            _initialized = True
        logger.info(f"IP registry schema ready at {target}")


@contextmanager
def connect(path: Optional[Path] = None) -> Iterator["sqlite3.Connection"]:  # noqa: F821
    """Context manager yielding a connection with foreign keys enforced and a
    commit-on-success / rollback-on-error transaction boundary."""
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
        rows = conn.execute("SELECT * FROM sites ORDER BY site_code").fetchall()
    return [dict(r) for r in rows]


def get_site(site_id: int, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def get_site_by_code(site_code: str, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM sites WHERE site_code = ? COLLATE NOCASE", (site_code,)
        ).fetchone()
    return dict(row) if row else None


def create_site(site_code: str, *, name: Optional[str] = None,
                region: Optional[str] = None, role: Optional[str] = None,
                status: str = "active", description: Optional[str] = None,
                path: Optional[Path] = None) -> dict:
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO sites (site_code, name, region, role, status, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (site_code, name, region, role, status, description),
        )
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


def update_site(site_id: int, *, site_code: Optional[str] = None,
                name: Optional[str] = None, region: Optional[str] = None,
                role: Optional[str] = None, status: Optional[str] = None,
                description: Optional[str] = None,
                path: Optional[Path] = None) -> Optional[dict]:
    fields, values = [], []
    for col, val in (("site_code", site_code), ("name", name), ("region", region),
                     ("role", role), ("status", status), ("description", description)):
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


def upsert_site(site_code: str, *, name: Optional[str] = None,
                region: Optional[str] = None, role: Optional[str] = None,
                status: Optional[str] = None, description: Optional[str] = None,
                path: Optional[Path] = None) -> tuple[dict, bool]:
    """Create the site if its code is new, else update the provided (non-None)
    fields. Returns ``(row, created)``. The join-key entry point for importers
    and audit bulk-accept."""
    existing = get_site_by_code(site_code, path)
    if existing:
        updated = update_site(
            existing["id"], name=name, region=region, role=role,
            status=status, description=description, path=path,
        )
        return updated, False
    created = create_site(
        site_code, name=name, region=region, role=role,
        status=status or "active", description=description, path=path,
    )
    return created, True


def delete_site(site_id: int, path: Optional[Path] = None) -> int:
    """Delete a site. Its prefixes cascade-delete; any container prefixes that
    were a *parent* of those rows are untouched. Returns rows deleted (0/1)."""
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        return cur.rowcount


# ── Prefixes ─────────────────────────────────────────────────────────────────

_PREFIX_SELECT = (
    "SELECT p.*, s.site_code AS site_code, s.name AS site_name "
    "FROM prefixes p LEFT JOIN sites s ON s.id = p.site_id"
)


def list_prefixes(site_id: Optional[int] = None, *, family: Optional[int] = None,
                  containers_only: bool = False, path: Optional[Path] = None) -> list[dict]:
    """List prefixes, optionally scoped to a site and/or family.

    ``site_id`` filters to one site's prefixes. ``containers_only`` returns the
    shared (``site_id IS NULL``) aggregates instead. Without either, returns
    everything (sites' prefixes and containers)."""
    sql = _PREFIX_SELECT
    clauses, args = [], []
    if containers_only:
        clauses.append("p.site_id IS NULL")
    elif site_id is not None:
        clauses.append("p.site_id = ?")
        args.append(site_id)
    if family is not None:
        clauses.append("p.family = ?")
        args.append(family)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY s.site_code IS NULL, s.site_code, p.family, p.prefix_length, p.cidr"
    with connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def get_prefix(prefix_id: int, path: Optional[Path] = None) -> Optional[dict]:
    with connect(path) as conn:
        row = conn.execute(_PREFIX_SELECT + " WHERE p.id = ?", (prefix_id,)).fetchone()
    return dict(row) if row else None


def find_prefix_by_cidr(cidr: str, *, site_id: Optional[int] = None,
                        path: Optional[Path] = None) -> Optional[dict]:
    """Exact canonical-CIDR lookup within a scope. ``site_id=None`` searches the
    shared containers (``site_id IS NULL``); a value searches that site."""
    _, _, _, canon = ipam_net.canonical(cidr)
    sql = _PREFIX_SELECT + " WHERE p.cidr = ?"
    args: list = [canon]
    if site_id is None:
        sql += " AND p.site_id IS NULL"
    else:
        sql += " AND p.site_id = ?"
        args.append(site_id)
    with connect(path) as conn:
        row = conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def create_prefix(cidr: str, *, site_id: Optional[int] = None,
                  parent_id: Optional[int] = None, role: Optional[str] = None,
                  vlan_id: Optional[int] = None, vvvv: Optional[str] = None,
                  label: Optional[str] = None, status: str = "allocated",
                  source: str = "manual", audit_state: Optional[str] = None,
                  last_seen_at: Optional[str] = None,
                  last_seen_source: Optional[str] = None,
                  owner: Optional[str] = None, description: Optional[str] = None,
                  path: Optional[Path] = None) -> dict:
    """Insert a prefix. ``cidr`` is canonicalized into family/network/length —
    pass any parseable form (CIDR, bare address, or IPv4 addr+netmask).
    Raises ``ValueError`` on an unparseable ``cidr``."""
    family, network, prefix_length, canon = ipam_net.canonical(cidr)
    with connect(path) as conn:
        cur = conn.execute(
            """INSERT INTO prefixes
               (site_id, parent_id, family, network, prefix_length, cidr, role,
                vlan_id, vvvv, label, status, source, audit_state, last_seen_at,
                last_seen_source, owner, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (site_id, parent_id, family, network, prefix_length, canon, role,
             vlan_id, vvvv, label, status, source, audit_state, last_seen_at,
             last_seen_source, owner, description),
        )
        row = conn.execute(_PREFIX_SELECT + " WHERE p.id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


def update_prefix(prefix_id: int, *, cidr: Optional[str] = None,
                  site_id: Optional[int] = None, parent_id: Optional[int] = None,
                  role: Optional[str] = None, vlan_id: Optional[int] = None,
                  vvvv: Optional[str] = None, label: Optional[str] = None,
                  status: Optional[str] = None, source: Optional[str] = None,
                  audit_state: Optional[str] = None, last_seen_at: Optional[str] = None,
                  last_seen_source: Optional[str] = None, owner: Optional[str] = None,
                  description: Optional[str] = None,
                  path: Optional[Path] = None) -> Optional[dict]:
    """Update mutable fields. When ``cidr`` is supplied it is re-canonicalized
    and family/network/length are rewritten alongside it."""
    fields, values = [], []
    if cidr is not None:
        family, network, prefix_length, canon = ipam_net.canonical(cidr)
        fields += ["family = ?", "network = ?", "prefix_length = ?", "cidr = ?"]
        values += [family, network, prefix_length, canon]
    for col, val in (("site_id", site_id), ("parent_id", parent_id), ("role", role),
                     ("vlan_id", vlan_id), ("vvvv", vvvv), ("label", label),
                     ("status", status), ("source", source),
                     ("audit_state", audit_state), ("last_seen_at", last_seen_at),
                     ("last_seen_source", last_seen_source), ("owner", owner),
                     ("description", description)):
        if val is not None:
            fields.append(f"{col} = ?")
            values.append(val)
    if not fields:
        return get_prefix(prefix_id, path)
    fields.append("updated_at = datetime('now')")
    values.append(prefix_id)
    with connect(path) as conn:
        conn.execute(f"UPDATE prefixes SET {', '.join(fields)} WHERE id = ?", values)
    return get_prefix(prefix_id, path)


def delete_prefix(prefix_id: int, path: Optional[Path] = None) -> int:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM prefixes WHERE id = ?", (prefix_id,))
        return cur.rowcount


def get_or_create_container(cidr: str, *, role: str = "container",
                            label: Optional[str] = None, source: str = "manual",
                            description: Optional[str] = None,
                            path: Optional[Path] = None) -> tuple[dict, bool]:
    """Find-or-create a shared aggregate (``site_id IS NULL``) by canonical
    CIDR. Used for the STIP /48 and any other multi-site parent. Returns
    ``(row, created)``."""
    existing = find_prefix_by_cidr(cidr, site_id=None, path=path)
    if existing:
        return existing, False
    try:
        row = create_prefix(cidr, site_id=None, role=role, label=label,
                            source=source, description=description, path=path)
        return row, True
    except sqlite3.IntegrityError:
        # Lost a race against a concurrent writer (the partial unique index
        # fired) — return the row they created rather than propagating.
        found = find_prefix_by_cidr(cidr, site_id=None, path=path)
        if found:
            return found, False
        raise


def _coerce_vlan(value) -> Optional[int]:
    """Validate a VLAN id from a bulk-accept item. Returns None or 1..4094;
    raises ValueError otherwise (recorded per-item, not fatal to the batch)."""
    if value is None or str(value).strip() == "":
        return None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"invalid vlan_id {value!r}")
    if not (1 <= n <= 4094):
        raise ValueError(f"vlan_id {n} out of range (1..4094)")
    return n


def bulk_accept(items: list[dict], *, path: Optional[Path] = None) -> dict:
    """Commit a batch of accepted drift items in **one** transaction.

    Each item is one of:
        {"container": True, "cidr": ..., "role"?, "label"?}        -> shared aggregate
        {"cidr": ..., "site_id": int,  "role"?, "vlan_id"?, "label"?}
        {"cidr": ..., "site_code": str, ...}                        -> site auto-created

    Discovered prefixes are written ``source='audit'``, ``status='deployed'``.
    Site prefixes get a ``parent_id`` set to the tightest enclosing prefix in
    their scope (the site's own aggregate or a shared container), so the tree
    renders nested. Per-item failures are collected in ``errors`` without
    aborting the batch; an already-present prefix/container is ``skipped``. The
    whole batch commits atomically (or rolls back if a non-item error escapes).

    Returns ``{created, skipped, sites_created, errors}``.
    """
    created = skipped = 0
    sites_created: list[str] = []
    errors: list[dict] = []

    with connect(path) as conn:
        for it in items:
            try:
                cidr = (it.get("cidr") or "").strip()
                if not cidr:
                    raise ValueError("missing cidr")
                family, network, plen, canon = ipam_net.canonical(cidr)

                # Shared aggregate (DMVPN overlay, STIP /48, …) — no owning site.
                if it.get("container"):
                    row = conn.execute(
                        "SELECT id FROM prefixes WHERE cidr = ? AND site_id IS NULL",
                        (canon,)).fetchone()
                    if row:
                        skipped += 1
                        continue
                    conn.execute(
                        "INSERT INTO prefixes (site_id, family, network, prefix_length, "
                        "cidr, role, label, status, source) "
                        "VALUES (NULL, ?, ?, ?, ?, ?, ?, 'deployed', 'audit')",
                        (family, network, plen, canon, it.get("role") or "container",
                         it.get("label") or None))
                    created += 1
                    continue

                vlan = _coerce_vlan(it.get("vlan_id"))

                # Resolve (or auto-create) the owning site.
                site_id = it.get("site_id")
                if site_id is None and it.get("site_code"):
                    code = str(it["site_code"]).strip().upper()
                    srow = conn.execute(
                        "SELECT id FROM sites WHERE site_code = ? COLLATE NOCASE",
                        (code,)).fetchone()
                    if srow:
                        site_id = srow["id"]
                    else:
                        cur = conn.execute("INSERT INTO sites (site_code) VALUES (?)", (code,))
                        site_id = cur.lastrowid
                        sites_created.append(code)
                if site_id is None:
                    raise ValueError("no site_id or site_code")
                site_id = int(site_id)

                # Already present for this site → skip (UNIQUE(site_id, cidr)).
                if conn.execute("SELECT 1 FROM prefixes WHERE site_id = ? AND cidr = ?",
                                (site_id, canon)).fetchone():
                    skipped += 1
                    continue

                # Parent linkage: tightest enclosing prefix in this scope (the
                # site's own rows or a shared container), excluding an identical
                # CIDR. Sees rows created earlier in this same transaction.
                cand = [dict(r) for r in conn.execute(
                    "SELECT id, cidr FROM prefixes "
                    "WHERE family = ? AND cidr != ? AND (site_id = ? OR site_id IS NULL)",
                    (family, canon, site_id)).fetchall()]
                parent = ipam_net.find_container(canon, cand)
                parent_id = parent["id"] if parent else None

                role = it.get("role") or ("site-aggregate" if family == 4 else "subnet")
                conn.execute(
                    "INSERT INTO prefixes (site_id, parent_id, family, network, "
                    "prefix_length, cidr, role, vlan_id, label, status, source, audit_state) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'deployed', 'audit', 'in-sync')",
                    (site_id, parent_id, family, network, plen, canon, role, vlan,
                     it.get("label") or None))
                created += 1

            except sqlite3.IntegrityError:
                # Constraint hit (e.g. a concurrent insert) — the statement is
                # rolled back on its own; treat as already-present.
                skipped += 1
            except (ValueError, TypeError) as e:
                errors.append({"item": it, "error": str(e)})

    return {"created": created, "skipped": skipped,
            "sites_created": sites_created, "errors": errors}


def set_audit_state(prefix_id: int, audit_state: Optional[str], *,
                    last_seen_source: Optional[str] = None,
                    seen: bool = False, path: Optional[Path] = None) -> Optional[dict]:
    """Stamp the audit columns. When ``seen`` is True, ``last_seen_at`` is set
    to now and ``last_seen_source`` recorded — call this when a live source
    confirms a registry prefix."""
    fields = ["audit_state = ?", "updated_at = datetime('now')"]
    values: list = [audit_state]
    if seen:
        fields.append("last_seen_at = datetime('now')")
    if last_seen_source is not None:
        fields.append("last_seen_source = ?")
        values.append(last_seen_source)
    values.append(prefix_id)
    with connect(path) as conn:
        conn.execute(f"UPDATE prefixes SET {', '.join(fields)} WHERE id = ?", values)
    return get_prefix(prefix_id, path)


def find_overlapping_prefixes(cidr: str, *, site_id: Optional[int] = None,
                              exclude_id: Optional[int] = None,
                              path: Optional[Path] = None) -> list[dict]:
    """Return prefixes in the same scope whose network overlaps ``cidr``.
    Hard-conflict signal for the write path (see ``utils.ipam_net.find_overlaps``)."""
    rows = list_prefixes(site_id=site_id, path=path) if site_id is not None \
        else list_prefixes(path=path)
    return ipam_net.find_overlaps(cidr, rows, exclude_id=exclude_id)
