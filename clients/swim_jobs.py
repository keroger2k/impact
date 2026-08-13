"""clients/swim_jobs.py — Durable job-tracking registry for IOS image
distribution/activation (SQLite).

DNAC only tracks a distribution/activation task transiently (via its own
task/networkDeviceImageUpdates APIs) — nothing persists a job's device-level
plan or lets a dropped connection resume cleanly. This module is that missing
persistence layer, following the same stdlib-``sqlite3``-only, no-ORM pattern
as ``clients/ip_registry.py``: a ``SCHEMA`` string run via
``conn.executescript()`` in an idempotent ``init_schema()``, a ``connect()``
contextmanager with commit-on-success/rollback-on-error, status-vocabulary
tuples colocated with the schema, and narrow ``set_*``-style update helpers.

Two tables:
  * ``jobs``        — one row per distribution/activation job (image, target
                       criteria, concurrency settings, lifecycle status).
  * ``job_devices``  — one row per device targeted by a job, tracking its own
                       submit/poll lifecycle independently so a resumed job
                       can tell exactly what still needs doing (see
                       ``utils/swim_scheduler.py``, which is the only writer
                       of device *status* transitions — this module just
                       exposes the primitives it composes them from).

Nothing here talks to DNAC. ``clients/swim.py`` owns the DNAC-facing calls;
``utils/swim_scheduler.py`` is what ties the two together.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "data" / "swim_jobs.db"

_init_lock = threading.Lock()
_initialized = False

# Lifecycle vocabularies — enforced at the router layer, exposed here so the
# router and the scheduler share one source of truth (mirrors
# clients/ip_registry.py's SITE_STATUSES/PREFIX_STATUSES pattern).
JOB_TYPES = ("distribution", "activation")
JOB_STATUSES = ("draft", "running", "paused", "completed", "completed_with_errors", "cancelled")
DEVICE_STATUSES = ("queued", "submitting", "in_progress", "success", "failed", "cancelled")
TARGETING_MODES = ("filter", "site_family", "csv")

# Device-row states a resumed job must feed back into the scheduler as "still
# needs work" — see utils/swim_scheduler.py's resume logic.
_UNFINISHED_DEVICE_STATUSES = ("queued", "submitting", "in_progress")

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type                      TEXT    NOT NULL,
    name                          TEXT,
    status                        TEXT    NOT NULL DEFAULT 'draft',
    image_uuid                    TEXT    NOT NULL,
    image_name                    TEXT,
    image_version                 TEXT,
    platform_id                   TEXT,
    site_concurrency              INTEGER NOT NULL DEFAULT 3,
    flash_cleanup                 INTEGER NOT NULL DEFAULT 0,
    schedule_validate             INTEGER,
    activate_lower_image_version  INTEGER,
    device_upgrade_mode           TEXT,
    distribute_if_needed          INTEGER,
    targeting_mode                TEXT    NOT NULL,
    targeting_criteria            TEXT,
    total_devices                 INTEGER NOT NULL DEFAULT 0,
    created_by                    TEXT    NOT NULL,
    confirmed_by                  TEXT,
    confirmed_at                  TEXT,
    created_at                    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at                    TEXT    NOT NULL DEFAULT (datetime('now')),
    started_at                    TEXT,
    completed_at                  TEXT
);

CREATE TABLE IF NOT EXISTS job_devices (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id                    INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    device_id                 TEXT    NOT NULL,
    hostname                  TEXT,
    management_ip             TEXT,
    platform_id               TEXT,
    family                    TEXT,
    site_code                 TEXT,
    site_code_source          TEXT,
    current_software_version  TEXT,
    status                    TEXT    NOT NULL DEFAULT 'queued',
    dnac_task_id              TEXT,
    submitted_at              TEXT,
    last_polled_at            TEXT,
    completed_at              TEXT,
    error_message             TEXT,
    created_at                TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at                TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (job_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status         ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_type           ON jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_job_devices_job     ON job_devices(job_id);
CREATE INDEX IF NOT EXISTS idx_job_devices_status  ON job_devices(job_id, status);
-- Every semaphore-scheduling tick and every resume needs "how many devices at
-- site X are currently submitting/in_progress for job Y" fast.
CREATE INDEX IF NOT EXISTS idx_job_devices_site    ON job_devices(job_id, site_code, status);
"""


def _connect_raw(path: Path):
    conn = sqlite3.connect(str(path), detect_types=sqlite3.PARSE_DECLTYPES, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _ensure_column(conn, table: str, column: str, decl: str) -> None:
    """Add a column to an existing table if it's missing (SQLite has no
    ADD COLUMN IF NOT EXISTS, and CREATE TABLE IF NOT EXISTS is a no-op on a
    table that already exists — new columns added to SCHEMA never reach an
    already-created database without this)."""
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        logger.info("swim_jobs: added column %s.%s", table, column)


def init_schema(path: Optional[Path] = None) -> None:
    """Create tables and indexes if missing, and migrate any columns added
    to SCHEMA after a database was first created. Safe to call repeatedly."""
    global _initialized
    target = path or DB_PATH
    with _init_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        conn = _connect_raw(target)
        try:
            conn.executescript(SCHEMA)
            _ensure_column(conn, "jobs", "flash_cleanup", "INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        finally:
            conn.close()
        if target == DB_PATH:
            _initialized = True
        logger.info(f"SWIM job registry schema ready at {target}")


@contextmanager
def connect(path: Optional[Path] = None) -> Iterator["sqlite3.Connection"]:
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


def _row(r: sqlite3.Row) -> dict:
    return dict(r)


# ── Jobs ──────────────────────────────────────────────────────────────────

def create_job(
    *,
    job_type: str,
    image_uuid: str,
    image_name: str | None,
    image_version: str | None,
    platform_id: str | None,
    site_concurrency: int,
    targeting_mode: str,
    targeting_criteria: dict | None,
    created_by: str,
    name: str | None = None,
    flash_cleanup: bool = False,
    schedule_validate: bool | None = None,
    activate_lower_image_version: bool | None = None,
    device_upgrade_mode: str | None = None,
    distribute_if_needed: bool | None = None,
) -> int:
    """Insert a new draft job. Returns its id. Caller inserts job_devices
    rows separately via add_devices(). `flash_cleanup` is distribution-only
    (see utils/swim_scheduler.py) — callers are expected to only set it True
    for job_type='distribution'; this layer doesn't enforce that itself
    (routers/swim.py does, alongside the env-flag gate)."""
    if job_type not in JOB_TYPES:
        raise ValueError(f"invalid job_type: {job_type!r}")
    if targeting_mode not in TARGETING_MODES:
        raise ValueError(f"invalid targeting_mode: {targeting_mode!r}")

    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO jobs (
                job_type, name, image_uuid, image_name, image_version, platform_id,
                site_concurrency, flash_cleanup, schedule_validate, activate_lower_image_version,
                device_upgrade_mode, distribute_if_needed,
                targeting_mode, targeting_criteria, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_type, name, image_uuid, image_name, image_version, platform_id,
                site_concurrency, int(flash_cleanup),
                None if schedule_validate is None else int(schedule_validate),
                None if activate_lower_image_version is None else int(activate_lower_image_version),
                device_upgrade_mode,
                None if distribute_if_needed is None else int(distribute_if_needed),
                targeting_mode,
                json.dumps(targeting_criteria) if targeting_criteria is not None else None,
                created_by,
            ),
        )
        return cur.lastrowid


def add_devices(job_id: int, devices: list[dict]) -> int:
    """Bulk-insert job_devices rows for a draft job, one transaction.

    Each dict: device_id, hostname, management_ip, platform_id, family,
    site_code, site_code_source, current_software_version. Duplicate
    device_ids for the same job are silently skipped (UNIQUE constraint) —
    the caller de-dupes upstream (utils/swim_targeting.py), this is just a
    safety net. Updates jobs.total_devices to the row count actually stored.
    """
    if not devices:
        return 0
    with connect() as conn:
        inserted = 0
        for d in devices:
            try:
                conn.execute(
                    """
                    INSERT INTO job_devices (
                        job_id, device_id, hostname, management_ip, platform_id,
                        family, site_code, site_code_source, current_software_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_id, d["device_id"], d.get("hostname"), d.get("management_ip"),
                        d.get("platform_id"), d.get("family"), d.get("site_code"),
                        d.get("site_code_source"), d.get("current_software_version"),
                    ),
                )
                inserted += 1
            except sqlite3.IntegrityError:
                continue
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM job_devices WHERE job_id = ?", (job_id,)
        ).fetchone()["n"]
        conn.execute(
            "UPDATE jobs SET total_devices = ?, updated_at = datetime('now') WHERE id = ?",
            (count, job_id),
        )
        return inserted


def get_job(job_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return _row(row) if row else None


def list_jobs(job_type: str | None = None) -> list[dict]:
    with connect() as conn:
        if job_type:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE job_type = ? ORDER BY created_at DESC", (job_type,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC").fetchall()
        return [_row(r) for r in rows]


def set_job_status(job_id: int, status: str, **extra) -> None:
    """Narrow status-update helper — mirrors ip_registry.set_audit_state().
    `extra` may carry started_at/completed_at/confirmed_by/confirmed_at."""
    if status not in JOB_STATUSES:
        raise ValueError(f"invalid job status: {status!r}")
    fields = ["status = ?", "updated_at = datetime('now')"]
    params: list = [status]
    for col in ("started_at", "completed_at", "confirmed_by", "confirmed_at"):
        if col in extra:
            fields.append(f"{col} = ?")
            params.append(extra[col])
    params.append(job_id)
    with connect() as conn:
        conn.execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", params)


def confirm_job(job_id: int, confirmed_by: str) -> None:
    """Stamp confirmation once, on first Start — never re-demanded on Resume
    (see utils/swim_scheduler.py). No-op if already confirmed."""
    with connect() as conn:
        conn.execute(
            "UPDATE jobs SET confirmed_by = ?, confirmed_at = datetime('now'), updated_at = datetime('now') "
            "WHERE id = ? AND confirmed_at IS NULL",
            (confirmed_by, job_id),
        )


# ── Job devices ──────────────────────────────────────────────────────────

def list_job_devices(job_id: int, status: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]:
    with connect() as conn:
        sql = "SELECT * FROM job_devices WHERE job_id = ?"
        params: list = [job_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY site_code, hostname"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [_row(r) for r in rows]


def unfinished_job_devices(job_id: int) -> list[dict]:
    """Rows a resumed run must feed back into the scheduler — queued,
    submitting, or in_progress. See utils/swim_scheduler.py §5.2."""
    with connect() as conn:
        placeholders = ",".join("?" * len(_UNFINISHED_DEVICE_STATUSES))
        rows = conn.execute(
            f"SELECT * FROM job_devices WHERE job_id = ? AND status IN ({placeholders})",
            (job_id, *_UNFINISHED_DEVICE_STATUSES),
        ).fetchall()
        return [_row(r) for r in rows]


def device_status_counts(job_id: int) -> dict[str, int]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM job_devices WHERE job_id = ? GROUP BY status", (job_id,)
        ).fetchall()
        counts = {s: 0 for s in DEVICE_STATUSES}
        for r in rows:
            counts[r["status"]] = r["n"]
        return counts


def set_device_status(device_row_id: int, status: str, **extra) -> None:
    """Narrow per-device status-update helper. `extra` may carry
    dnac_task_id/submitted_at/last_polled_at/completed_at/error_message."""
    if status not in DEVICE_STATUSES:
        raise ValueError(f"invalid device status: {status!r}")
    fields = ["status = ?", "updated_at = datetime('now')"]
    params: list = [status]
    for col in ("dnac_task_id", "submitted_at", "last_polled_at", "completed_at", "error_message"):
        if col in extra:
            fields.append(f"{col} = ?")
            params.append(extra[col])
    params.append(device_row_id)
    with connect() as conn:
        conn.execute(f"UPDATE job_devices SET {', '.join(fields)} WHERE id = ?", params)


def get_device_status(device_row_id: int) -> str | None:
    """Fast single-column read used by the scheduler's race check (does a
    concurrent cancel-queued call already have priority?) right before a
    worker acts on a row — see utils/swim_scheduler.py."""
    with connect() as conn:
        row = conn.execute("SELECT status FROM job_devices WHERE id = ?", (device_row_id,)).fetchone()
        return row["status"] if row else None


def cancel_queued(job_id: int) -> dict:
    """Bulk-cancel every still-queued device for a job, one transaction.

    Never touches submitting/in_progress rows — no DNAC cancel API exists,
    see clients/swim.py. Returns counts so the caller can render an honest
    cancellable-vs-in-flight split without a second round trip.
    """
    with connect() as conn:
        cur = conn.execute(
            "UPDATE job_devices SET status = 'cancelled', updated_at = datetime('now') "
            "WHERE job_id = ? AND status = 'queued'",
            (job_id,),
        )
        cancelled = cur.rowcount
        in_flight = conn.execute(
            "SELECT COUNT(*) AS n FROM job_devices WHERE job_id = ? AND status IN ('submitting', 'in_progress')",
            (job_id,),
        ).fetchone()["n"]
        # 'cancelled' is deliberately excluded here — those are exactly the
        # rows this call just cancelled (already reported via
        # cancelled_count) plus any cancelled by an earlier call; including
        # them would double-count against cancelled_count for this response.
        terminal = conn.execute(
            "SELECT COUNT(*) AS n FROM job_devices WHERE job_id = ? AND status IN ('success', 'failed')",
            (job_id,),
        ).fetchone()["n"]
        return {
            "cancelled_count": cancelled,
            "already_in_flight_count": in_flight,
            "already_terminal_count": terminal,
        }
