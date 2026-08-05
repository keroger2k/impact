"""utils/sna_jobs.py — in-memory registry of in-flight SNA flow-query jobs.

Flow search is async and can take minutes (confirmed via scripts/sna_discover.py
— a 24h window was still only ~52% done after 30s), so the frontend polls
status across multiple requests scoped to one query. This registry holds the
authenticated `requests.Session` so we don't re-authenticate on every poll —
SNA login is stateful cookie auth (unlike the stateless per-call Basic Auth
used for F5/SolarWinds).

Deliberately in-memory, not in the shared diskcache (`cache.py`): a live
session cookie is a credential, and diskcache persists to SQLite on disk.
This stays purely in-process and dies with the server — the right lifetime
for a job that finishes in minutes, and consistent with how `auth.py` keeps
its own session store in memory rather than on disk.
"""
from __future__ import annotations

import time

import requests

_JOB_TTL_SECONDS = 30 * 60
_jobs: dict[str, dict] = {}


def register(query_id: str, session: requests.Session, base_url: str, tenant_id: str, record_limit: int, hours: int) -> None:
    _prune()
    _jobs[query_id] = {
        "session": session,
        "base_url": base_url,
        "tenant_id": tenant_id,
        "record_limit": record_limit,
        "hours": hours,
        "created_at": time.time(),
    }


def get(query_id: str) -> dict | None:
    _prune()
    return _jobs.get(query_id)


def discard(query_id: str) -> None:
    _jobs.pop(query_id, None)


def _prune() -> None:
    now = time.time()
    expired = [qid for qid, job in _jobs.items() if now - job["created_at"] > _JOB_TTL_SECONDS]
    for qid in expired:
        _jobs.pop(qid, None)
