"""utils/time_buckets.py — shared UTC time-bucketing helpers.

Used by utils/sna_traffic.py (SNA application-traffic re-binning) and
utils/bandwidth_report.py (SolarWinds In/Out percent-utilization
re-binning) — both take a raw per-poll/per-minute series and average it
into wider display buckets, for the same reason: plotting every raw sample
renders as noise where the source system's own dashboard shows a smoothed
line. Bucket boundaries are real UTC instants (floors of the actual sample
timestamps), not synthesized calendar days, so callers can render them
through ordinary local-time formatting with no special-casing.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def bucket_start(dt: datetime, bucket_seconds: int) -> datetime:
    epoch = dt.timestamp()
    floored = epoch - (epoch % bucket_seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def bucket_range(start: datetime, end: datetime, bucket_seconds: int) -> list[datetime]:
    """Every bucket start from `start` through `end`, inclusive."""
    step = timedelta(seconds=bucket_seconds)
    current = bucket_start(start, bucket_seconds)
    last = bucket_start(end, bucket_seconds)
    out = []
    while current <= last:
        out.append(current)
        current += step
    return out
