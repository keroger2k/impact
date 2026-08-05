"""utils/sna_traffic.py — bucket SNA flow records into a stacked-by-application series.

Pure data shaping, no pandas/matplotlib — the chart renders client-side as
inline SVG (same approach as the bandwidth In/Out chart), so this just needs
to hand the frontend a clean {buckets, applications, series} shape.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

# 7 named applications + "Other" = 8 — the categorical palette's slot ceiling
# (see the dataviz skill's series-count ladder: past ~7-8, fold the tail).
TOP_N_APPS = 7


def _parse_time(value: str) -> datetime | None:
    # SNA timestamps look like "2026-08-05T17:37:59.000+0000"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _bucket_minutes(hours: int) -> int:
    return 60 if hours <= 24 else 360  # hourly for 24h, 6h buckets for 7d


def _normalize_flow(flow: dict) -> dict | None:
    stats = flow.get("statistics") or {}
    first_active = stats.get("firstActiveTime")
    byte_count = stats.get("byteCount")
    if not first_active or byte_count is None:
        return None
    t = _parse_time(first_active)
    if t is None:
        return None
    nbar = flow.get("nbarApp") or {}
    app_name = nbar.get("name") or f"app-{flow.get('applicationId', 'unknown')}"
    try:
        byte_count = float(byte_count)
    except (TypeError, ValueError):
        return None
    return {"t": t, "application": str(app_name), "bytes": byte_count}


def bucket_traffic(flows: list[dict], hours: int) -> dict:
    """Bucket flow bytes by time-bucket x application, folding everything
    past the top TOP_N_APPS applications (by total bytes) into "Other"."""
    bucket_minutes = _bucket_minutes(hours)
    records = [r for r in (_normalize_flow(f) for f in flows) if r]
    if not records:
        return {"buckets": [], "applications": [], "series": {}, "bucket_minutes": bucket_minutes}

    bucket_seconds = bucket_minutes * 60

    totals: dict[str, float] = defaultdict(float)
    for r in records:
        totals[r["application"]] += r["bytes"]

    top_apps = [app for app, _ in sorted(totals.items(), key=lambda kv: -kv[1])[:TOP_N_APPS]]
    top_set = set(top_apps)

    def _bucket_key(t: datetime) -> int:
        epoch = int(t.timestamp())
        return (epoch // bucket_seconds) * bucket_seconds

    bucketed: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    has_other = False
    for r in records:
        if r["application"] in top_set:
            app = r["application"]
        else:
            app = "Other"
            has_other = True
        bucketed[_bucket_key(r["t"])][app] += r["bytes"]

    bucket_keys = sorted(bucketed.keys())
    applications = top_apps + (["Other"] if has_other else [])

    series = {app: [bucketed[k].get(app, 0.0) for k in bucket_keys] for app in applications}
    buckets = [datetime.fromtimestamp(k, tz=timezone.utc).isoformat() for k in bucket_keys]

    return {"buckets": buckets, "applications": applications, "series": series, "bucket_minutes": bucket_minutes}
