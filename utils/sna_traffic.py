"""utils/sna_traffic.py — bucket SNA's interface-application-traffic report into a stacked series.

The Report Builder API returns raw samples at native granularity — confirmed
against real production data to be roughly one row per application per
minute, not per hour as originally assumed. SNA's own Report Builder chart
re-bins these into a handful of wider columns for display rather than
plotting each raw sample as its own bar (a 30-day view there showed ~13 bars
over 235k raw rows); this does the same, re-binning into hourly buckets for
a 24h window or daily buckets for a 7d window.

Two aggregation passes, in order:
  1. Fold every application outside the top N (by total bps) into one
     "Other Apps" pseudo-application PER RAW TIMESTAMP — concurrent apps at
     the same instant, so summing is correct here.
  2. Re-bin those raw (now-folded) samples into the wider output buckets.
     bps is a rate, not a count, so samples landing in the same output
     bucket are averaged, not summed — summing would scale the value by however
     many raw samples happened to fall in that window, which isn't a real quantity.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

# 7 named applications + "Other Apps" = 8 — the categorical palette's slot
# ceiling (see the dataviz skill's series-count ladder: past ~7-8, fold the tail).
TOP_N_APPS = 7

# SNA has its own literal application named "Others" for generically-classified
# traffic; ours is a different concept (everything outside our top N by
# volume), so it needs a visibly distinct label or the legend reads as a
# confusing near-duplicate.
OTHER_APPS_LABEL = "Other Apps"

HOURLY_BUCKET_SECONDS = 3600
DAILY_BUCKET_SECONDS = 86400


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _bucket_start(dt: datetime, bucket_seconds: int) -> datetime:
    epoch = dt.timestamp()
    floored = epoch - (epoch % bucket_seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def bucket_application_traffic(records: list[dict], hours: int) -> dict:
    """records: [{"applicationName", "time" (ISO8601 UTC str), "trafficInboundBps",
    "trafficOutboundBps"}, ...] — SNA's native per-minute-ish samples.

    `hours` picks the output bucket width: hourly for a <=24h window, daily
    otherwise (mirrors the 24h/7d toggle already on the Bandwidth Utilization
    report).

    Returns {"buckets": [iso8601 bucket-start, ...], "applications": [...],
    "series": {app: [avg bps, ...]}}.
    """
    bucket_seconds = HOURLY_BUCKET_SECONDS if hours <= 24 else DAILY_BUCKET_SECONDS

    parsed = []
    for r in records:
        t = r.get("time")
        app = r.get("applicationName")
        if not t or not app:
            continue
        try:
            value = float(r.get("trafficInboundBps") or 0) + float(r.get("trafficOutboundBps") or 0)
        except (TypeError, ValueError):
            continue
        parsed.append({"t": t, "application": str(app), "bps": value})

    if not parsed:
        return {"buckets": [], "applications": [], "series": {}}

    totals: dict[str, float] = defaultdict(float)
    for r in parsed:
        totals[r["application"]] += r["bps"]

    top_apps = [app for app, _ in sorted(totals.items(), key=lambda kv: -kv[1])[:TOP_N_APPS]]
    top_set = set(top_apps)

    # Pass 1: fold non-top apps into one combined value per raw timestamp.
    raw_by_time: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    has_other = False
    for r in parsed:
        app = r["application"] if r["application"] in top_set else OTHER_APPS_LABEL
        if app == OTHER_APPS_LABEL:
            has_other = True
        raw_by_time[r["t"]][app] += r["bps"]

    applications = top_apps + ([OTHER_APPS_LABEL] if has_other else [])

    # Pass 2: re-bin the folded raw samples into wider output buckets, averaging
    # (not summing) whatever lands in the same bucket.
    bucket_sums: dict[datetime, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    bucket_counts: dict[datetime, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for t, per_app in raw_by_time.items():
        dt = _parse_iso(t)
        if not dt:
            continue
        bucket_key = _bucket_start(dt, bucket_seconds)
        for app, value in per_app.items():
            bucket_sums[bucket_key][app] += value
            bucket_counts[bucket_key][app] += 1

    bucket_dts = sorted(bucket_sums.keys())
    bucket_keys = [dt.isoformat().replace("+00:00", "Z") for dt in bucket_dts]
    series = {
        app: [
            (bucket_sums[dt][app] / bucket_counts[dt][app]) if bucket_counts[dt].get(app) else 0.0
            for dt in bucket_dts
        ]
        for app in applications
    }

    return {"buckets": bucket_keys, "applications": applications, "series": series}
