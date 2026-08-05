"""utils/sna_traffic.py — bucket SNA's interface-application-traffic report into a stacked series.

The Report Builder API already returns clean, per-hour bps values (see
clients/sna.get_interface_application_traffic) — this just groups them by
application, folding everything past the top N (by total bps) into "Other".
No unit conversion or time-bucketing math needed; SNA did that already.
"""
from __future__ import annotations

from collections import defaultdict

# 7 named applications + "Other" = 8 — the categorical palette's slot ceiling
# (see the dataviz skill's series-count ladder: past ~7-8, fold the tail).
TOP_N_APPS = 7


def bucket_application_traffic(records: list[dict]) -> dict:
    """records: [{"applicationName", "time" (ISO8601 UTC str), "trafficInboundBps",
    "trafficOutboundBps"}, ...] — one row per (application, hour) already.

    Returns {"buckets": [iso8601, ...], "applications": [...], "series": {app: [bps, ...]}}.
    """
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

    bucketed: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    has_other = False
    for r in parsed:
        app = r["application"] if r["application"] in top_set else "Other"
        if app == "Other":
            has_other = True
        bucketed[r["t"]][app] += r["bps"]

    bucket_keys = sorted(bucketed.keys())  # ISO8601 strings sort chronologically
    applications = top_apps + (["Other"] if has_other else [])
    series = {app: [bucketed[k].get(app, 0.0) for k in bucket_keys] for app in applications}

    return {"buckets": bucket_keys, "applications": applications, "series": series}
