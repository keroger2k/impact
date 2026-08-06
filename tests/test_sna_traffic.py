"""tests/test_sna_traffic.py — bucket_application_traffic re-binning + averaging.

Covers the real production finding on 2026-08-05: SNA's Report Builder
returns raw per-minute-ish samples, not clean per-hour rows as originally
assumed, so plotting each raw sample as its own bar produced an unreadable
wall of spikes. bucket_application_traffic re-bins raw samples into
hourly (24h view) or daily (7d view) output buckets, averaging (not summing)
whatever lands in the same bucket since bps is a rate, not a count.

It also pads the output to the full requested window — see the padding tests
at the bottom for why. Every test here pins `window_end` so the padded range
is deterministic rather than relative to the wall clock.
"""
from datetime import datetime, timezone

from utils.sna_traffic import OTHER_APPS_LABEL, bucket_application_traffic


def _rec(t, app, inbound, outbound=0):
    return {"applicationName": app, "time": t, "trafficInboundBps": inbound, "trafficOutboundBps": outbound}


def _at(result, app, bucket_iso):
    """Value for `app` in the bucket starting at `bucket_iso`.

    Indexed by bucket rather than by position: the output now spans the whole
    requested window, so a bucket's position depends on where it falls in
    that range, which isn't what these aggregation tests are about.
    """
    return result["series"][app][result["buckets"].index(bucket_iso)]


WINDOW_END = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


# ── Re-binning + averaging ───────────────────────────────────────────────────

def test_multiple_raw_samples_in_same_hour_are_averaged():
    records = [
        _rec("2026-08-04T10:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-04T10:30:00Z", "Teams", 3_000_000),
    ]
    result = bucket_application_traffic(records, hours=24, window_end=WINDOW_END)

    assert result["applications"] == ["Teams"]
    assert _at(result, "Teams", "2026-08-04T10:00:00Z") == 2_000_000.0


def test_samples_in_different_hours_stay_in_separate_buckets():
    records = [
        _rec("2026-08-04T10:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-04T11:00:00Z", "Teams", 3_000_000),
    ]
    result = bucket_application_traffic(records, hours=24, window_end=WINDOW_END)

    assert _at(result, "Teams", "2026-08-04T10:00:00Z") == 1_000_000.0
    assert _at(result, "Teams", "2026-08-04T11:00:00Z") == 3_000_000.0


def test_other_apps_combines_concurrent_lower_ranked_apps_then_averages():
    # 9 distinct apps: top 7 by total volume stay named, the 2 smallest fold
    # into "Other Apps". Two raw timestamps in the same hour.
    top_names = [f"App{i}" for i in range(1, 8)]
    t1_top = [700, 600, 500, 400, 300, 200, 100]
    t2_top = [710, 610, 510, 410, 310, 210, 110]

    records = []
    for name, v in zip(top_names, t1_top):
        records.append(_rec("2026-08-04T10:00:00Z", name, v))
    for name, v in zip(top_names, t2_top):
        records.append(_rec("2026-08-04T10:30:00Z", name, v))

    # Two lower-ranked apps present at both raw timestamps.
    records.append(_rec("2026-08-04T10:00:00Z", "App8", 50))
    records.append(_rec("2026-08-04T10:00:00Z", "App9", 30))
    records.append(_rec("2026-08-04T10:30:00Z", "App8", 60))
    records.append(_rec("2026-08-04T10:30:00Z", "App9", 40))

    result = bucket_application_traffic(records, hours=24, window_end=WINDOW_END)

    assert set(result["applications"]) == set(top_names) | {OTHER_APPS_LABEL}
    assert "App8" not in result["applications"]
    assert "App9" not in result["applications"]

    # Correct: sum concurrent lower-ranked apps per raw timestamp (80, 100),
    # then average across the two timestamps in this bucket: (80+100)/2 = 90.
    # A buggy average-over-individual-rows implementation would instead give
    # (50+30+60+40)/4 = 45.
    assert _at(result, OTHER_APPS_LABEL, "2026-08-04T10:00:00Z") == 90.0
    assert _at(result, "App1", "2026-08-04T10:00:00Z") == 705.0


def test_hours_168_uses_daily_buckets():
    records = [
        _rec("2026-08-01T02:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-01T22:00:00Z", "Teams", 3_000_000),
        _rec("2026-08-02T05:00:00Z", "Teams", 5_000_000),
    ]
    result = bucket_application_traffic(records, hours=168, window_end=WINDOW_END)

    assert _at(result, "Teams", "2026-08-01T00:00:00Z") == 2_000_000.0
    assert _at(result, "Teams", "2026-08-02T00:00:00Z") == 5_000_000.0


def test_empty_records():
    result = bucket_application_traffic([], hours=24, window_end=WINDOW_END)
    assert result == {"buckets": [], "applications": [], "series": {}}


def test_malformed_rows_are_skipped():
    records = [
        {"applicationName": "Teams", "time": None, "trafficInboundBps": 1},
        {"applicationName": None, "time": "2026-08-04T10:00:00Z", "trafficInboundBps": 1},
        {"applicationName": "Teams", "time": "2026-08-04T10:00:00Z", "trafficInboundBps": "not-a-number"},
        _rec("2026-08-04T10:00:00Z", "Teams", 2_000_000),
    ]
    result = bucket_application_traffic(records, hours=24, window_end=WINDOW_END)

    assert _at(result, "Teams", "2026-08-04T10:00:00Z") == 2_000_000.0


# ── Window padding ───────────────────────────────────────────────────────────

def test_single_day_of_data_still_spans_the_full_7d_window():
    """The real production case: SNA had one day of data in a 7-day window.
    Unpadded, that rendered as one bar stretched across the entire chart —
    reading as steady traffic all week when it means the opposite. The output
    must cover the whole window so the six empty days show as empty.
    """
    records = [_rec("2026-07-30T02:00:00Z", "STIPTDM", 1_200_000)]
    result = bucket_application_traffic(records, hours=168, window_end=WINDOW_END)

    assert result["buckets"][0] == "2026-07-29T00:00:00Z"
    assert result["buckets"][-1] == "2026-08-05T00:00:00Z"
    assert len(result["buckets"]) == 8

    values = result["series"]["STIPTDM"]
    assert _at(result, "STIPTDM", "2026-07-30T00:00:00Z") == 1_200_000.0
    # Every other day is a real gap, not a carried-forward value.
    assert sum(1 for v in values if v > 0) == 1


def test_24h_window_is_padded_hourly():
    records = [_rec("2026-08-05T09:15:00Z", "Teams", 500_000)]
    result = bucket_application_traffic(records, hours=24, window_end=WINDOW_END)

    assert result["buckets"][0] == "2026-08-04T12:00:00Z"
    assert result["buckets"][-1] == "2026-08-05T12:00:00Z"
    assert len(result["buckets"]) == 25
    assert _at(result, "Teams", "2026-08-05T09:00:00Z") == 500_000.0


def test_data_outside_the_nominal_window_is_kept():
    """Padding defines a floor on the range, never a filter — a sample older
    than the nominal window must not be dropped just because it falls outside."""
    records = [
        _rec("2026-07-20T00:00:00Z", "Teams", 900_000),
        _rec("2026-08-04T00:00:00Z", "Teams", 100_000),
    ]
    result = bucket_application_traffic(records, hours=168, window_end=WINDOW_END)

    assert result["buckets"][0] == "2026-07-20T00:00:00Z"
    assert _at(result, "Teams", "2026-07-20T00:00:00Z") == 900_000.0


def test_every_application_series_matches_bucket_count():
    """Ragged series would silently misalign every stacked segment after the
    first gap, so this invariant is worth pinning independently."""
    records = [
        _rec("2026-08-03T00:00:00Z", "Teams", 1_000),
        _rec("2026-08-04T00:00:00Z", "Splunk", 2_000),
    ]
    result = bucket_application_traffic(records, hours=168, window_end=WINDOW_END)

    for app, values in result["series"].items():
        assert len(values) == len(result["buckets"]), app
