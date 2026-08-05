"""tests/test_sna_traffic.py — bucket_application_traffic re-binning + averaging.

Covers the real production finding on 2026-08-05: SNA's Report Builder
returns raw per-minute-ish samples, not clean per-hour rows as originally
assumed, so plotting each raw sample as its own bar produced an unreadable
wall of spikes. bucket_application_traffic now re-bins raw samples into
hourly (24h view) or daily (7d view) output buckets, averaging (not summing)
whatever lands in the same bucket since bps is a rate, not a count.
"""
from utils.sna_traffic import OTHER_APPS_LABEL, bucket_application_traffic


def _rec(t, app, inbound, outbound=0):
    return {"applicationName": app, "time": t, "trafficInboundBps": inbound, "trafficOutboundBps": outbound}


def test_multiple_raw_samples_in_same_hour_are_averaged():
    records = [
        _rec("2026-08-04T10:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-04T10:30:00Z", "Teams", 3_000_000),
    ]
    result = bucket_application_traffic(records, hours=24)

    assert result["buckets"] == ["2026-08-04T10:00:00Z"]
    assert result["applications"] == ["Teams"]
    assert result["series"]["Teams"] == [2_000_000.0]


def test_samples_in_different_hours_stay_in_separate_buckets():
    records = [
        _rec("2026-08-04T10:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-04T11:00:00Z", "Teams", 3_000_000),
    ]
    result = bucket_application_traffic(records, hours=24)

    assert result["buckets"] == ["2026-08-04T10:00:00Z", "2026-08-04T11:00:00Z"]
    assert result["series"]["Teams"] == [1_000_000.0, 3_000_000.0]


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

    result = bucket_application_traffic(records, hours=24)

    assert set(result["applications"]) == set(top_names) | {OTHER_APPS_LABEL}
    assert "App8" not in result["applications"]
    assert "App9" not in result["applications"]

    # Correct: sum concurrent lower-ranked apps per raw timestamp (80, 100),
    # then average across the two timestamps in this bucket: (80+100)/2 = 90.
    # A buggy average-over-individual-rows implementation would instead give
    # (50+30+60+40)/4 = 45.
    assert result["series"][OTHER_APPS_LABEL] == [90.0]
    assert result["series"]["App1"] == [705.0]


def test_hours_168_uses_daily_buckets():
    records = [
        _rec("2026-08-01T02:00:00Z", "Teams", 1_000_000),
        _rec("2026-08-01T22:00:00Z", "Teams", 3_000_000),
        _rec("2026-08-02T05:00:00Z", "Teams", 5_000_000),
    ]
    result = bucket_application_traffic(records, hours=168)

    assert result["buckets"] == ["2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"]
    assert result["series"]["Teams"] == [2_000_000.0, 5_000_000.0]


def test_empty_records():
    result = bucket_application_traffic([], hours=24)
    assert result == {"buckets": [], "applications": [], "series": {}}


def test_malformed_rows_are_skipped():
    records = [
        {"applicationName": "Teams", "time": None, "trafficInboundBps": 1},
        {"applicationName": None, "time": "2026-08-04T10:00:00Z", "trafficInboundBps": 1},
        {"applicationName": "Teams", "time": "2026-08-04T10:00:00Z", "trafficInboundBps": "not-a-number"},
        _rec("2026-08-04T10:00:00Z", "Teams", 2_000_000),
    ]
    result = bucket_application_traffic(records, hours=24)

    assert result["buckets"] == ["2026-08-04T10:00:00Z"]
    assert result["series"]["Teams"] == [2_000_000.0]
