"""Tests for utils/experience.py — the latency-under-load math and the
device-output parsers behind scripts/site_experience_report.py.

Fixtures are hand-written with invented addressing per
docs/IP_ADDRESS_POLICY.md (enforced by tests/test_no_real_ips.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from utils.experience import (
    MIN_BUCKETS_PER_BIN,
    busy_share,
    correlate,
    detect_series_offset,
    grade,
    hour_profile,
    latency_under_load,
    merge_sla_ops,
    overlap_ratio,
    parse_ip_sla_statistics,
    parse_ping,
    rpm,
    sla_targets,
    timestamp_form,
)

BUCKET = 900  # 15 minutes


def _rtt_rows(start: datetime, count: int, rtt: float, step_s: int = 900,
              availability: float = 100.0, offset_hours: float = 0.0) -> list[dict]:
    base = start + timedelta(hours=offset_hours)
    return [
        {
            "ObservationTimestamp": (base + timedelta(seconds=i * step_s)).isoformat(),
            "AvgResponseTime": rtt,
            "MaxResponseTime": rtt * 2,
            "Availability": availability,
        }
        for i in range(count)
    ]


def _util_rows(start: datetime, count: int, util: float, step_s: int = 900) -> list[dict]:
    return [
        {
            "DateTime": (start + timedelta(seconds=i * step_s)).isoformat(),
            "InPercentUtil": 5.0,
            "OutPercentUtil": util,
        }
        for i in range(count)
    ]


T0 = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)


# ─────────────────────────── grading ───────────────────────────────────────

@pytest.mark.parametrize("penalty,expected", [
    (0, "A+"), (4.9, "A+"),
    (5, "A"), (29.9, "A"),
    (30, "B"), (59.9, "B"),
    (60, "C"), (199.9, "C"),
    (200, "D"), (399.9, "D"),
    (400, "F"), (5000, "F"),
])
def test_grade_boundaries(penalty, expected):
    assert grade(penalty) == expected


def test_grade_treats_a_negative_penalty_as_no_penalty():
    # Busy measuring faster than idle is measurement noise, not an achievement.
    assert grade(-40.0) == "A+"


def test_grade_of_unmeasurable_is_none():
    assert grade(None) is None


def test_rpm():
    assert rpm(60.0) == pytest.approx(1000.0)
    assert rpm(487.0) == pytest.approx(123.2, rel=0.01)
    assert rpm(0) is None
    assert rpm(None) is None


# ─────────────────────────── correlation ───────────────────────────────────

def test_correlate_pairs_by_bucket():
    rtt = _rtt_rows(T0, 4, rtt=30.0)
    util = _util_rows(T0, 4, util=20.0)
    pairs = correlate(rtt, util, BUCKET)
    assert len(pairs) == 4
    assert pairs[0]["rtt_ms"] == 30.0
    assert pairs[0]["util_pct"] == 20.0
    assert pairs[0]["max_rtt_ms"] == 60.0


def test_correlate_drops_buckets_with_only_one_side():
    # A latency reading with no idea what the load was is precisely the
    # ambiguity this report exists to remove, so it is not reported.
    rtt = _rtt_rows(T0, 8, rtt=30.0)
    util = _util_rows(T0, 3, util=20.0)
    assert len(correlate(rtt, util, BUCKET)) == 3


def test_correlate_averages_within_a_bucket_but_keeps_the_peak():
    rtt = [
        {"ObservationTimestamp": T0.isoformat(), "AvgResponseTime": 10.0,
         "MaxResponseTime": 20.0, "Availability": 100.0},
        {"ObservationTimestamp": (T0 + timedelta(minutes=5)).isoformat(),
         "AvgResponseTime": 30.0, "MaxResponseTime": 900.0, "Availability": 100.0},
    ]
    util = _util_rows(T0, 1, util=50.0)
    pairs = correlate(rtt, util, BUCKET)
    assert len(pairs) == 1
    assert pairs[0]["rtt_ms"] == 20.0          # averaged
    assert pairs[0]["max_rtt_ms"] == 900.0     # peak kept, not averaged away


def test_correlate_skips_unparseable_timestamps():
    rtt = _rtt_rows(T0, 2, rtt=30.0) + [{"ObservationTimestamp": "not-a-date",
                                         "AvgResponseTime": 30.0}]
    util = _util_rows(T0, 2, util=20.0)
    assert len(correlate(rtt, util, BUCKET)) == 2


# ───────────────────── the timezone-alignment hazard ───────────────────────

def test_detect_series_offset_recovers_a_known_shift():
    """The failure this whole guard exists for: the two Orion entities store
    timestamps in different zones, so every RTT gets paired against the wrong
    hour's utilisation and the report is confidently wrong."""
    util = _util_rows(T0, 96, util=50.0)
    rtt = _rtt_rows(T0, 96, rtt=30.0, offset_hours=-5)   # stored 5h behind
    assert detect_series_offset(rtt, util) == timedelta(hours=5)


def test_detect_series_offset_ignores_polling_jitter():
    # The two entities are polled on unrelated schedules, so their newest rows
    # are minutes apart even when perfectly aligned. That must not read as an
    # offset.
    util = _util_rows(T0, 10, util=50.0)
    rtt = _rtt_rows(T0 + timedelta(minutes=7), 10, rtt=30.0)
    assert detect_series_offset(rtt, util) == timedelta(0)


def test_offset_correction_restores_pairing():
    util = _util_rows(T0, 96, util=50.0)
    rtt = _rtt_rows(T0, 96, rtt=30.0, offset_hours=-5)
    # Uncorrected, most buckets fail to pair.
    naive = correlate(rtt, util, BUCKET)
    corrected = correlate(rtt, util, BUCKET, rtt_offset=detect_series_offset(rtt, util))
    assert len(corrected) > len(naive)
    assert len(corrected) == 96


def test_detect_series_offset_mixes_naive_and_aware_timestamps():
    """The shape Orion actually returns, and the crash it caused:
    Orion.ResponseTime.ObservationTimestamp comes back naive while
    Orion.NPM.InterfaceTraffic.DateTime carries a trailing Z, so comparing
    them raw raises "can't subtract offset-naive and offset-aware datetimes".
    """
    rtt = [{"ObservationTimestamp": "2026-09-01T01:32:30",      # naive
            "AvgResponseTime": 30.0, "MaxResponseTime": 60.0, "Availability": 100.0}]
    util = [{"DateTime": "2026-09-01T06:30:00Z",                # aware
             "OutPercentUtil": 50.0}]
    # Naive is read as UTC, so the two maxima are ~5h apart.
    assert detect_series_offset(rtt, util) == timedelta(hours=5)


def test_detect_series_offset_within_one_series_mixing_forms():
    # max() over a mixed list is itself unorderable — it would raise before
    # the subtraction ever ran.
    rtt = [
        {"ObservationTimestamp": "2026-09-01T00:00:00"},
        {"ObservationTimestamp": "2026-09-01T01:00:00Z"},
    ]
    util = [{"DateTime": "2026-09-01T01:00:00Z"}]
    assert detect_series_offset(rtt, util) == timedelta(0)


def test_correlate_pairs_naive_against_aware():
    rtt = [{"ObservationTimestamp": "2026-09-01T00:00:00",
            "AvgResponseTime": 42.0, "MaxResponseTime": 90.0, "Availability": 100.0}]
    util = [{"DateTime": "2026-09-01T00:00:00Z", "OutPercentUtil": 80.0}]
    pairs = correlate(rtt, util, BUCKET)
    assert len(pairs) == 1
    assert pairs[0]["rtt_ms"] == 42.0 and pairs[0]["util_pct"] == 80.0


def test_detect_series_offset_needs_both_series():
    assert detect_series_offset([], _util_rows(T0, 3, 10.0)) is None
    assert detect_series_offset(_rtt_rows(T0, 3, 10.0), []) is None


def test_overlap_ratio_flags_a_misalignment():
    util = _util_rows(T0, 96, util=50.0)
    rtt = _rtt_rows(T0, 96, rtt=30.0, offset_hours=-40)   # beyond the window
    pairs = correlate(rtt, util, BUCKET)
    assert overlap_ratio(rtt, util, pairs) < 0.2


# ─────────────────────────── latency under load ────────────────────────────

def _mixed_window(idle_rtt=32.0, busy_rtt=487.0, idle_n=40, busy_n=40):
    """A window that is half quiet and half saturated — the K114 shape."""
    rtt = _rtt_rows(T0, idle_n, rtt=idle_rtt)
    util = _util_rows(T0, idle_n, util=12.0)
    busy_start = T0 + timedelta(seconds=idle_n * BUCKET)
    rtt += _rtt_rows(busy_start, busy_n, rtt=busy_rtt, availability=99.2)
    util += _util_rows(busy_start, busy_n, util=94.0)
    return rtt, util


def test_latency_under_load_computes_the_penalty():
    rtt, util = _mixed_window()
    result = latency_under_load(correlate(rtt, util, BUCKET))
    assert result["idle_buckets"] == 40
    assert result["busy_buckets"] == 40
    assert result["idle_p50_ms"] == pytest.approx(32.0)
    assert result["busy_p50_ms"] == pytest.approx(487.0)
    assert result["penalty_p50_ms"] == pytest.approx(455.0)
    assert result["grade"] == "F"
    assert result["sufficient"] is True
    assert result["busy_availability"] == pytest.approx(99.2)


def test_a_healthy_site_grades_well():
    rtt, util = _mixed_window(idle_rtt=30.0, busy_rtt=42.0)
    result = latency_under_load(correlate(rtt, util, BUCKET))
    assert result["penalty_p50_ms"] == pytest.approx(12.0)
    assert result["grade"] == "A"


def test_thin_bins_refuse_to_grade():
    """A letter grade computed from four samples is not reproducible, and it
    will be quoted. The report must say 'insufficient' instead."""
    rtt, util = _mixed_window(busy_n=MIN_BUCKETS_PER_BIN - 1)
    result = latency_under_load(correlate(rtt, util, BUCKET))
    assert result["sufficient"] is False
    assert result["grade"] is None
    # The underlying numbers are still returned for display.
    assert result["penalty_p50_ms"] is not None


def test_no_busy_buckets_at_all():
    rtt = _rtt_rows(T0, 40, rtt=30.0)
    util = _util_rows(T0, 40, util=5.0)
    result = latency_under_load(correlate(rtt, util, BUCKET))
    assert result["busy_buckets"] == 0
    assert result["penalty_p50_ms"] is None
    assert result["grade"] is None
    assert result["sufficient"] is False


def test_busy_share():
    rtt, util = _mixed_window(idle_n=70, busy_n=30)
    pairs = correlate(rtt, util, BUCKET)
    assert busy_share(pairs) == pytest.approx(30.0)
    assert busy_share([]) is None


def test_hour_profile_uses_local_time():
    rtt, util = _mixed_window(idle_n=4, busy_n=4)
    pairs = correlate(rtt, util, BUCKET)
    utc = {h["hour"]: h for h in hour_profile(pairs, 0)}
    local = {h["hour"]: h for h in hour_profile(pairs, -5)}
    assert len(utc) == 24 and len(local) == 24
    # The 00:00 UTC samples land at 19:00 the previous local day.
    assert utc[0]["samples"] > 0
    assert local[19]["samples"] > 0
    assert local[0]["samples"] == 0


# ─────────────────────────── ping parsing ──────────────────────────────────

PING_OK = """\
Type escape sequence to abort.
Sending 20, 1400-byte ICMP Echos to 1.2.3.4, timeout is 1 seconds:
Packet sent with a source address of 5.6.7.8
!!!!!!!!!!!!!!!!!!!!
Success rate is 100 percent (20/20), round-trip min/avg/max = 34/502/1140 ms
"""

PING_DECIMAL = """\
Success rate is 95 percent (19/20), round-trip min/avg/max = 31.2/38.7/54.9 ms
"""

PING_DEAD = """\
Type escape sequence to abort.
Sending 20, 1400-byte ICMP Echos to 1.2.3.4, timeout is 1 seconds:
....................
Success rate is 0 percent (0/20)
"""


def test_parse_ping_normal():
    r = parse_ping(PING_OK)
    assert r == {"sent": 20, "received": 20, "loss_pct": 0.0,
                 "min_ms": 34.0, "avg_ms": 502.0, "max_ms": 1140.0}


def test_parse_ping_decimal_milliseconds():
    r = parse_ping(PING_DECIMAL)
    assert r["avg_ms"] == pytest.approx(38.7)
    assert r["loss_pct"] == pytest.approx(5.0)


def test_parse_ping_total_loss_has_no_round_trip_clause():
    """IOS omits the timing clause entirely at 0%. Treating that as a parse
    failure would turn the single most important result — the circuit is
    down — into a crash."""
    r = parse_ping(PING_DEAD)
    assert r["sent"] == 20 and r["received"] == 0
    assert r["loss_pct"] == 100.0
    assert r["min_ms"] is None and r["avg_ms"] is None


def test_parse_ping_absent():
    assert parse_ping("% Unrecognized host or address.") is None
    assert parse_ping("") is None


# ─────────────────────────── IP SLA parsing ────────────────────────────────

SLA_STATISTICS = """\
IPSLAs Latest Operation Statistics

IPSLA operation id: 210
        Latest RTT: 98 milliseconds
Latest operation start time: 01:32:30 UTC Tue Sep 1 2026
Latest operation return code: OK
Number of successes: 288
Number of failures: 0

IPSLA operation id: 310
Type of operation: udp-jitter
        Latest RTT: 41 milliseconds
Latest operation return code: OK
Source to Destination Latency one way Min/Avg/Max: 18/21/44
Source to Destination Jitter Min/Avg/Max: 1/4/29
Packet Loss SD: 2
MOS=4.31 ICPIF=11
"""

SLA_SUMMARY = """\
IPSLAs Latest Operation Summary
Codes: * active, ^ inactive, ~ pending

ID           Type        Destination       Stats       Return      Last
                                                       Code        Run
-----------------------------------------------------------------------
*210         path-jitter 1.2.3.4           RTT=98      OK          5 minutes ago
*310         udp-jitter  5.6.7.8           RTT=41      OK          1 second ago
"""


def test_parse_ip_sla_statistics_blocks():
    ops = {o["op_id"]: o for o in parse_ip_sla_statistics(SLA_STATISTICS)}
    assert set(ops) == {"210", "310"}
    assert ops["210"]["rtt_ms"] == 98.0
    assert ops["210"]["return_code"] == "OK"
    jitter = ops["310"]
    assert jitter["type"] == "udp-jitter"
    assert jitter["rtt_ms"] == 41.0
    assert jitter["jitter_ms"] == 4.0     # the avg of min/avg/max
    assert jitter["loss_pct"] == 2.0
    assert jitter["mos"] == pytest.approx(4.31)
    assert jitter["icpif"] == 11.0


def test_parse_ip_sla_summary_table():
    ops = {o["op_id"]: o for o in parse_ip_sla_statistics(SLA_SUMMARY)}
    assert set(ops) == {"210", "310"}
    assert ops["210"]["type"] == "path-jitter"
    assert ops["210"]["destination"] == "1.2.3.4"
    assert ops["210"]["rtt_ms"] == 98.0
    assert ops["310"]["destination"] == "5.6.7.8"


def test_parse_ip_sla_handles_absent_output():
    assert parse_ip_sla_statistics("") == []
    assert parse_ip_sla_statistics("% IP SLAs is not configured") == []


def test_sla_targets_dedupes_in_order():
    ops = parse_ip_sla_statistics(SLA_SUMMARY)
    assert sla_targets(ops) == ["1.2.3.4", "5.6.7.8"]
    assert sla_targets([]) == []


def test_merge_sla_ops_fills_the_destination_gap():
    """No single command has everything: `statistics` carries RTT/jitter/MOS
    but omits the destination, `summary` carries the destination but little
    else. Without merging, the live ping test has no target to borrow."""
    stats = parse_ip_sla_statistics(SLA_STATISTICS)
    summary = parse_ip_sla_statistics(SLA_SUMMARY)
    assert sla_targets(stats) == []          # the gap this exists to close

    merged = {o["op_id"]: o for o in merge_sla_ops(stats, summary)}
    assert merged["310"]["mos"] == pytest.approx(4.31)      # kept from statistics
    assert merged["310"]["destination"] == "5.6.7.8"        # filled from summary
    assert merged["210"]["type"] == "path-jitter"
    assert sla_targets(merge_sla_ops(stats, summary)) == ["1.2.3.4", "5.6.7.8"]


def test_merge_sla_ops_prefers_the_first_source():
    a = [{"op_id": "1", "rtt_ms": 10.0, "destination": None}]
    b = [{"op_id": "1", "rtt_ms": 99.0, "destination": "1.2.3.4"}]
    merged = merge_sla_ops(a, b)
    assert merged[0]["rtt_ms"] == 10.0        # first wins where both have a value
    assert merged[0]["destination"] == "1.2.3.4"   # second fills the hole


def test_merge_sla_ops_handles_empty_inputs():
    assert merge_sla_ops([], []) == []
    assert len(merge_sla_ops(parse_ip_sla_statistics(SLA_SUMMARY), [])) == 2


def test_timestamp_form_reports_what_orion_returned():
    """Surfaced in the report because the two Orion entities were found to
    serialise differently, and because utils/bandwidth_report.py feeds the
    same raw strings into time_buckets.bucket_start, which reads a naive
    value in the local zone of whatever machine runs it."""
    assert timestamp_form([{"t": "2026-09-01T00:00:00Z"}], "t") == "aware"
    assert timestamp_form([{"t": "2026-09-01T00:00:00"}], "t") == "naive"
    assert timestamp_form(
        [{"t": "2026-09-01T00:00:00Z"}, {"t": "2026-09-01T01:00:00"}], "t"
    ) == "mixed"
    assert timestamp_form([], "t") == "none"
    assert timestamp_form([{"t": "not-a-date"}], "t") == "none"
