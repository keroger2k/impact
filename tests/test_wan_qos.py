"""Tests for utils/wan_qos.py — the policy-map parser shared by
scripts/wan_qos_report.py and scripts/wan_queue_latency.py, and the
queue-latency math the latter is built on.

The parser was extracted from wan_qos_report.py so both scripts could use it;
these tests exist because extraction is exactly when a parser starts drifting
from the output it was written against.

Fixtures are hand-written, with invented hostnames and addressing per
docs/IP_ADDRESS_POLICY.md. The shape (hierarchical parent shaper + child
CBWFQ, shared LLQ block, `bandwidth remaining percent`) mirrors what this
fleet's C8000 border routers actually print.
"""
from __future__ import annotations

import pytest

from utils.wan_qos import (
    MIN_QUEUE_LIMIT_PACKETS,
    avg_packet_bytes,
    coalesce_counter_spans,
    compute_stats,
    counter_delta,
    counter_resolution_s,
    full_queue_delay_ms,
    guaranteed_bps,
    observed_drain_bps,
    parent_shape_bps,
    parse_interface_config,
    parse_interface_counters,
    parse_policy_map,
    percentile,
    pick_drain_bps,
    queue_delay_ms,
    queue_limit_packets,
    recommend_queue_limit,
    total_priority_bps,
)

# A hierarchical policy shaped to 42.5 Mbps with an LLQ and four CBWFQ
# classes — the fleet's standard branch WAN policy.
POLICY_MAP = """\
 GigabitEthernet0/0/5

  Service-policy output: WAN-PARENT

    Class-map: class-default (match-any)
      1491831333 packets, 998765432100 bytes
      30 second offered rate 19000000 bps, drop rate 5000 bps
      Match: any
      Queueing
      queue limit 64 packets
      (queue depth/total drops/no-buffer drops) 0/510081/0
      (pkts output/bytes output) 1491321252/998000000000
      shape (average) cir 42500000, bc 170000, be 170000
      target shape rate 42500000

      Service-policy : WAN-CHILD

        queue stats for all priority classes:
          Queueing
          queue limit 512 packets
          (queue depth/total drops/no-buffer drops) 0/0/0
          (pkts output/bytes output) 745915/149183000

        Class-map: EF (match-any)
          745915 packets, 149183000 bytes
          30 second offered rate 9000 bps, drop rate 0 bps
          Match:  dscp ef (46)
          Priority: 30% (12750 kbps), burst bytes 318750, b/w exceed drops: 0

        Class-map: MISSION_CRITICAL (match-any)
          0 packets, 0 bytes
          30 second offered rate 0 bps, drop rate 0 bps
          Match:  dscp af31 (26)
          Queueing
          queue limit 64 packets
          (queue depth/total drops/no-buffer drops) 0/0/0
          (pkts output/bytes output) 0/0
          bandwidth remaining 20%

        Class-map: CONTROL_SIGNAL (match-any)
          3281028 packets, 328102800 bytes
          30 second offered rate 4000 bps, drop rate 0 bps
          Match:  dscp cs3 (24)
          Queueing
          queue limit 64 packets
          (queue depth/total drops/no-buffer drops) 0/0/0
          (pkts output/bytes output) 3281028/328102800
          bandwidth remaining 5%

        Class-map: SCAVENGER (match-any)
          444864088 packets, 400377679200 bytes
          30 second offered rate 6000000 bps, drop rate 12000 bps
          Match:  dscp cs1 (8)
          Queueing
          queue limit 4096 packets
          (queue depth/total drops/no-buffer drops) 226/302445/0
          (pkts output/bytes output) 444561643/400105478700
          bandwidth remaining 5%

        Class-map: BE (match-any)
          1041392554 packets, 598000000000 bytes
          30 second offered rate 13000000 bps, drop rate 2000 bps
          Match: any
          Queueing
          queue limit 4096 packets
          (queue depth/total drops/no-buffer drops) 6/207636/0
          (pkts output/bytes output) 1041184918/597900000000
          bandwidth remaining 60%
          Fair-queue: per-flow queue limit 1024 packets

        Class-map: class-default (match-any)
          0 packets, 0 bytes
          30 second offered rate 0 bps, drop rate 0 bps
          Match: any
          queue limit 64 packets
          (queue depth/total drops/no-buffer drops) 0/0/0
          (pkts output/bytes output) 0/0
"""

SHOW_INTERFACES = """\
GigabitEthernet0/0/5 is up, line protocol is up
  Hardware is 8P4S, address is 0000.5e00.5301 (bia 0000.5e00.5301)
  Internet address is 1.2.3.4/30
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 114/255, rxload 12/255
  Encapsulation ARPA, loopback not set
  Keepalive not supported
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
  output flow-control is off, input flow-control is off
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:00, output hang never
  Last clearing of "show interface" counters 41w2d
  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 510081
  Queueing strategy: Class-based queueing
  5 minute input rate 1874000 bits/sec, 402 packets/sec
  5 minute output rate 18994000 bits/sec, 2210 packets/sec
     903214410 packets input, 411223344556 bytes, 0 no buffer
     Received 0 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles
     1491321252 packets output, 998000000000 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
"""

TUNNEL_CONFIG = """\
interface Tunnel100
 description DMVPN spoke
 bandwidth 42500
 ip address 1.2.3.5 255.255.255.0
 load-interval 30
 qos pre-classify
!
interface Tunnel200
 description backup overlay
 ip address 5.6.7.8 255.255.255.0
!
"""


@pytest.fixture
def parsed():
    return parse_policy_map(POLICY_MAP)


# ─────────────────────────── parser ────────────────────────────────────────

def test_interface_and_policy_names(parsed):
    assert parsed["interface"] == "GigabitEthernet0/0/5"
    assert parsed["top_policy_name"] == "WAN-PARENT"
    assert parsed["nested_policy_name"] == "WAN-CHILD"


def test_indentation_maps_to_depth(parsed):
    by_name = {(c["name"], c["depth"]) for c in parsed["classes"]}
    # The parent class-default and the child one share a name; only depth
    # separates them, which is why depth is part of the identity everywhere.
    assert ("class-default", 0) in by_name
    assert ("class-default", 1) in by_name
    assert all(c["depth"] == 1 for c in parsed["classes"] if c["name"] == "BE")


def test_shared_llq_block_attaches_to_priority_class(parsed):
    ef = next(c for c in parsed["classes"] if c["name"] == "EF")
    # EF prints no queue line of its own; the "queue stats for all priority
    # classes" block above it is its queue, genuinely shared.
    assert ef["shared_priority_queue"] is True
    assert ef["queue_limit"] == 512
    assert ef["queue_depth"] == 0
    assert ef["priority_kbps"] == 12750
    assert ef["priority_pct"] == 30


def test_non_priority_class_keeps_its_own_queue_line(parsed):
    scav = next(c for c in parsed["classes"] if c["name"] == "SCAVENGER")
    assert scav["shared_priority_queue"] is False
    assert scav["queue_limit"] == 4096
    assert scav["queue_depth"] == 226
    assert scav["total_drops"] == 302445
    assert scav["bandwidth_remaining_pct"] == 5


def test_counters_and_shaper(parsed):
    parent = next(c for c in parsed["classes"] if c["depth"] == 0)
    assert parent["packets"] == 1491831333
    assert parent["shape_cir_bps"] == 42500000
    assert parent["target_shape_bps"] == 42500000


def test_aqm_flags(parsed):
    be = next(c for c in parsed["classes"] if c["name"] == "BE")
    scav = next(c for c in parsed["classes"] if c["name"] == "SCAVENGER")
    assert be["has_fair_queue"] is True
    assert scav["has_fair_queue"] is False
    assert scav["has_random_detect"] is False


@pytest.mark.parametrize("line,limit,unit", [
    ("queue limit 4096 packets", 4096, "packets"),
    ("queue limit 64000 bytes", 64000, "bytes"),
    ("queue limit 5000 us", 5000, "us"),
    ("queue limit 50 ms", 50, "ms"),
])
def test_queue_limit_units_are_captured(line, limit, unit):
    text = f" Gi0/0/1\n  Service-policy output: P\n    Class-map: X (match-any)\n      Queueing\n      {line}\n"
    cls = parse_policy_map(text)["classes"][0]
    assert (cls["queue_limit"], cls["queue_limit_unit"]) == (limit, unit)


def test_parser_tolerates_unknown_lines():
    text = POLICY_MAP.replace("      Match: any\n",
                              "      Match: any\n      QoS Set\n        dscp af21\n", 1)
    assert len(parse_policy_map(text)["classes"]) == len(parse_policy_map(POLICY_MAP)["classes"])


def test_compute_stats_denominates_against_depth_zero(parsed):
    stats = compute_stats(parsed)
    assert stats["total_traffic_pkts"] == 1491831333
    scav = next(c for c in stats["classes"] if c["name"] == "SCAVENGER")
    assert scav["pct_of_total_traffic"] == pytest.approx(29.82, abs=0.05)
    assert scav["queue_fill_pct"] == pytest.approx(226 / 4096 * 100)


# ─────────────────────── shaper / drain rates ──────────────────────────────

def test_parent_shape_and_priority_totals(parsed):
    assert parent_shape_bps(parsed) == 42_500_000
    assert total_priority_bps(parsed) == 12_750_000


def test_guaranteed_bps_priority_class(parsed):
    ef = next(c for c in parsed["classes"] if c["name"] == "EF")
    assert guaranteed_bps(ef, 42_500_000, 12_750_000) == 12_750_000


def test_guaranteed_bps_bandwidth_remaining_excludes_llq(parsed):
    be = next(c for c in parsed["classes"] if c["name"] == "BE")
    # 60% of what is left after the LLQ reservation, not 60% of the shaper.
    assert guaranteed_bps(be, 42_500_000, 12_750_000) == pytest.approx(17_850_000)


def test_guaranteed_bps_flat_bandwidth():
    cls = {"bandwidth_kbps": 2000}
    assert guaranteed_bps(cls, 42_500_000, 0) == 2_000_000


def test_guaranteed_bps_returns_none_without_a_basis():
    assert guaranteed_bps({}, None, 0) is None


# ─────────────────────── counter deltas ────────────────────────────────────

def test_counter_delta_normal_and_wrap():
    assert counter_delta(100, 250) == 150
    assert counter_delta(None, 250) is None
    # A reset/wrap must not become a negative rate downstream.
    assert counter_delta(4_000_000_000, 12) is None


def test_observed_drain_and_packet_size():
    prev = {"bytes_output": 1_000_000, "pkts_output": 1_000}
    cur = {"bytes_output": 3_500_000, "pkts_output": 3_000}
    assert observed_drain_bps(prev, cur, 2.0) == pytest.approx(10_000_000)
    assert avg_packet_bytes(prev, cur) == pytest.approx(1250)


def test_observed_drain_survives_counter_reset():
    prev = {"bytes_output": 3_500_000, "pkts_output": 3_000}
    cur = {"bytes_output": 12, "pkts_output": 1}
    assert observed_drain_bps(prev, cur, 2.0) is None
    assert avg_packet_bytes(prev, cur) is None


# ─────────────────────── latency math ──────────────────────────────────────

def test_queue_delay_ms_matches_hand_calculation():
    # 4096 packets of 1500 B at 17.85 Mbps ~= 2.75 s. This is the number the
    # whole feature exists to surface.
    ms = queue_delay_ms(4096, 1500, 17_850_000)
    assert ms == pytest.approx(2753.6, rel=0.01)


def test_full_queue_delay_for_the_scavenger_queue(parsed):
    scav = next(c for c in parsed["classes"] if c["name"] == "SCAVENGER")
    drain = guaranteed_bps(scav, 42_500_000, 12_750_000)  # 5% of 29.75M = 1.4875 Mbps
    ms = full_queue_delay_ms(scav, 900.0, drain)
    assert ms == pytest.approx(4096 * 900 * 8 / 1_487_500 * 1000, rel=1e-6)
    assert ms > 15_000  # a bulk queue permitted to buffer for over 15 seconds


def test_recommend_queue_limit_is_the_inverse_of_the_delay():
    rec = recommend_queue_limit(100, 1500, 17_850_000)
    assert rec == 148
    # Round-tripping the recommendation lands back on the budget.
    assert queue_delay_ms(rec, 1500, 17_850_000) == pytest.approx(100, rel=0.02)


def test_recommend_queue_limit_respects_the_floor():
    # 5% of the remaining bandwidth at a 50 ms budget is arithmetically ~6
    # packets; a config that shallow trades the latency problem back for a
    # loss one, so the floor holds.
    assert recommend_queue_limit(50, 1500, 1_487_500) == MIN_QUEUE_LIMIT_PACKETS


def test_recommend_queue_limit_needs_both_inputs():
    assert recommend_queue_limit(100, None, 17_850_000) is None
    assert recommend_queue_limit(100, 1500, None) is None


@pytest.mark.parametrize("unit,limit,expected", [
    ("packets", 4096, 4096),
    ("bytes", 150_000, 100),          # / 1500 B per packet
    ("ms", 100, 148),                 # 100 ms of 17.85 Mbps in 1500 B packets
])
def test_queue_limit_normalises_units(unit, limit, expected):
    cls = {"queue_limit": limit, "queue_limit_unit": unit}
    assert queue_limit_packets(cls, 1500, 17_850_000) == pytest.approx(expected, rel=0.01)


def test_a_microsecond_limit_is_not_read_as_packets():
    """The regression the unit capture exists for: `queue limit 5000 us` is
    5 ms, not 5000 packets — reading it as packets inverts the finding."""
    cls = {"queue_limit": 5000, "queue_limit_unit": "us"}
    assert full_queue_delay_ms(cls, 1500, 17_850_000) == pytest.approx(5.0, rel=0.01)


def test_pick_drain_bps_prefers_measured_but_says_so():
    assert pick_drain_bps(10_000_000, 17_850_000) == (10_000_000, "measured")
    # A near-idle class's observed rate is noise; fall back and label it.
    assert pick_drain_bps(12.0, 17_850_000) == (17_850_000, "guaranteed")
    assert pick_drain_bps(None, None) == (None, "unknown")


def test_coalesce_merges_intervals_until_the_counter_moves():
    """The regression this exists for, reproduced from a real run.

    A 42.5 Mbps circuit averaging 42.0 Mbps was reported as peaking at
    123.7 Mbps — 291% of its own shaper. The router refreshes these counters
    every ~6s, so polling every 2s left two of every three intervals reading
    a delta of zero and the third carrying three intervals' worth of bytes.
    Dividing that lump by one interval inflates the rate by exactly the
    aliasing ratio.
    """
    bytes_per_2s = 42_000_000 * 2 / 8  # 42 Mbps for 2 seconds
    readings, total = [], 0
    for i in range(31):
        if i % 3 == 0 and i > 0:
            total += int(bytes_per_2s * 3)   # three intervals published at once
        readings.append((float(i * 2), total))

    spans = coalesce_counter_spans(readings)
    rates = [d * 8 / secs for secs, d in spans]
    # Every span is a true 6-second average at the real rate, not a 3x spike.
    assert all(41_000_000 < r < 43_000_000 for r in rates), rates
    assert max(rates) < 45_000_000
    assert counter_resolution_s(spans) == pytest.approx(6.0)


def test_naive_adjacent_pairs_are_what_produced_the_bogus_peak():
    """Pins the failure mode itself, so the fix can't be quietly reverted."""
    bytes_per_2s = 42_000_000 * 2 / 8
    readings, total = [], 0
    for i in range(31):
        if i % 3 == 0 and i > 0:
            total += int(bytes_per_2s * 3)
        readings.append((float(i * 2), total))

    naive = [(b[1] - a[1]) * 8 / (b[0] - a[0]) for a, b in zip(readings, readings[1:])]
    assert max(naive) > 120_000_000     # the 123.7 Mbps artifact
    # ...while the mean over the window was right all along, which is why the
    # bogus peak was not obviously wrong.
    total_secs = readings[-1][0] - readings[0][0]
    assert readings[-1][1] * 8 / total_secs == pytest.approx(42_000_000, rel=0.05)


def test_coalesce_drops_a_counter_reset_without_smearing_it():
    readings = [(0.0, 1000), (2.0, 3000), (4.0, 12), (6.0, 2012)]
    spans = coalesce_counter_spans(readings)
    # The 3000 -> 12 reset contributes nothing; the span after it is clean.
    assert spans == [(2.0, 2000), (2.0, 2000)]


def test_coalesce_discards_a_trailing_unpublished_run():
    # Counters that never moved after the last change: those bytes simply
    # haven't been published, so reporting an idle span would be a lie.
    readings = [(0.0, 0), (2.0, 1000), (4.0, 1000), (6.0, 1000)]
    assert coalesce_counter_spans(readings) == [(2.0, 1000)]


def test_coalesce_handles_a_never_moving_counter():
    assert coalesce_counter_spans([(0.0, 5), (2.0, 5), (4.0, 5)]) == []
    assert counter_resolution_s([]) is None


def test_percentile_is_nearest_rank():
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    assert percentile(values, 50) == 3.0
    assert percentile(values, 95) == 100.0
    assert percentile([], 95) is None


# ─────────────────────── interface parsing ─────────────────────────────────

def test_parse_interface_counters():
    c = parse_interface_counters(SHOW_INTERFACES)
    assert c["pkts_out"] == 1491321252
    assert c["bytes_out"] == 998000000000
    assert c["pkts_in"] == 903214410
    assert c["total_output_drops"] == 510081


def test_parse_interface_counters_reports_absence_not_zero():
    c = parse_interface_counters("GigabitEthernet0/0/5 is up, line protocol is up\n")
    assert c["bytes_out"] is None and c["total_output_drops"] is None


def test_parse_interface_config_reads_preclassify_and_load_interval():
    cfg = parse_interface_config(TUNNEL_CONFIG)
    assert cfg["Tunnel100"]["qos_pre_classify"] is True
    assert cfg["Tunnel100"]["load_interval"] == 30
    assert cfg["Tunnel200"]["qos_pre_classify"] is False
    assert cfg["Tunnel200"]["load_interval"] is None
