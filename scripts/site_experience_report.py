#!/usr/bin/env python3
"""scripts/site_experience_report.py — an objective score for what using a
site actually feels like.

The companion to scripts/wan_qos_report.py and scripts/wan_queue_latency.py.
Those two measure the router describing its own queues, which is an
*inference* about user experience. This one measures the experience.

── The problem it solves ────────────────────────────────────────────────────

"It seems slow" is not actionable, not comparable between sites, and cannot
be used to prove a change worked. Meanwhile every dashboard says the site is
fine: the circuit is up, utilisation looks moderate, and with deep queues
there is no packet loss to point at.

The number that resolves this is already collectable and has simply never
been correlated:

    penalty = round-trip time while the circuit is BUSY
            - round-trip time while the circuit is IDLE

Idle RTT is short, stable, and useless — it is what the dashboards show. The
busy figure is what a user waits through on every click, keystroke, page load
and file open. On a site with deep WAN buffers the gap runs into hundreds of
milliseconds with nothing failing anywhere. That gap *is* the complaint, and
it grades against a published scale (see utils/experience.py), so the output
is a letter and a millisecond figure rather than an opinion.

── Where the data comes from ────────────────────────────────────────────────

Passive (the default — two SWQL reads, no SSH, nothing touched):
  * Orion.ResponseTime         -> AvgResponseTime / MaxResponseTime / Availability
  * Orion.NPM.InterfaceTraffic -> OutPercentUtil on the site's WAN interface
Paired into common time buckets, binned by concurrent utilisation.

Active (--live, opt-in because it generates traffic and needs SSH):
  Paired pings from the router at two DSCP markings, back to back so both
  see the same congestion, while sampling the WAN load and queue depth:
      ping <target> source <wan-if> tos 0   ...   # DSCP 0,  best effort
      ping <target> source <wan-if> tos 184 ...   # DSCP 46, EF
  If EF and BE come back the same, the policy is not classifying. That
  distinguishes "QoS is broken" from "QoS works but nothing is marked",
  which have completely different fixes — and the queue profiler's usual
  finding of ~99% best-effort predicts the latter.

Also parsed, where configured: `show ip sla statistics`. IP SLA is the only
*independent* measurement on the box — a real round trip across the circuit,
and on a jitter operation a MOS score, which is a literal 1-5 user-experience
number for voice.

── What it cannot tell you ──────────────────────────────────────────────────

Stated because each would otherwise read as a bug:

  * Orion.ResponseTime is ICMP from the poller to the router's *management*
    IP. It crosses the same WAN, but the router marks its own control-plane
    traffic — plausibly into a protected class. Where that is true the
    measured penalty is a **floor**, not the full user-visible one.
  * Correlation buckets mix loaded and idle moments within each bucket, which
    dilutes the result in the conservative direction. The real penalty is at
    least what is reported.
  * Pings are locally originated. IOS-XE applies the egress service-policy to
    them so the `tos` marking classifies correctly, but CoPP adds its own
    sending-side delay that a transit packet would not see.
  * A grade needs enough buckets in both bins. Where it doesn't have them it
    says so instead of printing a letter (utils.experience.MIN_BUCKETS_PER_BIN).

── Read-only ────────────────────────────────────────────────────────────────

SolarWinds access is clients.solarwinds.query (SWQL SELECT only). DNAC calls
are GETs. Device commands are `show` and `ping`, run through
utils.device_ssh.ssh_session, which has no config-mode path.

Usage:
    .venv/bin/python -m scripts.site_experience_report "DCA"
    .venv/bin/python -m scripts.site_experience_report "DCA" --days 14
    .venv/bin/python -m scripts.site_experience_report "DCA" --live
    .venv/bin/python -m scripts.site_experience_report --device RTR-DCA-01 --live \
        --ping-target 1.2.3.4 --json /tmp/k.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.dnac as dc  # noqa: E402
import clients.solarwinds as sw  # noqa: E402
from utils.bandwidth_report import (  # noqa: E402
    _escape_literal,
    _validate_name,
    bare_interface_name,
    list_interfaces_for_router,
    short_hostname,
)
from utils.device_ssh import guess_device_type, ssh_session  # noqa: E402
from utils.experience import (  # noqa: E402
    MIN_BUCKETS_PER_BIN,
    busy_share,
    correlate,
    detect_series_offset,
    hour_profile,
    latency_under_load,
    merge_sla_ops,
    overlap_ratio,
    parse_ip_sla_statistics,
    parse_ping,
    sla_targets,
    timestamp_form,
)
from utils.wan_qos import parse_interface_counters, parse_policy_map  # noqa: E402
# Target resolution is imported wholesale rather than reimplemented. The
# shallowest-site-match fix in particular must not exist in two versions —
# see find_best_site_match_prefer_shallow's docstring.
from scripts.wan_qos_report import (  # noqa: E402
    DEFAULT_ROLE,
    _IFACE_NAME_RE,
    find_best_site_match_prefer_shallow,
    find_border_routers,
    find_devices_by_name,
    get_site_device_ids,
    resolve_wan_interface,
    site_and_descendant_ids,
)
from scripts.tag_c8k_wan_interfaces import DEFAULT_TAG_NAME, DEFAULT_VRFS  # noqa: E402

logger = logging.getLogger("site_experience_report")

SSH_TIMEOUT = 30
DEFAULT_DAYS = 7
DEFAULT_BUCKET_MINUTES = 15
DEFAULT_IDLE_BELOW = 30.0
DEFAULT_BUSY_ABOVE = 70.0
DEFAULT_PING_COUNT = 20
DEFAULT_PING_SIZE = 1400
DEFAULT_PING_ROUNDS = 3

# ToS byte values for the paired live test. DSCP occupies the top 6 bits of
# the ToS byte, so ToS = DSCP << 2: EF (46) -> 184, best effort (0) -> 0.
PING_CLASSES = [("BE", 0), ("EF", 46 << 2)]

# Below this share of pairable samples, the two series are not describing the
# same window and nothing derived from them means anything — almost always a
# storage-timezone difference that detect_series_offset could not resolve.
_MIN_OVERLAP = 0.25

# Columns that are not proven to exist on Orion.ResponseTime anywhere in this
# codebase. SWQL is all-or-nothing, so they are requested first and dropped on
# failure — the same degrade-rather-than-fail pattern
# utils/device_comparison_report.py uses for its maintenance columns.
_OPTIONAL_RTT_COLUMNS = """,
    RT.MinResponseTime,
    RT.PercentLoss"""


# ─────────────────────────── SolarWinds reads ──────────────────────────────

def _rtt_swql(node_id: int, days: int, extra_columns: str) -> str:
    return f"""
SELECT
    RT.ObservationTimestamp,
    RT.AvgResponseTime,
    RT.MaxResponseTime,
    RT.Availability{extra_columns}
FROM Orion.ResponseTime RT
WHERE RT.NodeID = {int(node_id)}
AND RT.ObservationTimestamp >= ADDDAY(-{int(days)}, GETUTCDATE())
ORDER BY RT.ObservationTimestamp
"""


def fetch_response_time(node_id: int, days: int, timeout: int | None = None) -> tuple[list[dict], bool]:
    """Per-poll response-time history for one node.

    Returns (rows, got_optional_columns). MinResponseTime/PercentLoss are
    requested first and the query retried without them on failure, so an
    instance that lacks those columns degrades to Availability-as-loss rather
    than taking down the whole report.
    """
    try:
        return sw.query(_rtt_swql(node_id, days, _OPTIONAL_RTT_COLUMNS), timeout=timeout), True
    except Exception as e:
        logger.warning("Response-time query with optional columns failed (%s) — "
                       "retrying without MinResponseTime/PercentLoss", str(e)[:160])
    return sw.query(_rtt_swql(node_id, days, ""), timeout=timeout), False


def fetch_utilisation(interface_id: int, days: int, timeout: int | None = None) -> list[dict]:
    """Per-poll egress utilisation for one interface.

    Same entity and columns utils/bandwidth_report.py already charts, so the
    numbers here reconcile with the web app's Bandwidth Utilization report.
    """
    return sw.query(f"""
SELECT
    IT.DateTime,
    IT.InPercentUtil,
    IT.OutPercentUtil
FROM Orion.NPM.InterfaceTraffic IT
WHERE IT.InterfaceID = {int(interface_id)}
AND IT.DateTime >= ADDDAY(-{int(days)}, GETUTCDATE())
ORDER BY IT.DateTime
""", timeout=timeout)


def find_node(router_name: str, timeout: int | None = None) -> dict | None:
    """Resolve a router name to its Orion node, preferring an exact Caption.

    Mirrors utils.bandwidth_report.find_node_ip's matching, but returns the
    NodeID (which that helper doesn't expose) since every query here is
    node-keyed.
    """
    name = short_hostname(router_name)
    _validate_name(name, "router name")
    safe = _escape_literal(name)
    rows = sw.query(f"""
SELECT
    N.NodeID,
    N.Caption AS NodeName,
    N.IPAddress AS NodeIpAddress,
    CP.Site
FROM Orion.Nodes N
LEFT JOIN Orion.NodesCustomProperties CP ON CP.NodeID = N.NodeID
WHERE N.Caption = '{safe}' OR N.Caption LIKE '%{safe}%'
ORDER BY N.Caption
""", timeout=timeout)
    if not rows:
        return None
    for row in rows:
        if str(row.get("NodeName", "")).lower() == name.lower():
            return row
    return rows[0]


def find_interface(router_name: str, interface_name: str,
                   timeout: int | None = None) -> dict | None:
    """The Orion interface row for this router's WAN port.

    Matched on the bare interface name (utils.bandwidth_report.bare_interface_name),
    because Orion's Caption carries free-text circuit decoration that never
    equals the name the router calls the interface.
    """
    wanted = bare_interface_name(interface_name).lower()
    for row in list_interfaces_for_router(short_hostname(router_name)):
        for key in ("InterfaceName", "InterfaceCaption", "InterfaceAlias"):
            if bare_interface_name(str(row.get(key) or "")).lower() == wanted:
                return row
    return None


# ─────────────────────────── live ping test ────────────────────────────────

def run_live_test(run, wan_if: str, target: str, count: int, size: int,
                  rounds: int, timeout: int) -> dict:
    """Paired-DSCP pings while sampling the concurrent WAN load.

    The two classes run back to back inside each round so they see the same
    congestion — running all the EF pings and then all the BE pings would
    compare two different minutes of traffic and prove nothing.
    """
    results: dict[str, list[dict]] = {name: [] for name, _ in PING_CLASSES}
    loads: list[float] = []
    depths: list[int] = []

    # A ping with `timeout 1` blocks the CLI for up to `count` seconds when
    # the target is unreachable. The default read timeout would abort the
    # session mid-test, so size it to the worst case plus margin.
    read_timeout = max(timeout, count + 15)

    for r in range(rounds):
        before = run([("iface", f"show interfaces {wan_if}")], required=("iface",))
        t0 = time.monotonic()

        for name, tos in PING_CLASSES:
            cmd = (f"ping {target} source {wan_if} tos {tos} "
                   f"repeat {count} size {size} timeout 1")
            out = run([("ping", cmd)], required=(), read_timeout=read_timeout)
            parsed = parse_ping(out.get("ping", ""))
            if parsed:
                results[name].append(parsed)
            else:
                logger.warning("Round %d: no ping summary parsed for %s (target %s)",
                               r + 1, name, target)

        after = run([
            ("iface", f"show interfaces {wan_if}"),
            ("policy", f"show policy-map interface {wan_if} output"),
        ], required=("iface",))

        elapsed = time.monotonic() - t0
        b = parse_interface_counters(before.get("iface", ""))
        a = parse_interface_counters(after.get("iface", ""))
        if b.get("bytes_out") is not None and a.get("bytes_out") is not None and elapsed > 0:
            delta = a["bytes_out"] - b["bytes_out"]
            if delta >= 0:
                loads.append(delta * 8 / elapsed)

        policy = parse_policy_map(after.get("policy", ""))
        for c in policy.get("classes", []):
            if c.get("queue_depth"):
                depths.append(c["queue_depth"])

        logger.info("  round %d/%d done", r + 1, rounds)

    summary = {}
    for name, tos in PING_CLASSES:
        runs = results[name]
        if not runs:
            summary[name] = None
            continue
        sent = sum(x["sent"] for x in runs)
        received = sum(x["received"] for x in runs)
        avgs = [x["avg_ms"] for x in runs if x["avg_ms"] is not None]
        summary[name] = {
            "tos": tos,
            "dscp": tos >> 2,
            "sent": sent,
            "received": received,
            "loss_pct": ((sent - received) / sent * 100) if sent else None,
            "min_ms": min((x["min_ms"] for x in runs if x["min_ms"] is not None), default=None),
            "avg_ms": (sum(avgs) / len(avgs)) if avgs else None,
            "max_ms": max((x["max_ms"] for x in runs if x["max_ms"] is not None), default=None),
        }
    return {
        "target": target,
        "rounds": rounds,
        "classes": summary,
        "load_bps": (sum(loads) / len(loads)) if loads else None,
        "max_queue_depth": max(depths) if depths else None,
    }


# ─────────────────────────── formatting ────────────────────────────────────

def _ms(value) -> str:
    if value is None:
        return "-"
    if value >= 1000:
        return f"{value / 1000:.2f} s"
    return f"{value:.0f} ms"


def _pct(value) -> str:
    return f"{value:.1f}%" if value is not None else "-"


def _bps(value) -> str:
    if not value:
        return "n/a"
    if value >= 1e6:
        return f"{value / 1e6:.1f} Mb/s"
    return f"{value / 1e3:.0f} kb/s"


def _wrap(text: str, width: int = 76) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def _plain_english(result: dict, share: float | None) -> list[str]:
    """Say what the penalty means for a person. Converting the number back
    into words is the whole deliverable — a millisecond figure nobody can
    picture does not settle an argument about whether a site is slow."""
    penalty = result.get("penalty_p50_ms")
    if penalty is None:
        return ["Not enough paired samples in both bins to state a penalty."]
    if penalty < 30:
        return _wrap(
            f"Latency barely moves when this circuit gets busy (+{_ms(penalty)}). "
            f"Whatever users are experiencing, the WAN egress queues are not "
            f"causing it — look at the inbound direction, the application path, "
            f"or the client side."
        )
    seconds = penalty / 1000.0
    when = f" Users are in that state {share:.0f}% of the window." if share else ""
    return _wrap(
        f"When this circuit is busy, everything a user does waits an extra "
        f"{seconds:.2f} s before anything happens — every click, keystroke, page "
        f"load and file open.{when} Nothing is failing and nothing is being "
        f"dropped, which is why no alarm fires and every dashboard looks fine. "
        f"This is what \"it seems slow\" is."
    )


def render(site_label: str, node: dict, wan_if: str, method: str, days: int,
           pairs: list[dict], result: dict, share: float | None, offset,
           hours: list[dict], sla_ops: list[dict], live: dict | None,
           circuit_bps: float | None, tz_offset: float, notes: list[str]) -> None:
    print("=" * 88)
    print(f"Site Experience Scorecard — {site_label}")
    print("=" * 88)
    print(f"Router:        {node.get('NodeName')}")
    print(f"WAN:           {wan_if}  (detected via: {method})"
          + (f", {circuit_bps / 1e6:.1f} Mb/s circuit" if circuit_bps else ""))
    print(f"Window:        last {days} days")
    print(f"Paired:        {len(pairs)} buckets with both latency and load")
    for note in notes:
        print(f"  ! {note}")
    print()

    # ── the headline ──
    grade_txt = result["grade"] or "insufficient data"
    print(f"LATENCY UNDER LOAD{' ' * 44}GRADE: {grade_txt}")
    lw = 24
    idle_label = f"Idle  (WAN < {result['_idle_below']:.0f}%)  p50"
    busy_label = f"Busy  (WAN >= {result['_busy_above']:.0f}%) p50"
    print(f"  {idle_label:<{lw}}{_ms(result['idle_p50_ms']):>10}"
          f"{'':22}[{result['idle_buckets']} buckets]")
    print(f"  {busy_label:<{lw}}{_ms(result['busy_p50_ms']):>10}"
          f"   worst 5%: {_ms(result['busy_p95_ms']):>7}"
          f"   [{result['busy_buckets']} buckets]")
    print(f"  {'Penalty':<{lw}}{_ms(result['penalty_p50_ms']):>10}"
          f"   worst 5%: {_ms(result['penalty_p95_ms']):>7}")
    if not result["sufficient"]:
        print(f"  (Needs {MIN_BUCKETS_PER_BIN}+ buckets in each bin to grade; a letter from "
              f"fewer would not be reproducible.)")
    if share is not None:
        print(f"  Time in the busy state:  {share:.0f}% of the window")
    if result["rpm_busy"]:
        print(f"  Responsiveness under load: {result['rpm_busy']:.0f} RPM "
              f"(idle {result['rpm_idle']:.0f}; >1000 is responsive, <200 reads as broken)")
    print()
    for line in _plain_english(result, share):
        print(f"  {line}")
    print()

    # ── availability ──
    print("AVAILABILITY (ICMP probe success)")
    print(f"  Idle: {_pct(result['idle_availability'])}"
          f"       Busy: {_pct(result['busy_availability'])}")
    print()

    # ── time of day ──
    active = [h for h in hours if h["samples"]]
    if active:
        peak = max((h["rtt_ms"] or 0) for h in active) or 1.0
        tz_label = f"UTC{tz_offset:+.0f}" if tz_offset else "UTC"
        print(f"WHEN IT IS BAD (median RTT by hour, {tz_label})")
        for h in hours:
            if not h["samples"]:
                continue
            bar = "#" * int(round((h["rtt_ms"] or 0) / peak * 32))
            print(f"  {h['hour']:02d}  {_ms(h['rtt_ms']):>9}  {_pct(h['util_pct']):>6}  {bar}")
        print()

    # ── live test ──
    if live:
        load = f", WAN at {_bps(live['load_bps'])}" if live.get("load_bps") else ""
        print(f"LIVE TEST ({live['rounds']} rounds to {live['target']}{load})")
        print(f"  {'Class':<7}{'DSCP':>5}{'Sent':>7}{'Loss':>8}{'min':>10}{'avg':>10}{'max':>10}")
        for name, _ in PING_CLASSES:
            row = live["classes"].get(name)
            if not row:
                print(f"  {name:<7}{'—':>5}{'—':>7}{'no result':>8}")
                continue
            print(f"  {name:<7}{row['dscp']:>5}{row['sent']:>7}{_pct(row['loss_pct']):>8}"
                  f"{_ms(row['min_ms']):>10}{_ms(row['avg_ms']):>10}{_ms(row['max_ms']):>10}")
        be, ef = live["classes"].get("BE"), live["classes"].get("EF")
        if be and ef and be["avg_ms"] is not None and ef["avg_ms"] is not None:
            gap = be["avg_ms"] - ef["avg_ms"]
            print()
            if gap > 30:
                for line in _wrap(
                    f"EF is {_ms(gap)} faster than best-effort under the same load, so the "
                    f"policy IS protecting marked traffic. The problem is what is not "
                    f"marked — check the class shares in wan_qos_report."
                ):
                    print(f"  {line}")
            else:
                for line in _wrap(
                    f"EF and best-effort are within {_ms(abs(gap))} of each other, so marking "
                    f"is buying nothing here. Either the policy is not classifying, or the "
                    f"ping's DSCP is not surviving to the egress policy — check the "
                    f"qos pre-classify finding in wan_queue_latency."
                ):
                    print(f"  {line}")
        print()

    # ── IP SLA ──
    if sla_ops:
        print("IP SLA (independent round-trip probes configured on this router)")
        print(f"  {'ID':<7}{'Type':<14}{'Destination':<22}{'RTT':>9}{'Jitter':>9}"
              f"{'Loss':>8}{'MOS':>7}")
        for op in sla_ops:
            mos = f"{op['mos']:.2f}" if op["mos"] is not None else "-"
            print(f"  {op['op_id']:<7}{(op['type'] or '-'):<14}"
                  f"{(op['destination'] or '-'):<22}"
                  f"{_ms(op['rtt_ms']):>9}{_ms(op['jitter_ms']):>9}"
                  f"{_pct(op['loss_pct']):>8}{mos:>7}")
        # A MOS below 4.0 is where voice users start describing calls as
        # choppy; below 3.6 they escalate. Worth naming, since the number is
        # meaningless to anyone who hasn't seen the scale.
        if any(op["mos"] is not None for op in sla_ops):
            print("  MOS is a 1-5 voice-quality score: 4.4 is toll quality, "
                  "below 4.0 sounds choppy.")
        print()


# ─────────────────────────── per-device flow ───────────────────────────────

def report_device(dnac, device: dict, args) -> int:
    hostname = device.get("hostname") or device.get("id")
    ip = device.get("managementIpAddress")

    if args.interface:
        wan_if, method = args.interface, "manual override"
    else:
        target_vrfs = {v.strip().upper() for v in args.vrf.split(",") if v.strip()}
        wan_if, method = resolve_wan_interface(dnac, device, args.tag_name, target_vrfs)
    if not wan_if:
        logger.error("%s: could not determine a WAN interface (%s) — pass --interface",
                     hostname, method)
        return 1
    if not _IFACE_NAME_RE.match(wan_if):
        logger.error("%s: resolved interface name '%s' failed validation", hostname, wan_if)
        return 1

    logger.info("%s: resolving in SolarWinds...", hostname)
    node = find_node(hostname)
    if not node:
        logger.error("%s: no matching node in SolarWinds — cannot score latency history",
                     hostname)
        return 1
    iface = find_interface(hostname, wan_if)
    if not iface:
        logger.error("%s: SolarWinds is not polling interface %s — the utilisation half "
                     "of the correlation is unavailable", hostname, wan_if)
        return 1

    logger.info("%s: reading %d days of response time and utilisation...", hostname, args.days)
    rtt_rows, _ = fetch_response_time(int(node["NodeID"]), args.days)
    util_rows = fetch_utilisation(int(iface["InterfaceID"]), args.days)

    notes: list[str] = []
    if not rtt_rows:
        logger.error("%s: no response-time rows in the last %d days", hostname, args.days)
        return 1
    if not util_rows:
        logger.error("%s: no interface-traffic rows in the last %d days", hostname, args.days)
        return 1

    # The alignment guard. See utils.experience.detect_series_offset — this is
    # the failure this feature was most likely to ship with.
    offset = detect_series_offset(rtt_rows, util_rows)
    rtt_form = timestamp_form(rtt_rows, "ObservationTimestamp")
    util_form = timestamp_form(util_rows, "DateTime")
    if rtt_form != util_form:
        # Worth naming rather than silently handling: utils/bandwidth_report.py
        # feeds raw DateTime strings into time_buckets.bucket_start, which
        # reads a naive value in the local zone of whatever machine runs it.
        notes.append(
            f"Orion serialises these two entities differently — ResponseTime "
            f"timestamps are {rtt_form}, InterfaceTraffic are {util_form}. Naive "
            f"values are read as UTC here."
        )
    if offset and offset != timedelta(0):
        notes.append(
            f"Response-time and utilisation timestamps differ by {offset}. Corrected "
            f"before pairing."
        )

    bucket_seconds = args.bucket_minutes * 60
    pairs = correlate(rtt_rows, util_rows, bucket_seconds, rtt_offset=offset)
    ratio = overlap_ratio(rtt_rows, util_rows, pairs)
    if not pairs or ratio < _MIN_OVERLAP:
        logger.error(
            "%s: only %d paired buckets (%.0f%% overlap) from %d latency and %d "
            "utilisation rows. The two series are not describing the same window — "
            "refusing to grade rather than reporting a confidently wrong number.",
            hostname, len(pairs), ratio * 100, len(rtt_rows), len(util_rows),
        )
        return 1

    result = latency_under_load(pairs, args.idle_below, args.busy_above)
    result["_idle_below"], result["_busy_above"] = args.idle_below, args.busy_above
    share = busy_share(pairs, args.busy_above)
    hours = hour_profile(pairs, args.tz_offset)

    sla_ops: list[dict] = []
    live: dict | None = None
    if args.live:
        if not ip:
            logger.error("%s: no management IP — cannot run the live test", hostname)
            return 1
        device_type = guess_device_type(device.get("platformId", ""))
        logger.info("%s: connecting via SSH for the live test...", hostname)
        try:
            with ssh_session(ip, args.username, args.password, device_type, args.timeout) as run:
                # Both commands, merged: statistics carries RTT/jitter/loss/MOS
                # but usually omits the destination, and summary carries the
                # destination the live test needs to borrow as its target.
                sla_out = run([
                    ("sla_stats", "show ip sla statistics"),
                    ("sla_summary", "show ip sla summary"),
                ], required=())
                sla_ops = merge_sla_ops(
                    parse_ip_sla_statistics(sla_out.get("sla_stats", "")),
                    parse_ip_sla_statistics(sla_out.get("sla_summary", "")),
                )
                target = args.ping_target or next(iter(sla_targets(sla_ops)), None)
                if not target:
                    logger.error("%s: no --ping-target given and no IP SLA operation to "
                                 "borrow a destination from — skipping the live test", hostname)
                else:
                    _validate_name(target, "ping target")
                    live = run_live_test(run, wan_if, target, args.ping_count,
                                         args.ping_size, args.ping_rounds, args.timeout)
        except Exception as e:
            logger.error("%s: live test failed — %s: %s", hostname, type(e).__name__,
                         str(e)[:200])

    circuit = None
    try:
        circuit = float(iface.get("InterfaceSpeed")) if iface.get("InterfaceSpeed") else None
    except (TypeError, ValueError):
        pass

    site_label = f"{node.get('Site') or args.site or hostname} / {hostname}"
    render(site_label, node, wan_if, method, args.days, pairs, result, share,
           offset, hours, sla_ops, live, circuit, args.tz_offset, notes)

    if args.json:
        Path(args.json).write_text(json.dumps({
            "hostname": hostname,
            "site": node.get("Site"),
            "interface": wan_if,
            "days": args.days,
            "bucket_minutes": args.bucket_minutes,
            "offset_applied_s": offset.total_seconds() if offset else 0,
            "paired_buckets": len(pairs),
            "latency_under_load": {k: v for k, v in result.items() if not k.startswith("_")},
            "busy_share_pct": share,
            "hour_profile": hours,
            "ip_sla": sla_ops,
            "live": live,
        }, indent=2, default=str))
        logger.info("%s: wrote %s", hostname, args.json)
    return 0


# ─────────────────────────── main ──────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Objective user-experience scorecard for a site: latency under load, "
                    "graded, from data SolarWinds already collects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("site", nargs="?", help="Site name (DNAC site hierarchy, substring match)")
    ap.add_argument("--device", help="Skip site/role lookup; target this device directly")
    ap.add_argument("--role", default=DEFAULT_ROLE, help=f"DNAC role (default: {DEFAULT_ROLE!r})")
    ap.add_argument("--interface", help="Skip WAN-interface auto-detection")
    ap.add_argument("--tag-name", default=DEFAULT_TAG_NAME, help="DNAC tag marking a WAN interface")
    ap.add_argument("--vrf", default=",".join(DEFAULT_VRFS), help="WAN-detection VRF fallback")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS,
                    help=f"History window in days (default: {DEFAULT_DAYS})")
    ap.add_argument("--bucket-minutes", type=int, default=DEFAULT_BUCKET_MINUTES,
                    help=f"Correlation bucket size (default: {DEFAULT_BUCKET_MINUTES})")
    ap.add_argument("--idle-below", type=float, default=DEFAULT_IDLE_BELOW,
                    help=f"Utilisation %% below which the link counts as idle "
                         f"(default: {DEFAULT_IDLE_BELOW})")
    ap.add_argument("--busy-above", type=float, default=DEFAULT_BUSY_ABOVE,
                    help=f"Utilisation %% at or above which it counts as busy "
                         f"(default: {DEFAULT_BUSY_ABOVE})")
    ap.add_argument("--tz-offset", type=float, default=0.0,
                    help="Site local time offset from UTC, for the hour-of-day profile")
    ap.add_argument("--live", action="store_true",
                    help="Also run the paired-DSCP ping test from the router (needs SSH, "
                         "generates a small amount of ICMP)")
    ap.add_argument("--ping-target", help="Destination for the live test (default: borrow "
                                          "the destination of a configured IP SLA operation)")
    ap.add_argument("--ping-count", type=int, default=DEFAULT_PING_COUNT,
                    help=f"Pings per class per round (default: {DEFAULT_PING_COUNT})")
    ap.add_argument("--ping-size", type=int, default=DEFAULT_PING_SIZE,
                    help=f"Ping payload bytes (default: {DEFAULT_PING_SIZE})")
    ap.add_argument("--ping-rounds", type=int, default=DEFAULT_PING_ROUNDS,
                    help=f"Rounds of the paired test (default: {DEFAULT_PING_ROUNDS})")
    ap.add_argument("--json", help="Write the full structured result here")
    ap.add_argument("--username", default=os.getenv("DOMAIN_USERNAME", ""),
                    help="SSH username (default: DOMAIN_USERNAME from .env)")
    ap.add_argument("--password", default=os.getenv("DOMAIN_PASSWORD", ""),
                    help="SSH password (default: DOMAIN_PASSWORD from .env)")
    ap.add_argument("--timeout", type=int, default=SSH_TIMEOUT, help="SSH timeout in seconds")
    ap.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S",
    )
    if not args.verbose:
        for name in ("clients.dnac", "netmiko", "paramiko", "utils.device_ssh"):
            logging.getLogger(name).setLevel(logging.WARNING)

    if not args.site and not args.device:
        ap.error("either SITE or --device is required")
    if args.days < 1:
        ap.error("--days must be at least 1")
    if not (0 <= args.idle_below < args.busy_above <= 100):
        ap.error("--idle-below must be below --busy-above, both within 0-100")
    if args.live and (not args.username or not args.password):
        logger.error("--live needs SSH credentials — set DOMAIN_USERNAME/DOMAIN_PASSWORD "
                     "in .env or pass --username/--password")
        return 1

    dnac = dc.get_client()
    logger.info("Querying DNAC for device inventory...")
    devices = dc.get_all_devices(dnac, strict=True)

    if args.device:
        targets = find_devices_by_name(devices, args.device)
        if not targets:
            logger.error("No device matching '%s' in DNAC inventory", args.device)
            return 1
    else:
        site_cache = dc.get_site_cache(dnac)
        site_id, site_name = find_best_site_match_prefer_shallow(site_cache, args.site)
        if not site_id:
            logger.error("No site matching '%s'", args.site)
            return 1
        logger.info("Site '%s' resolved to: %s", args.site, site_name)
        branch_ids = site_and_descendant_ids(site_cache, site_name)
        site_device_ids: set[str] = set()
        for sid in branch_ids:
            site_device_ids |= get_site_device_ids(dnac, sid)
        targets = find_border_routers(devices, site_device_ids, args.role)
        if not targets:
            logger.error("No device with role matching '%s' at site '%s'", args.role, site_name)
            return 1

    logger.info("Target device(s): %s",
                ", ".join(d.get("hostname") or d.get("id") for d in targets))
    failures = sum(report_device(dnac, d, args) for d in targets)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
