#!/usr/bin/env python3
"""scripts/wan_queue_latency.py — WAN queue *latency* profiler for a site's
border router. The companion to scripts/wan_qos_report.py, for when that
report says "we're barely dropping anything" and users still say the site is
slow.

── Why this exists ──────────────────────────────────────────────────────────

Raising `queue-limit` makes drop counters go down. It does not make
congestion go away; it converts loss into delay. A queue holding 4096 packets
at a class's guaranteed share of a 42.5 Mbps shaper is *seconds* of buffered
delay, and every metric the fleet currently looks at is blind to it:

  * `Total drops: 0.03%` from wan_qos_report is cumulative since boot. Over
    a billion packets it cannot say anything about the twenty minutes a user
    complained about.
  * `Depth/Limit` there is one instantaneous reading. A single sample cannot
    distinguish a queue that spiked once from a queue that is never empty.
  * SolarWinds' utilisation chart averages over the interface's load-interval
    (300 s by default). Sustained bursts to 100% of the shaper are entirely
    consistent with a 45% line on that chart.

So this samples the same interface repeatedly and reports, per class:

  * **Standing queue** — the *minimum* depth observed across the window. This
    is the headline number and the one a single snapshot structurally cannot
    produce. A queue whose depth never reaches zero is never draining, which
    is bufferbloat: latency with no loss to show for it.
  * **Queue delay in milliseconds**, p50/p95/max — depth converted through
    the class's own measured packet size and measured drain rate. See
    utils/wan_qos.py for the arithmetic and why each input is measured
    rather than assumed.
  * **Windowed drop rate** — drops that happened *during the sample window*,
    as a share of that queue's traffic in the same window. Not since boot.
  * **Egress burst profile** — interval utilisation from the interface's raw
    byte counters, so peak-vs-average is visible instead of smoothed away.

It then flags findings, and prints a suggested `policy-map` block resizing
each queue-limit to a latency budget. **The suggested config is printed to
stdout and never sent.** This script has no config-mode code path: every
device interaction goes through utils.device_ssh.ssh_session, whose runner
only calls send_command.

── What it cannot tell you ──────────────────────────────────────────────────

Recorded because each of these would otherwise read as a bug:

  * Queue depth is an instantaneous sample. Polling every couple of seconds
    reliably catches a *standing* queue and will miss a purely transient one.
    The windowed drop deltas and the per-class 30-second offered/drop rate
    are what cover that gap — a queue that spikes between samples still shows
    up as drops.
  * `bandwidth remaining N%` is a floor, not a cap: a class drains faster
    when its neighbours are idle. "Full queue" is therefore worst-case-under-
    congestion while the p50/p95 columns use the measured rate. They are not
    meant to reconcile; each row says which denominator produced it.
  * Average packet size is a windowed mean. A class carrying both bare ACKs
    and 1500-byte bulk makes every ms figure a good estimate, not an exact
    one.
  * Issuing the command takes real time on a busy router, so the true
    interval is `max(--interval, execution time)`. Every delta uses the
    recorded timestamps, never the nominal interval.

── Read-only guarantee ──────────────────────────────────────────────────────

DNAC calls are GETs (inventory, site membership, interfaces, tag membership,
cached config). Device commands are all `show`, run via send_command. The
suggested-config block is text on stdout.

Auth:
  DNAC:   the app's shared service account (DOMAIN_USERNAME/DOMAIN_PASSWORD
          in .env — clients.dnac.get_client()).
  Device: the same shared account by default; override with --username/
          --password.

Usage:
    .venv/bin/python -m scripts.wan_queue_latency "DCA"
    .venv/bin/python -m scripts.wan_queue_latency "DCA" --duration 120 --interval 2
    .venv/bin/python -m scripts.wan_queue_latency --device RTR-DCA-01 --interface GigabitEthernet0/0/5
    .venv/bin/python -m scripts.wan_queue_latency "DCA" --target-ms "EF=15,default=80" --json /tmp/k.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.dnac as dc  # noqa: E402
from utils.device_ssh import guess_device_type, ssh_session  # noqa: E402
from utils.wan_qos import (  # noqa: E402
    MIN_QUEUE_LIMIT_PACKETS,
    coalesce_counter_spans,
    counter_delta,
    counter_resolution_s,
    full_queue_delay_ms,
    guaranteed_bps,
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
# Target resolution is imported wholesale rather than reimplemented: the
# site-matching in particular has a hard-won fix (prefer the shallowest
# hierarchy match, since this fleet floor-assigns only APs and a Floor-scoped
# search finds zero border routers) that must not exist in two versions.
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

logger = logging.getLogger("wan_queue_latency")

SSH_TIMEOUT = 30
DEFAULT_DURATION = 60
DEFAULT_INTERVAL = 2

# Latency budgets per class, in milliseconds. A priority queue exists to keep
# delay low, so a deep one defeats its own purpose — 20 ms is roughly the
# jitter budget a voice codec absorbs without help. The rest are sized so a
# TCP flow can still burst without the queue becoming a place packets live.
DEFAULT_TARGET_MS = "EF=20,CONTROL_SIGNAL=50,SCAVENGER=50,default=100"

# Classes that give traffic no meaningful treatment. class-default is that by
# definition; the rest are this fleet's naming for the same idea. Used only
# to compute the "unmanaged share" figure, and overridable, because guessing
# a class's intent from its name is exactly the kind of heuristic that should
# be visible and adjustable rather than buried.
_BEST_EFFORT_RE = re.compile(r"(^class-default$|^BE$|BEST.?EFFORT|SCAVENGER|^DEFAULT$)", re.IGNORECASE)

# Findings thresholds. Named rather than inlined so the report's claims can be
# argued with.
_STANDING_DEPTH_MIN = 2       # packets; below this a "never empty" claim is noise
_STANDING_DELAY_MIN_MS = 20   # ...and it has to cost something to be worth flagging
_LLQ_MAX_MS = 50              # a priority queue deeper than this defeats its purpose
_DEEP_QUEUE_MS = 200          # any class whose full queue exceeds this is oversized
_AQM_QUEUE_LIMIT = 512        # tail-dropping a queue this deep is worth calling out
_UNMANAGED_SHARE_PCT = 80.0   # above this, the policy isn't classifying anything
_BURST_PCT = 90.0             # a span at this share of the shaper is running full
_SATURATED_PCT = 85.0         # ...and a whole-window mean this high is a pegged circuit


# ─────────────────────────── sampling ──────────────────────────────────────

@dataclass
class Sample:
    """One poll of the device: monotonic clock for deltas, wall clock for
    display, plus the two parsed command outputs."""
    t: float
    wall: datetime
    parsed: dict
    iface: dict


@dataclass
class ClassProfile:
    """Per-class window statistics. Everything here is derived from at least
    two samples; a field is None when the window didn't contain enough
    movement to compute it honestly."""
    name: str
    depth: int
    display: str
    queue_limit: int | None
    queue_limit_unit: str | None
    is_priority: bool
    bw_config: str
    has_random_detect: bool
    has_fair_queue: bool
    depth_min: int | None = None
    depth_max: int | None = None
    delays_ms: list[float] = field(default_factory=list)
    pkt_bytes: float | None = None
    measured_bps: float | None = None
    guaranteed_bps: float | None = None
    drain_source: str = "unknown"
    window_pkts: int = 0
    window_drops: int = 0
    window_seconds: float = 0.0
    share_pct: float | None = None

    @property
    def standing_depth(self) -> int | None:
        return self.depth_min

    @property
    def p50_ms(self) -> float | None:
        return percentile(self.delays_ms, 50)

    @property
    def p95_ms(self) -> float | None:
        return percentile(self.delays_ms, 95)

    @property
    def max_ms(self) -> float | None:
        return max(self.delays_ms) if self.delays_ms else None

    @property
    def drops_per_sec(self) -> float | None:
        return (self.window_drops / self.window_seconds) if self.window_seconds > 0 else None

    @property
    def window_drop_pct(self) -> float | None:
        denom = self.window_pkts + self.window_drops
        return (self.window_drops / denom * 100) if denom else None

    @property
    def full_queue_ms(self) -> float | None:
        cls = {"queue_limit": self.queue_limit, "queue_limit_unit": self.queue_limit_unit}
        return full_queue_delay_ms(cls, self.pkt_bytes, self.guaranteed_bps)


def _class_key(c: dict) -> tuple[int, str]:
    """class-default appears at both the parent and child level of a
    hierarchical policy, so the name alone is not a key."""
    return (c.get("depth", 0), c["name"])


def collect_samples(run, wan_if: str, duration: int, interval: int) -> list[Sample]:
    """Poll the policy-map and interface counters until `duration` elapses.

    Sleeps to the next nominal tick rather than for a fixed interval, so a
    slow command doesn't compound into ever-later samples; if a command
    already overran the tick, the next poll starts immediately and the real
    elapsed time is what the deltas use.
    """
    commands = [
        ("policy", f"show policy-map interface {wan_if} output"),
        ("iface", f"show interfaces {wan_if}"),
    ]
    samples: list[Sample] = []
    start = time.monotonic()
    n = 0
    while True:
        out = run(commands, required=("policy", "iface"))
        samples.append(Sample(
            t=time.monotonic(),
            wall=datetime.now(timezone.utc),
            parsed=parse_policy_map(out.get("policy", "")),
            iface=parse_interface_counters(out.get("iface", "")),
        ))
        n += 1
        elapsed = time.monotonic() - start
        if elapsed >= duration:
            break
        if n % 5 == 0:
            logger.info("  ...%d samples, %.0fs of %ds", n, elapsed, duration)
        next_tick = start + n * interval
        remaining = next_tick - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    return samples


# ─────────────────────────── analysis ──────────────────────────────────────

def profile_classes(samples: list[Sample], target_ms: dict[str, float]) -> list[ClassProfile]:
    """Fold the sample series into one ClassProfile per class."""
    last = samples[-1].parsed
    shape_bps = parent_shape_bps(last)
    prio_bps = total_priority_bps(last)

    # Seed from the final sample so every class present at the end is
    # reported, including one that only started passing traffic mid-window.
    profiles: dict[tuple[int, str], ClassProfile] = {}
    for c in last["classes"]:
        profiles[_class_key(c)] = ClassProfile(
            name=c["name"],
            depth=c.get("depth", 0),
            display=_display_name(c),
            queue_limit=c.get("queue_limit"),
            queue_limit_unit=c.get("queue_limit_unit"),
            is_priority=c.get("priority_kbps") is not None or c.get("priority_pct") is not None,
            bw_config=_bw_config(c),
            has_random_detect=bool(c.get("has_random_detect")),
            has_fair_queue=bool(c.get("has_fair_queue")),
            guaranteed_bps=guaranteed_bps(c, shape_bps, prio_bps),
        )

    # Depth series spans every sample, including the first — the minimum is
    # the standing-queue figure and dropping a sample would only ever raise it.
    for s in samples:
        for c in s.parsed["classes"]:
            p = profiles.get(_class_key(c))
            if p is None or c.get("queue_depth") is None:
                continue
            d = c["queue_depth"]
            p.depth_min = d if p.depth_min is None else min(p.depth_min, d)
            p.depth_max = d if p.depth_max is None else max(p.depth_max, d)

    # Window totals, accumulated across consecutive pairs so a counter reset
    # mid-run costs one interval instead of corrupting the whole window.
    totals: dict[tuple[int, str], dict] = {k: {"bytes": 0, "pkts": 0, "drops": 0, "secs": 0.0}
                                           for k in profiles}
    for prev_s, cur_s in zip(samples, samples[1:]):
        elapsed = cur_s.t - prev_s.t
        if elapsed <= 0:
            continue
        prev_by_key = {_class_key(c): c for c in prev_s.parsed["classes"]}
        for c in cur_s.parsed["classes"]:
            key = _class_key(c)
            p, prev_c = profiles.get(key), prev_by_key.get(key)
            if p is None or prev_c is None:
                continue
            d_bytes = counter_delta(prev_c.get("bytes_output"), c.get("bytes_output"))
            d_pkts = counter_delta(prev_c.get("pkts_output"), c.get("pkts_output"))
            d_drops = counter_delta(prev_c.get("total_drops"), c.get("total_drops"))
            if d_bytes is None or d_pkts is None:
                continue
            t = totals[key]
            t["bytes"] += d_bytes
            t["pkts"] += d_pkts
            t["drops"] += d_drops or 0
            t["secs"] += elapsed

    for key, p in profiles.items():
        t = totals[key]
        p.window_pkts, p.window_drops, p.window_seconds = t["pkts"], t["drops"], t["secs"]
        p.pkt_bytes = (t["bytes"] / t["pkts"]) if t["pkts"] else None
        p.measured_bps = (t["bytes"] * 8 / t["secs"]) if t["secs"] > 0 else None
        _, p.drain_source = pick_drain_bps(p.measured_bps, p.guaranteed_bps)
        # A class that never built a queue was never rate-limited, so what it
        # moved is its offered load, not the rate it can drain at. Reporting
        # that as a "measured drain rate" reads as a capacity ceiling —
        # an EF class carrying 9 kbps of voice would look like it can only
        # ever drain 9 kbps. Fall back to the contracted rate and say so.
        if not p.depth_max:
            p.drain_source = "guaranteed" if p.guaranteed_bps else "unknown"

    # Delays are computed here, in a second pass, against each class's
    # *window-average* drain rate and packet size rather than per-interval
    # ones. The device publishes these counters on its own schedule, so a
    # single interval's apparent drain rate is an aliasing artifact (see
    # utils.wan_qos.coalesce_counter_spans) — and because drain rate is the
    # denominator, an inflated one *understates* the delay, which is the
    # error this tool can least afford to make. Window totals are immune:
    # summed deltas equal the true total no matter how they clustered.
    for s in samples:
        for c in s.parsed["classes"]:
            p = profiles.get(_class_key(c))
            if p is None or c.get("queue_depth") is None:
                continue
            drain, _ = pick_drain_bps(p.measured_bps, p.guaranteed_bps)
            ms = queue_delay_ms(c["queue_depth"], p.pkt_bytes, drain)
            if ms is not None:
                p.delays_ms.append(ms)

    # Share is denominated against the child (queueing) level, the same way
    # wan_qos_report denominates against depth 0 — whichever level actually
    # holds the per-class queues, so a parent rollup isn't double-counted.
    child_depth = max((p.depth for p in profiles.values()), default=0)
    denom = sum(p.window_pkts + p.window_drops
                for p in profiles.values() if p.depth == child_depth) or None
    for p in profiles.values():
        if denom and p.depth == child_depth:
            p.share_pct = (p.window_pkts + p.window_drops) / denom * 100

    return sorted(profiles.values(), key=lambda p: (p.depth, -(p.share_pct or 0)))


def burst_profile(samples: list[Sample], shape_bps: int | None) -> dict:
    """Egress rates from the raw interface byte counters.

    Rates are computed over *counter-change spans*, not adjacent poll pairs.
    The device publishes these counters on its own schedule; polling faster
    than that makes two of every three intervals read zero and the third read
    three intervals' worth of bytes over one interval of time — which reports
    a ~3x inflated "peak" that is purely a polling artifact. See
    utils.wan_qos.coalesce_counter_spans.

    `resolution_s` is how often the counters actually moved, and is reported
    so the peak figure is read at its true resolution rather than assumed to
    be a per-interval one.
    """
    readings = [(s.t, s.iface.get("bytes_out")) for s in samples]
    spans = coalesce_counter_spans(readings)
    if not spans:
        return {"samples": 0}

    rates = [d * 8 / secs for secs, d in spans if secs > 0]
    if not rates:
        return {"samples": 0}
    total_bytes = sum(d for _, d in spans)
    total_secs = sum(secs for secs, _ in spans)
    over = [r for r in rates if shape_bps and r >= shape_bps * _BURST_PCT / 100]
    return {
        "samples": len(rates),
        "polls": len(samples) - 1,
        "resolution_s": counter_resolution_s(spans),
        "peak_bps": max(rates),
        "p95_bps": percentile(rates, 95),
        # Mean from the totals, not the mean of the per-span rates: spans have
        # unequal lengths, so averaging their rates would weight a short span
        # the same as a long one.
        "mean_bps": (total_bytes * 8 / total_secs) if total_secs > 0 else None,
        "over_threshold": len(over),
        "shape_bps": shape_bps,
    }


def build_findings(profiles: list[ClassProfile], burst: dict, unmanaged_pct: float | None,
                   preclassify: dict, input_policy: bool) -> list[tuple[str, str]]:
    """Flagged conditions, each with the evidence inline. Ordered most- to
    least-likely to be the reason someone is complaining."""
    out: list[tuple[str, str]] = []

    for p in profiles:
        if (p.standing_depth is not None and p.standing_depth >= _STANDING_DEPTH_MIN
                and (p.p50_ms or 0) >= _STANDING_DELAY_MIN_MS):
            out.append((
                "BUFFERBLOAT",
                f"{p.display} never drained below {p.standing_depth} packets "
                f"(~{_fmt_delay(p.p50_ms)} at p50, {_fmt_delay(p.max_ms)} peak). A queue "
                f"that is never empty is pure added latency, not protection.",
            ))

    for p in profiles:
        if p.is_priority and (p.full_queue_ms or 0) > _LLQ_MAX_MS:
            out.append((
                "LLQ_TOO_DEEP",
                f"{p.display} is a priority queue with queue-limit {p.queue_limit} "
                f"= {_fmt_delay(p.full_queue_ms)} at {_fmt_bps(p.guaranteed_bps)}. "
                f"A low-latency queue that can buffer that long isn't one.",
            ))

    for p in profiles:
        if not p.is_priority and (p.full_queue_ms or 0) > _DEEP_QUEUE_MS:
            out.append((
                "DEEP_QUEUE",
                f"{p.display} queue-limit {p.queue_limit} = {_fmt_delay(p.full_queue_ms)} "
                f"of buffering at its guaranteed {_fmt_bps(p.guaranteed_bps)}.",
            ))

    for p in profiles:
        if (not p.is_priority and not p.has_random_detect
                and (p.queue_limit or 0) >= _AQM_QUEUE_LIMIT):
            out.append((
                "NO_AQM",
                f"{p.display} tail-drops a {p.queue_limit}-packet queue with no "
                f"random-detect — TCP only learns to slow down once the buffer is "
                f"already full, which is what produces a full queue plus burst loss.",
            ))

    if unmanaged_pct is not None and unmanaged_pct >= _UNMANAGED_SHARE_PCT:
        out.append((
            "DECORATIVE",
            f"{unmanaged_pct:.1f}% of traffic in this window landed in best-effort / "
            f"class-default queues. The policy has classes it is barely using, so "
            f"interactive traffic is queued behind bulk in the same class.",
        ))

    if not input_policy:
        out.append((
            "NO_INPUT_POLICY",
            "No input service-policy on this interface — nothing is re-marking or "
            "trusting DSCP on ingress, so the egress policy classifies whatever "
            "marking arrived.",
        ))

    tunnels = [n for n, cfg in preclassify.items() if n.lower().startswith("tunnel")]
    without = [n for n in tunnels if not preclassify[n]["qos_pre_classify"]]
    if tunnels and without:
        out.append((
            "NO_PRE_CLASSIFY",
            f"{len(without)} of {len(tunnels)} Tunnel interfaces lack `qos pre-classify`. "
            f"On a WAN egress carrying tunnels the policy then classifies on the outer "
            f"header only, which collapses every tunnelled flow into one class.",
        ))

    # Saturation is judged on the window mean, which is exact regardless of
    # how the counters clustered. The peak is only as trustworthy as the
    # counter refresh rate, so it is context here, never the claim.
    mean, shape = burst.get("mean_bps"), burst.get("shape_bps")
    if mean and shape:
        share = mean / shape * 100
        if share >= _SATURATED_PCT:
            out.append((
                "SATURATED",
                f"The circuit averaged {_fmt_bps(mean)} over the whole window — "
                f"{share:.0f}% of the {_fmt_bps(shape)} shaper. At that load the "
                f"queues are the only thing standing between users and loss, which "
                f"is why they are deep and why everything feels slow.",
            ))
        elif burst.get("over_threshold"):
            res = burst.get("resolution_s")
            out.append((
                "BURST",
                f"{burst['over_threshold']} of {burst['samples']} spans reached "
                f"{_BURST_PCT:.0f}%+ of the {_fmt_bps(shape)} shaper against a mean of "
                f"{_fmt_bps(mean)}"
                + (f" (measured over {res:.0f}s spans)" if res else "")
                + ". A 5-minute chart shows you the mean.",
            ))

    return out


# ─────────────────────────── formatting ────────────────────────────────────

def _display_name(c: dict) -> str:
    if c["name"].lower() == "class-default":
        return "class-default [parent]" if c.get("depth", 0) == 0 else "class-default [child default]"
    return c["name"]


def _bw_config(c: dict) -> str:
    if c.get("priority_pct") is not None or c.get("priority_kbps") is not None:
        pct = f"{c['priority_pct']}% " if c.get("priority_pct") is not None else ""
        return f"priority {pct}({c.get('priority_kbps')} kbps)"
    if c.get("bandwidth_remaining_pct") is not None:
        return f"bw remaining {c['bandwidth_remaining_pct']}%"
    if c.get("bandwidth_kbps") is not None:
        return f"bandwidth {c['bandwidth_kbps']} kbps"
    if c.get("shape_cir_bps") is not None:
        return f"shape cir {c['shape_cir_bps']:,} bps"
    return "(none)"


def _fmt_delay(ms) -> str:
    """Same unit-scaling rule as wan_qos_report._fmt_delay — these span five
    orders of magnitude in one table and "33043.4 ms" next to "4.2 ms" makes
    the outlier harder to spot, not easier."""
    if ms is None:
        return "n/a"
    if ms >= 10_000:
        return f"{ms / 1000:.0f} s"
    if ms >= 1_000:
        return f"{ms / 1000:.1f} s"
    return f"{ms:.0f} ms"


def _fmt_bps(bps) -> str:
    if not bps:
        return "n/a"
    if bps >= 1e6:
        return f"{bps / 1e6:.1f} Mbps"
    if bps >= 1e3:
        return f"{bps / 1e3:.0f} kbps"
    return f"{bps:.0f} bps"


def _fmt_int(n) -> str:
    return f"{n:,}" if n is not None else "n/a"


def _fmt_pct(n) -> str:
    return f"{n:.2f}%" if n is not None else "n/a"


def parse_target_ms(spec: str) -> dict[str, float]:
    """`EF=20,default=100` -> {"EF": 20.0, "default": 100.0}."""
    out: dict[str, float] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"bad --target-ms entry {part!r} (expected NAME=MS)")
        name, _, val = part.partition("=")
        out[name.strip()] = float(val)
    if "default" not in out:
        raise ValueError("--target-ms must include a 'default=' entry")
    return out


def target_for(name: str, target_ms: dict[str, float]) -> float:
    for key, val in target_ms.items():
        if key != "default" and key.lower() == name.lower():
            return val
    return target_ms["default"]


# ─────────────────────────── rendering ─────────────────────────────────────

def render(hostname: str, ip: str, wan_if: str, method: str, samples: list[Sample],
           profiles: list[ClassProfile], burst: dict, context: dict,
           target_ms: dict[str, float], suggest: bool) -> None:
    last = samples[-1].parsed
    shape_bps = parent_shape_bps(last)
    window = samples[-1].t - samples[0].t

    print("=" * 96)
    print(f"WAN Queue Latency Profile — {hostname} ({ip})")
    print("=" * 96)
    print(f"Interface:     {wan_if}  (detected via: {method})")
    if last.get("top_policy_name"):
        print(f"Policy:        {last['top_policy_name']}"
              + (f" -> {last['nested_policy_name']}" if last.get("nested_policy_name") else ""))
    print(f"Shaper:        {_fmt_bps(shape_bps)}" if shape_bps else "Shaper:        not found")
    print(f"Sampled:       {len(samples)} samples over {window:.1f}s "
          f"({samples[0].wall:%H:%M:%S} – {samples[-1].wall:%H:%M:%S} UTC)")
    li = context.get("load_interval")
    if li:
        print(f"load-interval: {li}s  (every rate this router reports, and everything "
              f"SolarWinds polls, is smoothed over this)")
    print()

    # ── burst profile ──
    res = burst.get("resolution_s")
    print("Egress profile (from raw byte counters):")
    if not burst.get("samples"):
        print("  n/a — interface counters unavailable")
    else:
        for label, key in (("Peak", "peak_bps"), ("p95", "p95_bps"), ("Mean", "mean_bps")):
            val = burst.get(key)
            share = f"  ({val / shape_bps * 100:.1f}% of shaper)" if shape_bps and val else ""
            print(f"  {label:<6}{_fmt_bps(val):>12}{share}")
        if shape_bps:
            print(f"  Spans at {_BURST_PCT:.0f}%+ of shaper: "
                  f"{burst['over_threshold']} of {burst['samples']}")
        if res:
            print(f"  Measured over {res:.0f}s spans — the router only refreshes these "
                  f"counters that often,")
            print(f"  so {res:.0f}s is the finest burst this can see, whatever "
                  f"--interval is set to.")
            if res > _args_interval_hint(samples) * 1.5:
                print(f"  (Polling faster than that gains nothing here; the Mean is "
                      f"unaffected either way.)")
    print()

    # ── queue latency ──
    print("Queue latency (depth converted to delay; Drain says which rate was used):")
    name_w = max(28, max((len(p.display) for p in profiles), default=0) + 2)
    print(f"  {'Queue':<{name_w}}{'Share':>8}{'Depth max':>11}{'Standing':>10}"
          f"{'p50':>9}{'p95':>9}{'Max':>9}{'Full queue':>12}  Drain")
    for p in profiles:
        drain = p.measured_bps if p.drain_source == "measured" else p.guaranteed_bps
        print(
            f"  {p.display:<{name_w}}"
            f"{_fmt_pct(p.share_pct) if p.share_pct is not None else '-':>8}"
            f"{_fmt_int(p.depth_max):>11}"
            f"{_fmt_int(p.standing_depth):>10}"
            f"{_fmt_delay(p.p50_ms):>9}"
            f"{_fmt_delay(p.p95_ms):>9}"
            f"{_fmt_delay(p.max_ms):>9}"
            f"{_fmt_delay(p.full_queue_ms):>12}  "
            f"{_fmt_bps(drain)} ({p.drain_source})"
        )
    print("  Standing = lowest depth seen all window. Non-zero means the queue never drained.")
    print("  Full queue = delay at the configured queue-limit, at the class's *guaranteed* rate.")
    print()

    # ── windowed drops ──
    print(f"Drops during this {window:.0f}s window (not since boot):")
    dropping = [p for p in profiles if p.window_drops]
    if not dropping:
        print("  None in any queue.")
    else:
        print(f"  {'Queue':<{name_w}}{'Drops':>10}{'Drops/s':>10}{'% of queue traffic':>21}")
        for p in sorted(dropping, key=lambda p: -p.window_drops):
            print(f"  {p.display:<{name_w}}{_fmt_int(p.window_drops):>10}"
                  f"{p.drops_per_sec or 0:>10.2f}{_fmt_pct(p.window_drop_pct):>21}")
    print()

    # ── classification ──
    collected = bool(context.get("collected"))
    print("Classification:")
    child_depth = max((p.depth for p in profiles), default=0)
    leaves = [p for p in profiles if p.depth == child_depth and p.share_pct is not None]
    unmanaged = sum(p.share_pct or 0 for p in leaves if _BEST_EFFORT_RE.search(p.name))
    managed = sum(p.share_pct or 0 for p in leaves if not _BEST_EFFORT_RE.search(p.name))
    # The class shares come from the policy-map itself, so they stand even
    # when the supporting commands were skipped.
    print(f"  Managed classes:                {managed:6.2f}% of windowed traffic")
    print(f"  Best-effort / class-default:    {unmanaged:6.2f}%")
    pc = context.get("preclassify") or {}
    if not collected:
        print("  (--no-classification: input policy, NBAR and qos pre-classify not checked)")
    else:
        print(f"  Input service-policy:           {'yes' if context.get('input_policy') else 'no'}")
        tunnels = [n for n in pc if n.lower().startswith("tunnel")]
        if tunnels:
            have = sum(1 for n in tunnels if pc[n]["qos_pre_classify"])
            print(f"  qos pre-classify on tunnels:    {have} of {len(tunnels)}")
        if context.get("nbar"):
            print("  NBAR protocol-discovery (top talkers):")
            for line in context["nbar"]:
                print(f"    {line}")
    print()

    # ── IP SLA ──
    # The one *independent* latency measurement available here: everything
    # else in this report is the router describing its own queues, which is
    # an inference about user experience. An IP SLA probe is a real
    # round-trip across the circuit. Only shown when probes are configured.
    if collected and context.get("ipsla"):
        print("IP SLA (independent round-trip measurement across this circuit):")
        for line in context["ipsla"].splitlines()[:12]:
            if line.strip():
                print(f"  {line.rstrip()}")
        print()

    # ── findings ──
    findings = build_findings(profiles, burst, unmanaged if leaves else None,
                              pc if collected else {},
                              # Unknown, not absent: suppresses NO_INPUT_POLICY
                              # rather than asserting one isn't there.
                              True if not collected else bool(context.get("input_policy")))
    print("Findings:")
    if not findings:
        print("  Nothing flagged. If users are still complaining, the congestion is not")
        print("  on this interface's egress queues — check the inbound direction (an")
        print("  egress policy cannot manage traffic that has already arrived) and")
        print("  whether the provider polices below the configured shaper rate.")
    for tag, text in findings:
        wrapped = _wrap(text, 78)
        print(f"  [{tag}]")
        for line in wrapped:
            print(f"      {line}")
    print()

    if suggest:
        render_suggestion(last, profiles, target_ms)


def _args_interval_hint(samples: list[Sample]) -> float:
    """Actual median poll interval, for comparing against the counter
    refresh rate. Taken from the samples rather than the --interval flag,
    since a slow command makes the real interval longer than requested."""
    gaps = [b.t - a.t for a, b in zip(samples, samples[1:])]
    return percentile(gaps, 50) or 1.0


def _wrap(text: str, width: int) -> list[str]:
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


# A class carrying this share of the link is one where intra-class fairness
# matters: a single bulk flow inside it can starve every interactive flow
# sharing the same queue.
_FAIR_QUEUE_SHARE_PCT = 20.0


def render_suggestion(last: dict, profiles: list[ClassProfile],
                      target_ms: dict[str, float]) -> None:
    """Print a candidate policy-map block. Never sent anywhere.

    Deliberately conservative about what it will suggest:

      * **Only reductions.** A class sitting under its latency budget needs
        no change; suggesting it be enlarged would be this tool arguing
        against its own purpose, and someone will paste this block verbatim.
      * **Only classes with evidence.** A class that moved no traffic in the
        window has shown nothing, so it gets no recommendation.
      * **AQM only where the queue is deep enough to matter**, matching the
        NO_AQM finding's own threshold rather than blanketing every class.
    """
    policy = last.get("nested_policy_name") or last.get("top_policy_name") or "<child-policy>"
    lines: list[str] = []
    comment_col = 34

    def entry(cfg: str, comment: str) -> str:
        return f"  {cfg:<{comment_col}}! {comment}"

    for p in profiles:
        # Parent shaper class has no per-class queue worth resizing, and a
        # class with no traffic this window has produced no evidence.
        if p.depth == 0 or (p.window_pkts == 0 and p.window_drops == 0):
            continue
        drain = p.guaranteed_bps
        target = target_for(p.name, target_ms)
        rec = recommend_queue_limit(target, p.pkt_bytes, drain)
        cur_pkts = queue_limit_packets(
            {"queue_limit": p.queue_limit, "queue_limit_unit": p.queue_limit_unit},
            p.pkt_bytes, drain,
        )
        body: list[str] = []

        # A 20% floor on the change: churning a config from 148 to 151
        # packets buys nothing and still costs a change window.
        if rec and cur_pkts and rec < cur_pkts * 0.8:
            body.append(entry(
                f"queue-limit {rec} packets",
                f"was {p.queue_limit} ({_fmt_delay(p.full_queue_ms)} -> "
                f"~{target:.0f} ms @ {_fmt_bps(drain)})",
            ))
        if (not p.is_priority and not p.has_random_detect
                and (p.queue_limit or 0) >= _AQM_QUEUE_LIMIT):
            body.append(entry("random-detect dscp-based",
                              "signal TCP before the queue is full"))
        if (not p.is_priority and not p.has_fair_queue
                and (p.share_pct or 0) >= _FAIR_QUEUE_SHARE_PCT):
            body.append(entry("fair-queue",
                              f"{p.share_pct:.0f}% of the link in one queue — stop "
                              f"one flow starving it"))
        if body:
            lines.append(f" class {p.name}")
            lines.extend(body)

    if not lines:
        return

    print("Suggested config — NOT applied, review before use:")
    print("-" * 96)
    print(f" policy-map {policy}")
    for line in lines:
        print(line)
    print("-" * 96)
    print("  Targets: " + ", ".join(f"{k}={v:.0f}ms" for k, v in target_ms.items())
          + f"  (--target-ms; floor {MIN_QUEUE_LIMIT_PACKETS} packets)")
    print("  Sizing uses each class's *guaranteed* rate, so these hold under full")
    print("  congestion — the case that matters. Verify on one site before the fleet:")
    print("  queue-limit, random-detect and fair-queue interact per platform, and a")
    print("  shorter queue trades some throughput on high-latency paths for the delay")
    print("  it removes.")
    print()


# ─────────────────────────── per-device flow ───────────────────────────────

CONTEXT_COMMANDS = [
    ("input_policy", "show policy-map interface {i} input"),
    ("nbar", "show ip nbar protocol-discovery interface {i} top-n 10"),
    ("if_config", "show running-config interface {i}"),
    ("tunnels", "show running-config | section ^interface Tunnel"),
    ("ipsla", "show ip sla summary"),
]


def gather_context(run, wan_if: str) -> dict:
    """One-shot supporting commands. Every one is best-effort: a router
    without NBAR, without IP SLA, or on an image that rejects a section
    filter should still produce the latency report, so a missing section is
    rendered as absent rather than aborting the run."""
    cmds = [(label, tpl.format(i=wan_if)) for label, tpl in CONTEXT_COMMANDS]
    out = run(cmds, required=())

    if_cfg = parse_interface_config(out.get("if_config", ""))
    this_if = next(iter(if_cfg.values()), {}) if if_cfg else {}

    nbar_lines: list[str] = []
    for line in (out.get("nbar") or "").splitlines():
        s = line.strip()
        if s and not s.startswith(("Last clearing", "Interface", "-")) and "Total" not in s:
            nbar_lines.append(s)
    return {
        # Distinguishes "we looked and there is none" from "we didn't look"
        # (--no-classification). Without it the report would assert an absent
        # input policy and flag it as a finding on the strength of a command
        # that was never run.
        "collected": True,
        "input_policy": bool((out.get("input_policy") or "").strip()
                             and "Class-map" in out.get("input_policy", "")),
        "nbar": nbar_lines[:12],
        "load_interval": this_if.get("load_interval"),
        "preclassify": parse_interface_config(out.get("tunnels", "")),
        "ipsla": (out.get("ipsla") or "").strip(),
        "raw": out,
    }


def profile_device(dnac, device: dict, args) -> int:
    hostname = device.get("hostname") or device.get("id")
    ip = device.get("managementIpAddress")
    if not ip:
        logger.error("%s: no management IP in DNAC inventory — skipped", hostname)
        return 1

    if args.interface:
        wan_if, method = args.interface, "manual override"
    else:
        target_vrfs = {v.strip().upper() for v in args.vrf.split(",") if v.strip()}
        wan_if, method = resolve_wan_interface(dnac, device, args.tag_name, target_vrfs)

    if not wan_if:
        logger.error("%s: could not determine a WAN interface (%s) — pass --interface", hostname, method)
        return 1
    if not _IFACE_NAME_RE.match(wan_if):
        logger.error("%s: resolved interface name '%s' failed validation — refusing to use it",
                     hostname, wan_if)
        return 1

    logger.info("%s (%s): WAN interface %s [%s]", hostname, ip, wan_if, method)

    device_type = guess_device_type(device.get("platformId", ""))
    logger.info("%s: connecting via SSH, sampling for %ds every %ds...",
                hostname, args.duration, args.interval)
    try:
        with ssh_session(ip, args.username, args.password, device_type, args.timeout) as run:
            context = {} if args.no_classification else gather_context(run, wan_if)
            samples = collect_samples(run, wan_if, args.duration, args.interval)
    except Exception as e:
        logger.error("%s: SSH failed — %s: %s", hostname, type(e).__name__, str(e)[:200])
        return 1

    if len(samples) < 2:
        logger.error("%s: only %d sample(s) collected — need at least 2 for any delta. "
                     "Raise --duration or lower --interval.", hostname, len(samples))
        return 1
    if not samples[-1].parsed["classes"]:
        logger.error("%s: no classes parsed from 'show policy-map interface %s output' — "
                     "no service-policy applied, or wrong interface name?", hostname, wan_if)
        return 1

    target_ms = parse_target_ms(args.target_ms)
    profiles = profile_classes(samples, target_ms)
    burst = burst_profile(samples, parent_shape_bps(samples[-1].parsed))

    render(hostname, ip, wan_if, method, samples, profiles, burst, context,
           target_ms, not args.no_suggest_config)

    if args.json:
        _write_json(args.json, hostname, ip, wan_if, samples, profiles, burst, context)
        logger.info("%s: wrote %s", hostname, args.json)

    if args.raw:
        print("Raw CLI output (last sample):")
        print("-" * 96)
        for label, text in (context.get("raw") or {}).items():
            print(f"### {label}\n{text}\n")
        print("-" * 96)
    return 0


def _write_json(path: str, hostname: str, ip: str, wan_if: str, samples: list[Sample],
                profiles: list[ClassProfile], burst: dict, context: dict) -> None:
    payload = {
        "hostname": hostname, "ip": ip, "interface": wan_if,
        "started": samples[0].wall.isoformat(),
        "ended": samples[-1].wall.isoformat(),
        "sample_count": len(samples),
        "burst": burst,
        "load_interval": context.get("load_interval"),
        "input_policy": context.get("input_policy"),
        "classes": [
            {
                "name": p.name, "depth": p.depth, "share_pct": p.share_pct,
                "queue_limit": p.queue_limit, "queue_limit_unit": p.queue_limit_unit,
                "is_priority": p.is_priority, "bw_config": p.bw_config,
                "depth_min": p.depth_min, "depth_max": p.depth_max,
                "p50_ms": p.p50_ms, "p95_ms": p.p95_ms, "max_ms": p.max_ms,
                "full_queue_ms": p.full_queue_ms,
                "pkt_bytes": p.pkt_bytes,
                "measured_bps": p.measured_bps, "guaranteed_bps": p.guaranteed_bps,
                "drain_source": p.drain_source,
                "window_pkts": p.window_pkts, "window_drops": p.window_drops,
                "window_drop_pct": p.window_drop_pct,
                "delays_ms": p.delays_ms,
            }
            for p in profiles
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2))


# ─────────────────────────── main ──────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Read-only WAN queue latency / bufferbloat profiler for a site's "
                    "border router(s). Samples over a window; reports delay, not just loss.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("site", nargs="?", help="Site name (DNAC site hierarchy, substring match)")
    ap.add_argument("--device", help="Skip site/role lookup; target this device directly "
                                     "(hostname or management-IP substring, matched fleet-wide)")
    ap.add_argument("--role", default=DEFAULT_ROLE,
                    help=f"DNAC device role to treat as the border router (substring match, "
                         f"case-insensitive; default: {DEFAULT_ROLE!r})")
    ap.add_argument("--interface", help="Skip WAN-interface auto-detection; use this interface directly")
    ap.add_argument("--tag-name", default=DEFAULT_TAG_NAME,
                    help=f"DNAC tag that marks a WAN interface (default: {DEFAULT_TAG_NAME})")
    ap.add_argument("--vrf", default=",".join(DEFAULT_VRFS),
                    help=f"Comma-separated VRF names used as the WAN-detection fallback "
                         f"(default: {','.join(DEFAULT_VRFS)})")
    ap.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                    help=f"Seconds to sample for (default: {DEFAULT_DURATION}). Longer windows "
                         f"make the standing-queue figure more trustworthy.")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                    help=f"Seconds between samples (default: {DEFAULT_INTERVAL})")
    ap.add_argument("--target-ms", default=DEFAULT_TARGET_MS,
                    help=f"Per-class latency budget used to size the suggested queue-limits, "
                         f"as NAME=MS pairs with a required 'default' (default: {DEFAULT_TARGET_MS!r})")
    ap.add_argument("--no-suggest-config", action="store_true",
                    help="Suppress the suggested policy-map block")
    ap.add_argument("--no-classification", action="store_true",
                    help="Skip the supporting commands behind the Classification section "
                         "(input policy, NBAR, tunnel qos pre-classify, IP SLA)")
    ap.add_argument("--json", help="Also write the full sample series and analysis to this path")
    ap.add_argument("--username", default=os.getenv("DOMAIN_USERNAME", ""),
                    help="SSH username (default: DOMAIN_USERNAME from .env)")
    ap.add_argument("--password", default=os.getenv("DOMAIN_PASSWORD", ""),
                    help="SSH password (default: DOMAIN_PASSWORD from .env)")
    ap.add_argument("--timeout", type=int, default=SSH_TIMEOUT,
                    help=f"SSH timeout in seconds (default: {SSH_TIMEOUT})")
    ap.add_argument("--raw", action="store_true", help="Also print the raw supporting CLI output")
    ap.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        # This script's own logger.info() calls are the progress output.
        # Quiet the libraries' routine internals specifically rather than
        # dropping INFO globally, so those steps still show.
        for name in ("clients.dnac", "netmiko", "paramiko", "utils.device_ssh"):
            logging.getLogger(name).setLevel(logging.WARNING)

    if not args.site and not args.device:
        ap.error("either SITE or --device is required")
    if args.interval < 1:
        ap.error("--interval must be at least 1 second")
    if args.duration < args.interval * 2:
        ap.error(f"--duration must be at least 2 intervals ({args.interval * 2}s) — "
                 f"every figure here is a delta between samples")
    if not args.username or not args.password:
        logger.error("No SSH credentials — set DOMAIN_USERNAME/DOMAIN_PASSWORD in .env "
                     "or pass --username/--password")
        return 1
    try:
        parse_target_ms(args.target_ms)
    except ValueError as e:
        ap.error(str(e))

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
            logger.error("No device with role matching '%s' found at site '%s'", args.role, site_name)
            return 1

    logger.info("Target device(s): %s", ", ".join(d.get("hostname") or d.get("id") for d in targets))

    failures = 0
    for device in targets:
        failures += profile_device(dnac, device, args)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
