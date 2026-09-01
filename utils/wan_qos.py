"""utils/wan_qos.py — IOS-XE `show policy-map interface` parsing and the
queue-latency math built on top of it.

The parser half was lifted verbatim out of scripts/wan_qos_report.py when
scripts/wan_queue_latency.py needed the same output shape. Nothing here
touches DNAC, Netmiko or the network: it is text -> dict plus arithmetic,
which is what makes it testable (tests/test_wan_qos.py) without a device.

── Why the latency half exists ──────────────────────────────────────────────

The queue report answers "are we dropping packets". On this fleet the answer
became "no" once queue-limit was raised to 4096 packets, and users kept
complaining anyway. That is not a contradiction, it is the trade: a deep
queue converts loss into delay. At a 42.5 Mbps shaper, 4096 packets of
1500 bytes is 1.16 s of buffering on the interface as a whole, and far more
inside a class whose guaranteed share is a fraction of that rate. Nothing in
the drop counters says so.

So the functions below convert a queue depth in *packets* into a delay in
*milliseconds*, which is the unit a user experiences:

    delay_ms = depth_packets x avg_packet_bytes x 8 / drain_bps x 1000

Two things make that a measurement rather than a model:

  * `avg_packet_bytes` comes from the class's own (pkts output/bytes output)
    counters, not an assumed MTU. A class carrying bare TCP ACKs and one
    carrying 1500-byte bulk transfers have wildly different packet sizes,
    and assuming 1500 everywhere overstates the first by 20x.
  * `drain_bps` prefers the *observed* rate — the delta of bytes_output
    between two samples over the real elapsed time — falling back to the
    configured guarantee only when the class moved too little traffic for
    that to mean anything. See `observed_drain_bps` / `guaranteed_bps`.

── The two drain rates are not interchangeable ──────────────────────────────

`guaranteed_bps` is what CBWFQ promises a class under full congestion.
`bandwidth remaining N%` is a floor, not a cap: an idle neighbour class
gives its share away, so a class routinely drains faster than its guarantee.
Both numbers are worth reporting and they answer different questions —
"how bad can this get" versus "how bad is it right now" — so callers should
label which one produced a given figure rather than reconciling them.
"""
from __future__ import annotations

import math
import re

# ─────────────────────────── policy-map parsing ────────────────────────────

_RE_CLASS = re.compile(r"^Class-map:\s*(\S.+?)\s*\(match-(any|all)\)\s*$", re.IGNORECASE)
_RE_COUNTS = re.compile(r"^([\d,]+)\s+packets,\s+([\d,]+)\s+bytes\s*$", re.IGNORECASE)
_RE_RATE = re.compile(r"^30 second offered rate\s+(\d+)\s*bps,\s*drop rate\s+(\d+)\s*bps\s*$", re.IGNORECASE)
_RE_MATCH = re.compile(r"^Match:\s*(.+)$", re.IGNORECASE)
# IOS-XE expresses a queue limit in packets, bytes or microseconds depending
# on platform and how it was configured. Capturing the unit keeps the ms math
# from reading "queue limit 5000 us" as five thousand packets — which would
# turn a 5 ms queue into a multi-second one and invert the finding.
_RE_QUEUE_LIMIT = re.compile(r"^queue\s+limit\s+(\d+)\s+(packets|bytes|us|ms)\s*$", re.IGNORECASE)
_RE_QUEUE_STATS = re.compile(
    r"^\(queue depth/total drops/no-buffer drops\)\s+(\d+)/(\d+)/(\d+)\s*$", re.IGNORECASE
)
_RE_PKTS_OUT = re.compile(r"^\((?:pkts|pts) output/bytes output\)\s+(\d+)/(\d+)\s*$", re.IGNORECASE)
_RE_BW_REMAIN = re.compile(r"^bandwidth remaining\s+(\d+)\s*%\s*$", re.IGNORECASE)
_RE_BW_FLAT = re.compile(r"^bandwidth\s+(\d+)\s*kbps\s*$", re.IGNORECASE)
_RE_PRIORITY = re.compile(
    r"^Priority:\s*(?:(?P<pct>\d+)%\s*)?\(\s*(?P<kbps>\d+)\s*kbps\s*\)\s*,\s*"
    r"burst bytes\s+(?P<burst>\d+)\s*,\s*b/?w exceed drops:?\s*(?P<exceed>\d+)?",
    re.IGNORECASE,
)
_RE_SHAPE = re.compile(r"^shape\s*\(average\)\s*cir\s+(?P<cir>\d+)", re.IGNORECASE)
_RE_TARGET_SHAPE = re.compile(r"^target shape rate\s+(\d+)\s*$", re.IGNORECASE)
# IOS-XE prints these hyphenated ("Service-policy output: NAME"). The
# original patterns required a space and so never matched on real output —
# which is why the report's "Policy (parent):" line silently never appeared.
# Accept either spelling rather than swapping one guess for another.
_RE_SVC_OUTPUT = re.compile(r"^Service[- ]policy output:\s*(\S*)\s*$", re.IGNORECASE)
_RE_SVC_NESTED = re.compile(r"^Service[- ]policy\s*:\s*(\S+)\s*$", re.IGNORECASE)
_RE_PRIORITY_AGG = re.compile(r"^queue stats for all priority classes:\s*$", re.IGNORECASE)

# Active queue management, read off the class's own config lines. Their
# absence is a finding in its own right: tail-dropping a 4096-packet queue
# is what produces a full buffer punctuated by burst loss, where WRED would
# have signalled TCP to back off while the queue was still shallow.
_RE_RANDOM_DETECT = re.compile(r"^\s*(?:Exp-weight-constant|mean queue depth|packet output)", re.IGNORECASE)
_RE_FAIR_QUEUE = re.compile(r"^\s*Fair-queue:", re.IGNORECASE)


def _new_class(name: str, match_type: str, indent: int) -> dict:
    return {
        "name": name, "match_type": match_type, "indent": indent,
        "packets": None, "bytes": None,
        "offered_bps": None, "drop_bps": None,
        "matches": [],
        "queue_limit": None, "queue_limit_unit": None,
        "queue_depth": None, "total_drops": None, "no_buffer_drops": None,
        "pkts_output": None, "bytes_output": None,
        "bandwidth_remaining_pct": None, "bandwidth_kbps": None,
        "priority_pct": None, "priority_kbps": None, "priority_burst_bytes": None, "bw_exceed_drops": None,
        "shape_cir_bps": None, "target_shape_bps": None,
        "shared_priority_queue": False,
        "has_random_detect": False, "has_fair_queue": False,
    }


def parse_policy_map(text: str) -> dict:
    """Parse `show policy-map interface ... output` into interface name,
    parent/nested policy names, and a list of per-class-map queue dicts.
    Tolerant by design: unrecognized lines are ignored rather than raising,
    since policy-map shapes vary (WRED, marking actions, single-level
    policies, ...) — anything not captured here is still visible in the
    raw CLI output the caller keeps alongside this."""
    lines = [l for l in text.splitlines() if l.strip()]

    interface_name = None
    top_policy_name = None
    nested_policy_name = None
    classes: list[dict] = []
    current: dict | None = None
    pending_priority: dict | None = None
    capturing_priority_agg = False

    for raw in lines:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())

        if interface_name is None and not stripped.lower().startswith(
                ("service policy", "service-policy", "class-map")):
            interface_name = stripped
            continue

        m = _RE_SVC_OUTPUT.match(stripped)
        if m:
            top_policy_name = m.group(1) or top_policy_name
            continue
        m = _RE_SVC_NESTED.match(stripped)
        if m:
            nested_policy_name = m.group(1)
            continue

        if _RE_PRIORITY_AGG.match(stripped):
            capturing_priority_agg = True
            pending_priority = {
                "queue_limit": None, "queue_limit_unit": None,
                "queue_depth": None, "total_drops": None,
                "no_buffer_drops": None, "pkts_output": None, "bytes_output": None,
            }
            continue

        m = _RE_CLASS.match(stripped)
        if m:
            if current is not None:
                classes.append(current)
            current = _new_class(m.group(1), m.group(2), indent)
            capturing_priority_agg = False
            continue

        if capturing_priority_agg and pending_priority is not None:
            m = _RE_QUEUE_LIMIT.match(stripped)
            if m:
                pending_priority["queue_limit"] = int(m.group(1))
                pending_priority["queue_limit_unit"] = m.group(2).lower()
                continue
            m = _RE_QUEUE_STATS.match(stripped)
            if m:
                pending_priority["queue_depth"] = int(m.group(1))
                pending_priority["total_drops"] = int(m.group(2))
                pending_priority["no_buffer_drops"] = int(m.group(3))
                continue
            m = _RE_PKTS_OUT.match(stripped)
            if m:
                pending_priority["pkts_output"] = int(m.group(1))
                pending_priority["bytes_output"] = int(m.group(2))
                continue
            if stripped.lower() == "queueing":
                continue

        if current is None:
            continue

        m = _RE_COUNTS.match(stripped)
        if m:
            current["packets"] = int(m.group(1).replace(",", ""))
            current["bytes"] = int(m.group(2).replace(",", ""))
            continue
        m = _RE_RATE.match(stripped)
        if m:
            current["offered_bps"] = int(m.group(1))
            current["drop_bps"] = int(m.group(2))
            continue
        m = _RE_MATCH.match(stripped)
        if m:
            current["matches"].append(m.group(1).strip())
            continue
        m = _RE_QUEUE_LIMIT.match(stripped)
        if m:
            current["queue_limit"] = int(m.group(1))
            current["queue_limit_unit"] = m.group(2).lower()
            continue
        m = _RE_QUEUE_STATS.match(stripped)
        if m:
            current["queue_depth"] = int(m.group(1))
            current["total_drops"] = int(m.group(2))
            current["no_buffer_drops"] = int(m.group(3))
            continue
        m = _RE_PKTS_OUT.match(stripped)
        if m:
            current["pkts_output"] = int(m.group(1))
            current["bytes_output"] = int(m.group(2))
            continue
        m = _RE_BW_REMAIN.match(stripped)
        if m:
            current["bandwidth_remaining_pct"] = int(m.group(1)); continue
        m = _RE_BW_FLAT.match(stripped)
        if m:
            current["bandwidth_kbps"] = int(m.group(1)); continue
        m = _RE_PRIORITY.match(stripped)
        if m:
            current["priority_pct"] = int(m.group("pct")) if m.group("pct") else None
            current["priority_kbps"] = int(m.group("kbps")) if m.group("kbps") else None
            current["priority_burst_bytes"] = int(m.group("burst")) if m.group("burst") else None
            current["bw_exceed_drops"] = int(m.group("exceed")) if m.group("exceed") else None
            continue
        m = _RE_SHAPE.match(stripped)
        if m:
            current["shape_cir_bps"] = int(m.group("cir")); continue
        m = _RE_TARGET_SHAPE.match(stripped)
        if m:
            current["target_shape_bps"] = int(m.group(1)); continue
        if _RE_FAIR_QUEUE.match(stripped):
            current["has_fair_queue"] = True
            continue
        if _RE_RANDOM_DETECT.match(stripped):
            current["has_random_detect"] = True
            continue
        # Anything else (bare "Queueing", "QoS Set", "Marker statistics: ...",
        # nested marking-action lines) is intentionally not modeled.

    if current is not None:
        classes.append(current)

    # Priority classes share one physical LLQ system queue on IOS-XE and
    # don't print their own per-class queue line — attach the aggregate
    # block to every class that has priority config but no queue line of
    # its own.
    if pending_priority is not None:
        for c in classes:
            has_priority = c["priority_pct"] is not None or c["priority_kbps"] is not None
            if has_priority and c["queue_depth"] is None:
                c["queue_limit"] = pending_priority["queue_limit"]
                c["queue_limit_unit"] = pending_priority["queue_limit_unit"]
                c["queue_depth"] = pending_priority["queue_depth"]
                c["total_drops"] = pending_priority["total_drops"]
                c["no_buffer_drops"] = pending_priority["no_buffer_drops"]
                c["pkts_output"] = pending_priority["pkts_output"]
                c["bytes_output"] = pending_priority["bytes_output"]
                c["shared_priority_queue"] = True

    uniq_indents = sorted({c["indent"] for c in classes})
    depth_map = {ind: i for i, ind in enumerate(uniq_indents)}
    for c in classes:
        c["depth"] = depth_map[c["indent"]]

    return {
        "interface": interface_name,
        "top_policy_name": top_policy_name,
        "nested_policy_name": nested_policy_name,
        "classes": classes,
    }


def compute_stats(parsed: dict) -> dict:
    """Derived per-queue stats: drop % of the queue's own traffic, each
    queue's share of total interface drops/traffic, instantaneous 30s drop
    %, and queue fill %. Percentages are denominated against the depth-0
    (outermost) class(es) so a hierarchical policy's parent-level rollup
    counters aren't double-counted against its own child queues."""
    classes = parsed["classes"]
    parent = [c for c in classes if c["depth"] == 0]

    total_traffic_pkts = sum(c["packets"] or 0 for c in parent) or None
    total_drops = sum(c["total_drops"] or 0 for c in parent) or None
    if total_drops is None:
        total_drops = sum(c["total_drops"] or 0 for c in classes) or None

    enriched = []
    for c in classes:
        pkts = c["packets"] or 0
        drops = c["total_drops"] or 0
        out_pkts = c["pkts_output"] or 0
        denom_q = drops + out_pkts
        offered = c["offered_bps"] or 0
        dropped_rate = c["drop_bps"] or 0

        enriched.append({
            **c,
            "drop_pct_of_queue": (drops / denom_q * 100) if denom_q else 0.0,
            "pct_of_total_traffic": (pkts / total_traffic_pkts * 100) if total_traffic_pkts else None,
            "share_of_total_drops": (drops / total_drops * 100) if total_drops else 0.0,
            "instant_drop_pct": (dropped_rate / offered * 100) if offered else 0.0,
            "queue_fill_pct": (c["queue_depth"] / c["queue_limit"] * 100) if c["queue_limit"] else None,
        })

    return {"classes": enriched, "total_traffic_pkts": total_traffic_pkts, "total_drops": total_drops}


# ────────────────── `show interfaces` counters (burst profile) ─────────────

# Raw byte counters, not the "5 minute output rate" line. That line is an
# exponentially-decayed average over the interface's load-interval — 300 s by
# default — which is precisely the averaging that hides the problem: a link
# that sits at 100% of its shaper for twenty seconds at a time reads as
# comfortably under 50% there. Differencing the cumulative counters over the
# real elapsed time between two samples gives a true interval average at
# whatever resolution we poll at.
_RE_IF_PKTS_IN = re.compile(r"^(\d+)\s+packets input,\s+(\d+)\s+bytes", re.IGNORECASE)
_RE_IF_PKTS_OUT = re.compile(r"^(\d+)\s+packets output,\s+(\d+)\s+bytes", re.IGNORECASE)
_RE_IF_TOTAL_DROPS = re.compile(r"Total output drops:\s*(\d+)", re.IGNORECASE)
_RE_IF_LOAD_INTERVAL = re.compile(r"^load-interval\s+(\d+)\s*$", re.IGNORECASE)
_RE_IF_QOS_PRECLASSIFY = re.compile(r"^qos\s+pre-classify\s*$", re.IGNORECASE)
_RE_IF_NAME = re.compile(r"^interface\s+(\S+)\s*$", re.IGNORECASE)


def parse_interface_counters(text: str) -> dict:
    """Pull the cumulative packet/byte counters out of `show interfaces X`.

    Returns {"pkts_in", "bytes_in", "pkts_out", "bytes_out", "total_output_drops"},
    each None when the line wasn't present, so a caller can tell "zero" from
    "not collected".
    """
    out = {
        "pkts_in": None, "bytes_in": None,
        "pkts_out": None, "bytes_out": None,
        "total_output_drops": None,
    }
    for raw in text.splitlines():
        stripped = raw.strip()
        m = _RE_IF_PKTS_IN.match(stripped)
        if m:
            out["pkts_in"] = int(m.group(1))
            out["bytes_in"] = int(m.group(2))
            continue
        m = _RE_IF_PKTS_OUT.match(stripped)
        if m:
            out["pkts_out"] = int(m.group(1))
            out["bytes_out"] = int(m.group(2))
            continue
        m = _RE_IF_TOTAL_DROPS.search(stripped)
        if m:
            out["total_output_drops"] = int(m.group(1))
    return out


def parse_interface_config(text: str) -> dict:
    """Read the handful of facts the report needs out of an interface's
    running-config: its load-interval (the averaging window every rate the
    box reports — and everything SolarWinds polls — is smoothed over) and
    whether `qos pre-classify` is set.

    `qos pre-classify` matters on a WAN egress carrying tunnels: without it
    the policy classifies on the *outer* header, so inner DSCP markings are
    invisible and every tunnelled flow lands in whichever class matches the
    tunnel's own marking — usually one. That is a leading explanation for a
    policy where almost all traffic arrives in a single class.
    """
    interfaces: dict[str, dict] = {}
    current = None
    for raw in text.splitlines():
        stripped = raw.strip()
        m = _RE_IF_NAME.match(stripped)
        if m:
            current = {"name": m.group(1), "load_interval": None, "qos_pre_classify": False}
            interfaces[m.group(1)] = current
            continue
        if current is None:
            continue
        m = _RE_IF_LOAD_INTERVAL.match(stripped)
        if m:
            current["load_interval"] = int(m.group(1))
            continue
        if _RE_IF_QOS_PRECLASSIFY.match(stripped):
            current["qos_pre_classify"] = True
    return interfaces


# ─────────────────────────── shaper / drain rates ──────────────────────────

# Below this, a class moved so little traffic between two samples that its
# observed drain rate is noise — one stray packet over two seconds reads as
# 6 kbps and would turn a 3-packet queue into a fictitious 12-second delay.
# Fall back to the configured guarantee instead.
_MIN_OBSERVED_BPS = 1000.0

# An arithmetically-correct recommendation of `queue-limit 2` is not a config
# anyone should paste: it leaves no room for a normal TCP burst and trades
# the latency problem straight back for a loss one.
MIN_QUEUE_LIMIT_PACKETS = 8


def parent_shape_bps(parsed: dict) -> int | None:
    """The shaper CIR the child policy's percentages are taken against.

    Prefers the parent (depth-0) class's `shape (average) cir`, since that is
    the circuit rate this policy is actually shaped to. `target shape rate`
    is the same number as IOS resolves it and serves as the fallback for
    policies that print only that.
    """
    for c in sorted(parsed.get("classes") or [], key=lambda c: c.get("depth", 0)):
        if c.get("shape_cir_bps"):
            return c["shape_cir_bps"]
    for c in sorted(parsed.get("classes") or [], key=lambda c: c.get("depth", 0)):
        if c.get("target_shape_bps"):
            return c["target_shape_bps"]
    return None


def total_priority_bps(parsed: dict) -> int:
    """Sum of every priority class's reserved rate.

    `bandwidth remaining percent` is a share of what is left *after* the LLQ
    reservations are taken off the top, so this is the subtrahend in
    `guaranteed_bps`. Priority classes sharing one physical LLQ queue still
    each carry their own reservation, so they all count.
    """
    total = 0
    for c in parsed.get("classes") or []:
        if c.get("priority_kbps"):
            total += c["priority_kbps"] * 1000
    return total


def guaranteed_bps(cls: dict, shape_bps: int | None, priority_bps: int = 0) -> float | None:
    """The rate this class is guaranteed under full congestion, in bps.

    This is the conservative denominator for "how bad can this queue get":
    every other class busy, this one getting exactly its contracted share.
    Returns None when the policy gives no basis to compute one (no shaper
    and no explicit bandwidth), rather than guessing — a wrong drain rate
    produces a confidently wrong latency figure, which is worse than a gap.
    """
    if cls.get("priority_kbps"):
        return float(cls["priority_kbps"] * 1000)
    if cls.get("bandwidth_kbps"):
        return float(cls["bandwidth_kbps"] * 1000)
    if cls.get("bandwidth_remaining_pct") is not None and shape_bps:
        remaining = max(shape_bps - priority_bps, 0)
        return remaining * cls["bandwidth_remaining_pct"] / 100.0
    if cls.get("shape_cir_bps"):
        return float(cls["shape_cir_bps"])
    if shape_bps:
        return float(shape_bps)
    return None


def counter_delta(prev: int | None, cur: int | None) -> int | None:
    """Delta between two readings of a monotonic device counter.

    Returns None on a negative delta rather than the negative number. IOS
    counters reset on `clear counters`, a reload, or a 32-bit wrap, and any
    of those produce a nonsense negative that would otherwise propagate into
    a negative drain rate and a negative queue delay. Dropping the interval
    loses one sample; keeping it corrupts the whole window's statistics.
    """
    if prev is None or cur is None:
        return None
    delta = cur - prev
    return delta if delta >= 0 else None


def observed_drain_bps(prev: dict, cur: dict, elapsed_s: float) -> float | None:
    """Measured rate this class actually drained at, from its own
    (pkts output/bytes output) counters over the real elapsed time.

    This is what makes the reported latency a measurement rather than a
    model — it reflects the bandwidth the scheduler genuinely handed this
    class, including whatever it borrowed from idle neighbours.
    """
    if elapsed_s <= 0:
        return None
    delta = counter_delta(prev.get("bytes_output"), cur.get("bytes_output"))
    if delta is None:
        return None
    return delta * 8 / elapsed_s


def avg_packet_bytes(prev: dict, cur: dict) -> float | None:
    """Mean packet size this class moved between two samples.

    Windowed rather than since-boot: a class's traffic mix changes, and the
    figure that matters is the one for the packets currently sitting in the
    queue. Returns None when no packets moved.
    """
    d_bytes = counter_delta(prev.get("bytes_output"), cur.get("bytes_output"))
    d_pkts = counter_delta(prev.get("pkts_output"), cur.get("pkts_output"))
    if not d_bytes or not d_pkts:
        return None
    return d_bytes / d_pkts


def queue_delay_ms(depth_pkts: int | None, pkt_bytes: float | None,
                   drain_bps: float | None) -> float | None:
    """Milliseconds of delay implied by `depth_pkts` waiting at `drain_bps`.

    The headline conversion: this is the number a user experiences, where
    queue depth in packets is the number the CLI reports.
    """
    if depth_pkts is None or not pkt_bytes or not drain_bps or drain_bps <= 0:
        return None
    return depth_pkts * pkt_bytes * 8 / drain_bps * 1000.0


def queue_limit_packets(cls: dict, pkt_bytes: float | None,
                        drain_bps: float | None) -> float | None:
    """The class's configured queue limit expressed in packets.

    Normalises the `bytes` and `us`/`ms` forms so a caller can compare
    limits, and compute a full-queue delay, without branching on the unit
    everywhere. Returns None when the conversion needs a packet size or a
    drain rate that isn't available.
    """
    limit, unit = cls.get("queue_limit"), (cls.get("queue_limit_unit") or "packets")
    if limit is None:
        return None
    if unit == "packets":
        return float(limit)
    if unit == "bytes":
        return (limit / pkt_bytes) if pkt_bytes else None
    if unit in ("us", "ms"):
        # A time-based limit already *is* the answer to "how deep in ms"; go
        # back to packets so the same downstream math applies to every form.
        seconds = limit / 1_000_000.0 if unit == "us" else limit / 1000.0
        if not drain_bps or not pkt_bytes:
            return None
        return seconds * drain_bps / (pkt_bytes * 8)
    return None


def full_queue_delay_ms(cls: dict, pkt_bytes: float | None,
                        drain_bps: float | None) -> float | None:
    """Delay at the configured queue limit — the worst case this buffer
    permits. This is the number that turns "queue-limit 4096" into
    "2.75 seconds"."""
    limit_pkts = queue_limit_packets(cls, pkt_bytes, drain_bps)
    return queue_delay_ms(limit_pkts, pkt_bytes, drain_bps)


def recommend_queue_limit(target_ms: float, pkt_bytes: float | None,
                          drain_bps: float | None) -> int | None:
    """Queue limit in packets that caps this class's delay at `target_ms`.

    The inverse of `queue_delay_ms`, floored at MIN_QUEUE_LIMIT_PACKETS so
    the suggestion stays a usable config rather than a number that merely
    satisfies the equation.
    """
    if not pkt_bytes or not drain_bps or drain_bps <= 0 or target_ms <= 0:
        return None
    packets = (target_ms / 1000.0) * drain_bps / (pkt_bytes * 8)
    return max(MIN_QUEUE_LIMIT_PACKETS, int(packets))


def pick_drain_bps(observed: float | None, guaranteed: float | None) -> tuple[float | None, str]:
    """Choose between the measured and contracted drain rate, and say which.

    Returns (bps, source) where source is "measured" or "guaranteed". The
    caller is expected to surface that label: the two rates can differ by
    an order of magnitude on a class borrowing from idle neighbours, and a
    latency figure whose denominator is unstated is not interpretable.
    """
    if observed is not None and observed >= _MIN_OBSERVED_BPS:
        return observed, "measured"
    if guaranteed is not None:
        return guaranteed, "guaranteed"
    return None, "unknown"


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile over an already-collected sample list.

    Deliberately not interpolating: these are observations of a real queue,
    and a p95 that never occurred is harder to reason about than one that
    did. Also avoids a numpy dependency for the one place it'd be used.
    """
    clean = sorted(v for v in values if v is not None)
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    rank = max(1, min(len(clean), math.ceil(pct / 100.0 * len(clean))))
    return clean[rank - 1]
