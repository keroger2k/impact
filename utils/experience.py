"""utils/experience.py — turning "it seems slow" into a number.

Pure text->dict and arithmetic: no network, no DNAC, no Netmiko, same
posture as utils/wan_qos.py, so tests/test_experience.py runs without a
device or a SolarWinds instance.

── Why latency *under load*, and not latency ────────────────────────────────

A branch circuit's idle round-trip time is close to useless as a measure of
user experience. It is short, stable, and looks healthy on every dashboard
even at sites where users are complaining daily.

What a user actually feels is the round-trip time *while the circuit is
busy*, because that is when their packet waits behind a queue. On a WAN
egress with deep buffers the gap between those two numbers is enormous — a
site can sit at 32 ms idle and 490 ms loaded with no packet loss, no errors,
no alarms and nothing on a utilisation chart that looks wrong. That gap is
the whole of the user's complaint, and it is a single subtractable number:

    penalty = RTT(busy) - RTT(idle)

Everything in this module exists to compute that from two series the
monitoring system is already collecting, and to grade it against a published
scale so the result is defensible rather than invented.

── The grading scale ────────────────────────────────────────────────────────

`grade()` uses the bufferbloat scale popularised by Waveform's bufferbloat
test, which grades on *added* latency under load rather than absolute
latency. It is used here because it is public, widely cited, and calibrated
against subjective experience — arguments about the boundaries are arguments
with a published standard rather than with this report.

`rpm()` is the IETF ippm-responsiveness metric (Apple's "RPM"), which
expresses the same thing as round-trips achievable per minute under working
conditions. Reported alongside because it is the direction the industry is
standardising on, and because "123 round-trips per minute" lands with
non-network audiences in a way that "487 ms" does not.

── The correctness hazard: timestamp alignment ──────────────────────────────

The two source series come from different Orion entities with different
timestamp columns, and their storage timezones are not documented anywhere.
`Orion.NPM.InterfaceTraffic.DateTime` is filtered with `GETUTCDATE()` and is
UTC; `Orion.ResponseTime.ObservationTimestamp` is compared against bare
local-form date strings elsewhere in this codebase, so it may well be server
local time.

If those differ and nothing notices, every RTT is paired against the
utilisation from a different hour and the report produces a confident,
completely wrong answer — the worst possible failure for a tool whose entire
job is to replace a subjective impression with a number. `detect_series_offset`
exists to catch it; see its docstring.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from utils.time_buckets import bucket_start, parse_iso
from utils.wan_qos import percentile

# Waveform's published bufferbloat grades, in milliseconds of *added* latency
# under load. Ordered best-first; the first threshold a penalty falls under
# wins.
_GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (5, "A+"),
    (30, "A"),
    (60, "B"),
    (200, "C"),
    (400, "D"),
]
_WORST_GRADE = "F"

# Below this many buckets in a bin, a percentile is not a statistic. The
# report says "insufficient data" rather than printing a letter grade
# computed from four samples — a grade nobody can reproduce is worse than no
# grade, because it will be quoted.
MIN_BUCKETS_PER_BIN = 10


# ─────────────────────────── scoring ───────────────────────────────────────

def grade(penalty_ms: float | None) -> str | None:
    """Letter grade for added latency under load. None when unmeasurable."""
    if penalty_ms is None:
        return None
    # A negative penalty (busy faster than idle) is noise, not an A+ earned;
    # clamp so the grade reflects "no measurable penalty".
    penalty = max(0.0, penalty_ms)
    for threshold, letter in _GRADE_THRESHOLDS:
        if penalty < threshold:
            return letter
    return _WORST_GRADE


def rpm(latency_ms: float | None) -> float | None:
    """Round-trips per minute at this latency (IETF ippm-responsiveness).

    Higher is better; >1000 is a responsive link, <200 is one users describe
    as broken.
    """
    if not latency_ms or latency_ms <= 0:
        return None
    return 60_000.0 / latency_ms


# ─────────────────────────── correlation ───────────────────────────────────

def _series_max(rows: list[dict], key: str) -> datetime | None:
    stamps = [parse_iso(str(r.get(key))) for r in rows]
    real = [s for s in stamps if s is not None]
    return max(real) if real else None


def detect_series_offset(rtt_rows: list[dict], util_rows: list[dict],
                         rtt_key: str = "ObservationTimestamp",
                         util_key: str = "DateTime") -> timedelta | None:
    """Storage-timezone offset between the two series, or None if undetectable.

    Both queries ask for the same relative window ending "now", so their
    newest rows describe the same wall-clock instant. Any systematic gap
    between the two maxima is therefore the difference in how the two
    entities store time, not a real gap in the data.

    Rounded to the nearest hour: timezone offsets are whole (or half) hours,
    while the raw difference also contains polling jitter — the two entities
    are polled on unrelated schedules, so their newest rows are minutes apart
    even when perfectly aligned. Rounding separates the signal (hours) from
    that noise (minutes).

    Returned as the amount to ADD to RTT timestamps to bring them onto the
    utilisation series' clock.
    """
    rtt_max = _series_max(rtt_rows, rtt_key)
    util_max = _series_max(util_rows, util_key)
    if rtt_max is None or util_max is None:
        return None
    raw = (util_max - rtt_max).total_seconds()
    hours = round(raw / 3600.0)
    return timedelta(hours=hours)


def _as_utc(dt: datetime) -> datetime:
    """SWQL timestamps arrive with or without an offset depending on entity.
    A naive one is treated as UTC — the offset detection above is what
    actually reconciles the two series, so guessing a zone here would just
    apply the correction twice."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _to_float(value) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f


def correlate(rtt_rows: list[dict], util_rows: list[dict], bucket_seconds: int,
              rtt_offset: timedelta | None = None) -> list[dict]:
    """Pair response-time samples with the utilisation in the same bucket.

    Returns one dict per bucket that has *both* measurements:
    `{t, rtt_ms, max_rtt_ms, availability, util_pct}`. Buckets with only one
    side are dropped — a latency reading with no idea what the load was is
    exactly the ambiguity this whole report exists to remove.

    Multiple raw samples inside a bucket are averaged, except `max_rtt_ms`
    which takes the max (averaging peaks away would hide the tail that users
    actually notice).
    """
    offset = rtt_offset or timedelta(0)

    rtt_buckets: dict[datetime, dict] = {}
    for row in rtt_rows:
        stamp = parse_iso(str(row.get("ObservationTimestamp")))
        if stamp is None:
            continue
        key = bucket_start(_as_utc(stamp) + offset, bucket_seconds)
        slot = rtt_buckets.setdefault(key, {"avg": [], "max": [], "avail": []})
        for src, dst in (("AvgResponseTime", "avg"), ("MaxResponseTime", "max"),
                         ("Availability", "avail")):
            val = _to_float(row.get(src))
            if val is not None:
                slot[dst].append(val)

    util_buckets: dict[datetime, list[float]] = {}
    for row in util_rows:
        stamp = parse_iso(str(row.get("DateTime")))
        if stamp is None:
            continue
        val = _to_float(row.get("OutPercentUtil"))
        if val is None:
            continue
        util_buckets.setdefault(bucket_start(_as_utc(stamp), bucket_seconds), []).append(val)

    pairs = []
    for key in sorted(set(rtt_buckets) & set(util_buckets)):
        slot, utils = rtt_buckets[key], util_buckets[key]
        if not slot["avg"] or not utils:
            continue
        pairs.append({
            "t": key,
            "rtt_ms": sum(slot["avg"]) / len(slot["avg"]),
            "max_rtt_ms": max(slot["max"]) if slot["max"] else None,
            "availability": (sum(slot["avail"]) / len(slot["avail"])) if slot["avail"] else None,
            "util_pct": sum(utils) / len(utils),
        })
    return pairs


def overlap_ratio(rtt_rows: list[dict], util_rows: list[dict], pairs: list[dict]) -> float:
    """Share of the smaller series that actually found a partner.

    A near-zero ratio with both series populated is the signature of a
    timezone misalignment that `detect_series_offset` failed to correct — the
    report checks this before grading anything.
    """
    smaller = min(len(rtt_rows), len(util_rows))
    return (len(pairs) / smaller) if smaller else 0.0


def latency_under_load(pairs: list[dict], idle_below: float = 30.0,
                       busy_above: float = 70.0) -> dict:
    """The headline computation: how much latency the load adds.

    Bins buckets by concurrent egress utilisation, then compares the typical
    busy latency against the typical idle one. `sufficient` is False when
    either bin is too thin to support a percentile, and the caller is
    expected to report that instead of a grade.
    """
    idle = [p for p in pairs if p["util_pct"] < idle_below]
    busy = [p for p in pairs if p["util_pct"] >= busy_above]

    idle_rtts = [p["rtt_ms"] for p in idle]
    busy_rtts = [p["rtt_ms"] for p in busy]

    idle_p50 = percentile(idle_rtts, 50)
    busy_p50 = percentile(busy_rtts, 50)
    busy_p95 = percentile(busy_rtts, 95)

    penalty_p50 = (busy_p50 - idle_p50) if (busy_p50 is not None and idle_p50 is not None) else None
    penalty_p95 = (busy_p95 - idle_p50) if (busy_p95 is not None and idle_p50 is not None) else None
    sufficient = len(idle) >= MIN_BUCKETS_PER_BIN and len(busy) >= MIN_BUCKETS_PER_BIN

    return {
        "idle_buckets": len(idle),
        "busy_buckets": len(busy),
        "total_buckets": len(pairs),
        "idle_p50_ms": idle_p50,
        "busy_p50_ms": busy_p50,
        "busy_p95_ms": busy_p95,
        "penalty_p50_ms": penalty_p50,
        "penalty_p95_ms": penalty_p95,
        # Graded on the p50 penalty: the median experience while busy. A grade
        # driven by the p95 would swing on a handful of outliers and stop
        # being reproducible, which defeats the point of scoring at all. The
        # p95 is reported beside it as the tail.
        "grade": grade(penalty_p50) if sufficient else None,
        "rpm_busy": rpm(busy_p50),
        "rpm_idle": rpm(idle_p50),
        "idle_availability": _mean([p["availability"] for p in idle]),
        "busy_availability": _mean([p["availability"] for p in busy]),
        "sufficient": sufficient,
    }


def _mean(values) -> float | None:
    real = [v for v in values if v is not None]
    return (sum(real) / len(real)) if real else None


def busy_share(pairs: list[dict], busy_above: float = 70.0) -> float | None:
    """Share of the window spent above the busy threshold — "how often are
    users in the bad state". A severe penalty that occurs 2% of the time is a
    different problem from a mild one that occurs constantly."""
    if not pairs:
        return None
    return len([p for p in pairs if p["util_pct"] >= busy_above]) / len(pairs) * 100


def hour_profile(pairs: list[dict], tz_offset_hours: float = 0.0) -> list[dict]:
    """Median RTT and utilisation per hour-of-day.

    Rendered in *site local* time because the output is meant to be checked
    against when people actually complain ("mornings are terrible"), and a
    UTC histogram cannot be compared to a human's day without mental
    arithmetic nobody does correctly.
    """
    buckets: dict[int, list[dict]] = {}
    shift = timedelta(hours=tz_offset_hours)
    for p in pairs:
        buckets.setdefault((p["t"] + shift).hour, []).append(p)
    out = []
    for hour in range(24):
        rows = buckets.get(hour, [])
        out.append({
            "hour": hour,
            "samples": len(rows),
            "rtt_ms": percentile([r["rtt_ms"] for r in rows], 50),
            "util_pct": percentile([r["util_pct"] for r in rows], 50),
        })
    return out


# ─────────────────────────── device output ─────────────────────────────────

# IOS/IOS-XE ping summary. The round-trip clause is optional: at 0% success
# IOS omits it entirely, and parsing that as a malformed line would turn a
# totally-down circuit into a crash instead of the most important result the
# test can produce. Milliseconds are \d+ on older images and decimal on newer
# ones, so both are accepted.
_RE_PING = re.compile(
    r"Success rate is (?P<pct>\d+) percent \((?P<rx>\d+)/(?P<tx>\d+)\)"
    r"(?:,\s*round-trip min/avg/max\s*=\s*"
    r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)\s*(?P<unit>ms|us))?",
    re.IGNORECASE,
)


def parse_ping(text: str) -> dict | None:
    """Parse an IOS `ping` summary into a dict, or None if absent.

    Returns {sent, received, loss_pct, min_ms, avg_ms, max_ms}. The timing
    fields are None when the ping got no replies at all.
    """
    m = _RE_PING.search(text or "")
    if not m:
        return None
    tx, rx = int(m.group("tx")), int(m.group("rx"))
    scale = 0.001 if (m.group("unit") or "ms").lower() == "us" else 1.0
    timings = {"min_ms": None, "avg_ms": None, "max_ms": None}
    if m.group("avg") is not None:
        timings = {
            "min_ms": float(m.group("min")) * scale,
            "avg_ms": float(m.group("avg")) * scale,
            "max_ms": float(m.group("max")) * scale,
        }
    return {
        "sent": tx,
        "received": rx,
        "loss_pct": ((tx - rx) / tx * 100) if tx else None,
        **timings,
    }


_RE_SLA_ENTRY = re.compile(r"^(?:IPSLAs?\s+)?[Oo]peration\s+[Ii][Dd]:?\s*(\d+)", re.IGNORECASE)
# A `show ip sla summary` row: one whole operation on one line, optionally
# prefixed by the state code (* active, ^ inactive, ~ pending). Anchored and
# five-field-specific so it can be tried *before* the per-operation block
# parsing without matching block content — no line inside a statistics block
# begins with a bare operation number followed by a lowercase type token.
_RE_SLA_SUMMARY_ROW = re.compile(
    r"^[*^~]?(?P<id>\d+)\s+(?P<type>[a-z][a-z-]*)\s+(?P<dest>[\w.:-]+)\s+"
    r"(?P<stats>\S+)\s+(?P<code>\S+)",
    re.IGNORECASE,
)
_RE_SLA_TYPE = re.compile(r"^Type of operation:\s*(.+?)\s*$", re.IGNORECASE)
_RE_SLA_RTT = re.compile(r"^(?:Latest )?RTT:?\s*(\d+)\s*(?:milliseconds|ms)?", re.IGNORECASE)
_RE_SLA_RTT_INLINE = re.compile(r"\bRTT[=:]\s*(\d+)", re.IGNORECASE)
_RE_SLA_LOSS = re.compile(r"Packet Loss(?: SD| DS)?:?\s*(\d+)", re.IGNORECASE)
_RE_SLA_JITTER = re.compile(
    r"^(?:Source to Destination|Destination to Source) Jitter Min/Avg/Max:?\s*"
    r"(\d+)/(\d+)/(\d+)", re.IGNORECASE,
)
_RE_SLA_MOS = re.compile(r"\bMOS[=:]\s*([\d.]+)", re.IGNORECASE)
_RE_SLA_ICPIF = re.compile(r"\bICPIF[=:]\s*(\d+)", re.IGNORECASE)
_RE_SLA_RETURN = re.compile(r"^(?:Latest operation return code|Return code):?\s*(.+?)\s*$",
                            re.IGNORECASE)
_RE_SLA_TARGET = re.compile(r"^(?:Target address(?:/Source address)?|Destination):?\s*"
                            r"([0-9a-fA-F.:]+)", re.IGNORECASE)


def parse_ip_sla_statistics(text: str) -> list[dict]:
    """Parse `show ip sla statistics` (or `... summary`) into per-operation dicts.

    IP SLA is the only *independent* latency measurement available on the
    router — everything else in these reports is the device describing its
    own queues, which is an inference about user experience. A configured
    probe is a real round trip across the circuit, and a jitter operation
    additionally yields jitter and a MOS score, which is a literal 1-5
    user-experience number for voice.

    Returns [{op_id, type, destination, rtt_ms, loss_pct, jitter_ms, mos,
    icpif, return_code}], each field None when that operation doesn't report
    it. Deliberately tolerant: output shape varies a lot by operation type
    and IOS version, and a partially-understood operation is still worth
    showing.
    """
    ops: list[dict] = []
    current: dict | None = None

    def _new(op_id: str) -> dict:
        return {"op_id": op_id, "type": None, "destination": None, "rtt_ms": None,
                "loss_pct": None, "jitter_ms": None, "mos": None, "icpif": None,
                "return_code": None}

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _RE_SLA_ENTRY.match(line)
        if m:
            current = _new(m.group(1))
            ops.append(current)
            continue

        # `show ip sla summary` is a flat table rather than per-operation
        # blocks; each row is a whole operation on one line. Tried before the
        # block-field parsing below, because a summary row contains "RTT=" and
        # would otherwise be mistaken for block content.
        row = _RE_SLA_SUMMARY_ROW.match(line)
        if row:
            current = _new(row.group("id"))
            current["type"] = row.group("type")
            current["destination"] = row.group("dest")
            rtt = _RE_SLA_RTT_INLINE.search(line)
            if rtt:
                current["rtt_ms"] = float(rtt.group(1))
            current["return_code"] = row.group("code")
            ops.append(current)
            continue

        if current is None:
            continue

        for regex, key, cast in (
            (_RE_SLA_TYPE, "type", str),
            (_RE_SLA_RETURN, "return_code", str),
            (_RE_SLA_TARGET, "destination", str),
        ):
            m = regex.match(line)
            if m:
                current[key] = cast(m.group(1))
                break
        else:
            m = _RE_SLA_RTT.match(line)
            if m:
                current["rtt_ms"] = float(m.group(1))
                continue
            m = _RE_SLA_JITTER.match(line)
            if m and current["jitter_ms"] is None:
                current["jitter_ms"] = float(m.group(2))   # the avg of min/avg/max
                continue
            m = _RE_SLA_LOSS.search(line)
            if m and current["loss_pct"] is None:
                current["loss_pct"] = float(m.group(1))
            m = _RE_SLA_MOS.search(line)
            if m:
                current["mos"] = float(m.group(1))
            m = _RE_SLA_ICPIF.search(line)
            if m:
                current["icpif"] = float(m.group(1))

    return ops


def merge_sla_ops(*op_lists: list[dict]) -> list[dict]:
    """Merge per-operation records from several `show ip sla ...` outputs.

    Necessary because no single command carries everything: `show ip sla
    statistics` reports RTT, jitter, loss and MOS but usually omits the
    destination, while `show ip sla summary` gives type and destination but
    little else. Without the merge the destination is missing, and the live
    ping test cannot borrow a target from a configured operation.

    First non-None value for each field wins, so callers should pass the
    richer source first.
    """
    merged: dict[str, dict] = {}
    for ops in op_lists:
        for op in ops:
            key = str(op.get("op_id"))
            existing = merged.get(key)
            if existing is None:
                merged[key] = dict(op)
                continue
            for field, value in op.items():
                if existing.get(field) is None and value is not None:
                    existing[field] = value
    return [merged[k] for k in sorted(merged, key=lambda s: (len(s), s))]


def sla_targets(ops: list[dict]) -> list[str]:
    """Destinations of configured IP SLA operations.

    Used to default the live ping test's target: an address the router is
    already probing every minute is, by construction, reachable and
    operationally sanctioned — a better default than asking someone to invent
    one, and it makes the active test directly comparable to the passive
    IP SLA numbers beside it.
    """
    seen, out = set(), []
    for op in ops:
        dest = (op.get("destination") or "").strip()
        if dest and dest not in seen:
            seen.add(dest)
            out.append(dest)
    return out
