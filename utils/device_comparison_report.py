"""utils/device_comparison_report.py — DNAC vs SolarWinds inventory reconciliation.

Answers "is everything Catalyst Center manages also being monitored, and vice
versa?" by putting the two inventories side by side:

  - **DNAC** side is a live, all-or-nothing pull of the device inventory.
  - **SolarWinds** side is a live SWQL read of `Orion.Nodes`, narrowed to
    `Vendor = 'Cisco'` — the same literal `utils/cdrl49_report.py` already
    uses successfully against the real instance.

Neither side is cached; see fetch_dnac_devices for why a stale DNAC list
would invert this report rather than merely age it.

SolarWinds nodes in **maintenance mode** ("unmanaged" in Orion terms) are
kept in the results and flagged rather than dropped — polling is suspended
for those, so they may already be off the network, which makes "missing from
DNAC" something to verify rather than act on. See maintenance_state.

Scope, per the report's purpose: only device classes Catalyst Center actually
manages. The two exclusions are *not* symmetric, because the underlying facts
aren't:

  - **Nexus, ACI and Unified Communications** (CUCM) are dropped from the
    SolarWinds side only. Catalyst Center doesn't manage any of them, so they
    can never appear in the DNAC inventory — running those patterns there
    couldn't remove a real Nexus, only misfire on a switch whose model string
    happened to match, silently dropping it from the comparison.
  - **Wireless** is dropped from *both* sides, because Catalyst Center does
    manage WLCs and APs. Excluding wireless from SolarWinds alone would
    resurface every AP as a bogus "in DNAC but not monitored" row.

Because that classification is heuristic (it reads vendor model strings), the
report **returns what it excluded and why**, grouped with examples. A filter
that's too aggressive shows up as a surprising exclusion count rather than as
silently missing devices — the failure mode is visible instead of invisible.

Devices are identified by hostname *and* management IP together, matched in
three passes (both keys, then hostname alone, then IP alone) so certain pairs
are settled before weaker evidence is considered — see compare_inventories.

Nothing here is cached: a reconciliation is a point-in-time answer, same
posture as the other reports.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

import clients.dnac as dc
import clients.solarwinds as solarwinds
from cache import cache
from utils.bandwidth_report import short_hostname
from utils.report_pool import FANOUT_POOL
from utils.version_compare import versions_compatible

logger = logging.getLogger(__name__)

# Matched against model/description strings, lowercased. Word-boundary
# anchored where a bare substring would over-match.
#
# Each rule declares which system it applies to, and that scoping is load
# bearing rather than tidiness: Catalyst Center does not manage Nexus, ACI or
# CUCM at all, so those patterns can never legitimately fire on a DNAC device
# — running them there could only ever produce a false positive that silently
# drops a real switch from the comparison. Wireless is the opposite case:
# Catalyst Center *does* manage WLCs and APs, so wireless genuinely exists on
# both sides and has to be filtered from both.
_SW = "solarwinds"
_DNAC = "dnac"

_EXCLUSION_RULES: list[tuple[str, re.Pattern, frozenset]] = [
    ("Nexus", re.compile(r"\bnexus\b|\bn[2357]k\b|\bn9k\b|\bnx-?os\b", re.I), frozenset({_SW})),
    ("ACI", re.compile(r"\bapic\b|\baci\b", re.I), frozenset({_SW})),
    # Voice/collaboration servers. CUCM often reports server hardware as its
    # MachineType, so the identifying string usually turns up in
    # NodeDescription (sysDescr) instead — both fields are checked. "Call
    # Manager" is CUCM's pre-2006 name and still appears in older sysDescrs.
    ("Unified Communications", re.compile(
        r"\bcucm\b|\bunified\s+communications?\s+manager\b|\bunified\s+cm\b|\bcall\s*manager\b",
        re.I,
    ), frozenset({_SW})),
    # "ap" is never matched bare — far too short, and NodeDescription carries
    # a full sysDescr string where a two-letter token would fire constantly.
    # Catalyst wireless is model-ranged rather than named: 91xx are APs and
    # 9800 is the WLC, while 92xx-96xx are switches, so only the former two
    # are matched.
    ("Wireless", re.compile(
        r"\baironet\b|\bair-[a-z]|\bwireless\b|\bwlc\b"
        r"|\baccess\s+point\b|\b(?:unified|lightweight|embedded)\s+ap\b"
        r"|\bap\d{3,4}[a-z]*\b|\bc?9800\b|\bc?91\d{2}[a-z]*\b",
        re.I,
    ), frozenset({_SW, _DNAC})),
]


def classify_exclusion(*fields: str | None, system: str = _SW) -> str | None:
    """Return the exclusion category for a device, or None to keep it.

    `system` selects which rules apply — see _EXCLUSION_RULES. Every provided
    field is checked (model, family, description) since which one carries the
    useful signal differs: DNAC's `family` says "Unified AP" outright while
    SolarWinds only has a `MachineType`/`NodeDescription` string.
    """
    haystack = " ".join(f for f in fields if f)
    if not haystack.strip():
        return None
    for label, pattern, systems in _EXCLUSION_RULES:
        if system in systems and pattern.search(haystack):
            return label
    return None


def _norm(value: str | None) -> str:
    """Lowercase, strip everything but alphanumerics — for loose comparison of
    model/version strings that the two systems format differently."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _key(hostname: str | None) -> str:
    return short_hostname(hostname or "").lower()


# Orion's node status code for a node taken out of monitoring. Used as a
# second signal alongside the `Unmanaged` flag so maintenance is still
# detected when the maintenance columns had to be dropped (see
# fetch_solarwinds_devices) — `Status` is part of the proven base query.
_STATUS_UNMANAGED = 9

_MAINTENANCE_COLUMNS = """,
    n.Unmanaged,
    n.UnManageFrom,
    n.UnManageUntil"""


def _node_swql(extra_columns: str) -> str:
    return f"""
SELECT
    n.NodeID,
    n.Caption AS NodeName,
    n.IPAddress AS NodeIpAddress,
    n.MachineType,
    n.IOSVersion,
    n.NodeDescription,
    n.Status,
    cp.Site{extra_columns}
FROM Orion.Nodes n
LEFT JOIN Orion.NodesCustomProperties cp ON cp.NodeID = n.NodeID
WHERE n.Vendor = 'Cisco'
ORDER BY n.Caption
"""


def _is_true(value) -> bool:
    """SWQL booleans arrive as bool, 0/1, or a string depending on the column
    and serialiser, so normalise rather than trusting one shape."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"true", "yes", "y", "1"}


def maintenance_state(node: dict) -> tuple[bool, str | None]:
    """Is this node in maintenance mode, and until when?

    SolarWinds calls it "unmanaged": polling is suspended, so the node's data
    is frozen at whatever it was when maintenance began. That matters here
    because such a device may already be off the network — it would still
    appear as a gap this report suggests onboarding.

    Two signals, because the `Unmanaged` column may have been dropped from
    the query: the flag itself, falling back to the node status code, which
    comes from the proven base column set.

    `UnManageUntil` is only read when the node is actually unmanaged — Orion
    leaves stale values in that column after a maintenance window ends.
    """
    unmanaged = _is_true(node.get("Unmanaged"))
    if not unmanaged:
        try:
            unmanaged = int(node.get("Status")) == _STATUS_UNMANAGED
        except (TypeError, ValueError):
            unmanaged = False
    if not unmanaged:
        return False, None
    until = node.get("UnManageUntil")
    return True, (until.strip() if isinstance(until, str) and until.strip() else None)


def fetch_solarwinds_devices(username: str, password: str, timeout: int | None = None) -> list[dict]:
    """Cisco nodes from SolarWinds.

    `Vendor = 'Cisco'` and `MachineType` are both confirmed working against the
    real instance (see utils/cdrl49_report.build_swql), as is the
    `Orion.NodesCustomProperties` join and its `Site` field (see
    utils/bandwidth_report._SITE_INFO_JOIN). `IOSVersion`, `NodeDescription`
    and `Status` are standard Orion.Nodes columns but are not independently
    confirmed here — if this query ever 400s, they're the first suspects, and
    clients.solarwinds.query now surfaces Orion's actual "Cannot resolve
    property ..." text.

    The custom-properties join is a LEFT JOIN, unlike the other reports':
    those want site metadata for a node already known to have it, whereas
    this report exists to *find* gaps. An inner join would silently drop any
    node missing a custom-properties row — hiding exactly the unmonitored or
    unmanaged device the report was run to surface.

    The maintenance-mode columns are requested first and dropped on failure
    (see _MAINTENANCE_COLUMNS). They're the one part of this query never
    confirmed against the real instance, and SWQL is all-or-nothing — an
    unresolvable column would take down a report that currently works, to add
    a supplementary flag. Degrading to "maintenance unknown" is the better
    trade; the fallback logs loudly.
    """
    try:
        return solarwinds.query(
            _node_swql(_MAINTENANCE_COLUMNS), username, password, timeout=timeout,
        )
    except Exception as e:
        logger.warning(
            "SolarWinds maintenance-mode columns unavailable, retrying without them "
            f"(devices will show as maintenance-unknown): {e}",
            extra={"target": "SolarWinds", "action": "DEVICE_COMPARISON"},
        )
        return solarwinds.query(_node_swql(""), username, password, timeout=timeout)


def fetch_dnac_devices(dnac) -> list[dict]:
    """DNAC's device inventory, fetched **live** on every report run.

    Deliberately not the warmed `devices` cache. That cache carries a 7-day
    TTL, and a stale entry here doesn't just age the report — it inverts it:
    a device onboarded since the last refresh still reads as "in SolarWinds
    but not DNAC", and this report offers a button to onboard exactly those
    rows. Acting on stale data would push an already-managed device back
    through discovery.

    strict=True for the same reason (see clients.dnac.get_all_devices): a
    partial page fetch would fabricate the same false gaps, so a failure
    must surface as an error rather than a shorter list.

    `dnac` of None means "no client available" — only DEV_MODE, where the
    seeded cache stands in for a real controller.
    """
    if dnac is None:
        return cache.get_stale("devices") or []
    return dc.get_all_devices(dnac, strict=True)


def _dnac_view(device: dict) -> dict:
    return {
        "hostname": short_hostname(device.get("hostname")),
        "ip": device.get("managementIpAddress"),
        "model": device.get("platformId"),
        "version": device.get("softwareVersion"),
        "serial": device.get("serialNumber"),
        "family": device.get("family"),
        "role": device.get("role"),
        "reachability": device.get("reachabilityStatus"),
    }


def site_code_for(hostname: str | None, site: str | None) -> tuple[str, str]:
    """Site code for a SolarWinds node, and where it came from.

    Prefers the node's `Site` custom property. Falls back to the first four
    characters of the hostname — the same convention `routers/f5.py::_site_of`
    already uses to derive a site from a hostname.

    The source is returned alongside the value because this feeds the "Add to
    DNAC" action, which assigns the device to a site in production. A derived
    code is a guess, and the operator confirming that action should be able to
    see that it's a guess rather than a recorded fact.
    """
    recorded = (site or "").strip()
    if recorded:
        return recorded, "solarwinds"
    return short_hostname(hostname)[:4].upper(), "hostname"


def _sw_view(node: dict) -> dict:
    hostname = short_hostname(node.get("NodeName"))
    code, code_source = site_code_for(hostname, node.get("Site"))
    in_maintenance, until = maintenance_state(node)
    return {
        "hostname": hostname,
        "ip": node.get("NodeIpAddress"),
        "model": node.get("MachineType"),
        "version": node.get("IOSVersion"),
        "description": node.get("NodeDescription"),
        "status": node.get("Status"),
        "site_code": code,
        "site_code_source": code_source,
        "in_maintenance": in_maintenance,
        "maintenance_until": until,
    }


def _model_matches(a: str | None, b: str | None) -> bool:
    """Do two model strings describe the same hardware?

    The systems format models very differently for identical kit — DNAC's
    `platformId` is the ordering code ("ISR4451-X/K9") while SolarWinds'
    `MachineType` is a prose name ("Cisco ISR 4451"). Neither contains the
    other, so plain substring matching flags every single device and buries
    the real mismatches.

    The stable signal across both is the model *number*, so compare runs of
    3+ digits: {4451} vs {4451} matches, {4451} vs {1001} (ISR vs ASR) does
    not. Short runs are ignored — port counts and "K9" suffixes are noise.
    Falls back to substring matching when either side has no such number.
    """
    tokens_a = set(re.findall(r"\d{3,}", a or ""))
    tokens_b = set(re.findall(r"\d{3,}", b or ""))
    if tokens_a and tokens_b:
        return bool(tokens_a & tokens_b)
    na, nb = _norm(a), _norm(b)
    return na in nb or nb in na


def _version_matches(a: str | None, b: str | None) -> bool:
    """Compare numerically so zero-padding doesn't read as a mismatch —
    SolarWinds reports "17.06.05" where DNAC reports "17.6.5". Prefix-
    tolerant (truncated-to-shortest-length): moved to utils/version_compare
    so the golden-image compliance dashboard can reuse the same zero-padding
    handling under its own, stricter, non-truncating semantics."""
    return versions_compatible(a, b)


def _differences(dnac: dict, sw: dict, matched_by: str) -> list[dict]:
    """Field-level mismatches worth showing.

    Deliberately conservative — see _model_matches/_version_matches. A report
    that flags every device as "differs" because of cosmetic formatting is
    worse than no report at all, since it trains you to ignore it.
    """
    diffs = []

    if matched_by == "ip":
        # Same device by address, different names — a genuine finding, and the
        # reason it didn't match by hostname in the first place.
        diffs.append({
            "field": "Hostname", "dnac": dnac["hostname"], "solarwinds": sw["hostname"],
        })
    elif (dnac.get("ip") or sw.get("ip")) and (dnac.get("ip") or "") != (sw.get("ip") or ""):
        diffs.append({"field": "IP Address", "dnac": dnac.get("ip"), "solarwinds": sw.get("ip")})

    if dnac.get("model") and sw.get("model") and not _model_matches(dnac["model"], sw["model"]):
        diffs.append({"field": "Model", "dnac": dnac["model"], "solarwinds": sw["model"]})

    if dnac.get("version") and sw.get("version") and not _version_matches(dnac["version"], sw["version"]):
        diffs.append({"field": "Software Version", "dnac": dnac["version"], "solarwinds": sw["version"]})

    return diffs


def _summarize_exclusions(excluded: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in excluded:
        grouped[item["reason"]].append(item)
    return [
        {
            "reason": reason,
            "count": len(items),
            "examples": [i["name"] for i in sorted(items, key=lambda x: x["name"] or "")[:5]],
        }
        for reason, items in sorted(grouped.items())
    ]


def compare_inventories(dnac_devices: list[dict], sw_nodes: list[dict]) -> dict:
    """Reconcile the two inventories. Pure function — no I/O, so the matching
    and classification rules are testable without either system."""
    dnac_kept, dnac_excluded = [], []
    for d in dnac_devices:
        reason = classify_exclusion(
            d.get("platformId"), d.get("family"), d.get("type"), system=_DNAC,
        )
        name = short_hostname(d.get("hostname"))
        if not name:
            continue
        (dnac_excluded if reason else dnac_kept).append(
            {"reason": reason, "name": name} if reason else d
        )

    sw_kept, sw_excluded = [], []
    for n in sw_nodes:
        reason = classify_exclusion(
            n.get("MachineType"), n.get("NodeDescription"), system=_SW,
        )
        name = short_hostname(n.get("NodeName"))
        if not name:
            continue
        (sw_excluded if reason else sw_kept).append(
            {"reason": reason, "name": name} if reason else n
        )

    # A device's identity here is hostname *and* management IP together, so
    # matching runs in three passes, strongest first:
    #
    #   1. both agree      — unambiguous, the device is the same by every key
    #   2. hostname only   — renumbered / IP recorded differently
    #   3. IP only         — renamed in one system but the same box
    #
    # Ordering matters: a single greedy hostname pass lets a partial match
    # consume a node that was a perfect both-key match for a *different*
    # device, which then reports as two false gaps. Settling every certain
    # pair before considering weaker evidence removes that whole class of
    # mis-pairing.
    by_pair: dict[tuple[str, str], int] = {}
    by_name: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for idx, n in enumerate(sw_kept):
        name, ip = _key(n.get("NodeName")), (n.get("NodeIpAddress") or "").strip()
        if name and ip:
            by_pair.setdefault((name, ip), idx)
        if name:
            by_name.setdefault(name, idx)
        if ip:
            by_ip.setdefault(ip, idx)

    matched: list[dict] = []
    consumed: set[int] = set()

    def _record(device: dict, idx: int, matched_by: str) -> None:
        consumed.add(idx)
        dnac_view, sw_view = _dnac_view(device), _sw_view(sw_kept[idx])
        matched.append({
            "hostname": dnac_view["hostname"],
            "matched_by": matched_by,
            "dnac": dnac_view,
            "solarwinds": sw_view,
            "differences": _differences(dnac_view, sw_view, matched_by),
        })

    def _lookup(index: dict, key) -> int | None:
        # An incomplete key (missing hostname or IP) must never match — it
        # would collapse every such device onto the same "" bucket.
        parts = key if isinstance(key, tuple) else (key,)
        if not all(parts):
            return None
        # A SolarWinds node can only satisfy one DNAC device — otherwise
        # duplicate hostnames across sites would hide a genuine gap.
        idx = index.get(key)
        return None if idx is None or idx in consumed else idx

    pending = list(dnac_kept)
    for matched_by, key_of, index in (
        ("hostname+ip", lambda d: (_key(d.get("hostname")), (d.get("managementIpAddress") or "").strip()), by_pair),
        ("hostname", lambda d: _key(d.get("hostname")), by_name),
        ("ip", lambda d: (d.get("managementIpAddress") or "").strip(), by_ip),
    ):
        still_pending = []
        for d in pending:
            idx = _lookup(index, key_of(d))
            if idx is None:
                still_pending.append(d)
            else:
                _record(d, idx, matched_by)
        pending = still_pending

    dnac_only = [_dnac_view(d) for d in pending]
    sw_only = [_sw_view(n) for idx, n in enumerate(sw_kept) if idx not in consumed]

    matched.sort(key=lambda m: (m["hostname"] or "").lower())
    dnac_only.sort(key=lambda d: (d["hostname"] or "").lower())
    sw_only.sort(key=lambda s: (s["hostname"] or "").lower())

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "summary": {
            "dnac_total": len(dnac_kept),
            "solarwinds_total": len(sw_kept),
            "matched": len(matched),
            "with_differences": sum(1 for m in matched if m["differences"]),
            "dnac_only": len(dnac_only),
            "solarwinds_only": len(sw_only),
            # Of the gaps, how many are unmanaged in SolarWinds — those
            # may already be off the network, so "missing from DNAC" is
            # not necessarily something to act on.
            "solarwinds_only_in_maintenance": sum(1 for s in sw_only if s["in_maintenance"]),
        },
        "matched": matched,
        "dnac_only": dnac_only,
        "solarwinds_only": sw_only,
        "excluded": {
            "dnac": _summarize_exclusions(dnac_excluded),
            "solarwinds": _summarize_exclusions(sw_excluded),
        },
    }


def generate_device_comparison_report(dnac, username: str, password: str) -> dict:
    """Pull both inventories live and reconcile them.

    Either side failing raises rather than degrading to a one-sided report:
    with no SolarWinds the answer reads as "nothing is monitored", with no
    DNAC as "nothing is managed". Both are worse than an error, because both
    look like findings.

    The two fetches are independent, so they're overlapped on the shared
    FANOUT_POOL — this function already runs in a worker thread, and pulling
    a whole fleet from DNAC alongside a fleet-wide SWQL read is the slowest
    thing on the Reports pages.
    """
    fut_dnac = FANOUT_POOL.submit(fetch_dnac_devices, dnac)
    fut_sw = FANOUT_POOL.submit(fetch_solarwinds_devices, username, password)
    return compare_inventories(fut_dnac.result(), fut_sw.result())


def to_csv(report: dict) -> str:
    """Flat CSV of every device and its status, for sharing outside the app."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Status", "Hostname", "Matched By", "Differences",
        "DNAC IP", "SolarWinds IP", "DNAC Model", "SolarWinds Model",
        "DNAC Version", "SolarWinds Version", "DNAC Serial", "DNAC Family",
        "Site Code", "Site Code Source", "Maintenance Mode", "Maintenance Until",
    ])

    for m in report["matched"]:
        d, s = m["dnac"], m["solarwinds"]
        writer.writerow([
            "Differs" if m["differences"] else "In sync",
            m["hostname"], m["matched_by"],
            "; ".join(f'{x["field"]}: {x["dnac"]} vs {x["solarwinds"]}' for x in m["differences"]),
            d.get("ip") or "", s.get("ip") or "", d.get("model") or "", s.get("model") or "",
            d.get("version") or "", s.get("version") or "", d.get("serial") or "", d.get("family") or "",
            s.get("site_code") or "", s.get("site_code_source") or "",
            "Yes" if s.get("in_maintenance") else "", s.get("maintenance_until") or "",
        ])

    for d in report["dnac_only"]:
        writer.writerow([
            "DNAC only", d.get("hostname") or "", "", "",
            d.get("ip") or "", "", d.get("model") or "", "",
            d.get("version") or "", "", d.get("serial") or "", d.get("family") or "",
            "", "", "", "",
        ])

    for s in report["solarwinds_only"]:
        writer.writerow([
            "SolarWinds only", s.get("hostname") or "", "", "",
            "", s.get("ip") or "", "", s.get("model") or "",
            "", s.get("version") or "", "", "",
            s.get("site_code") or "", s.get("site_code_source") or "",
            "Yes" if s.get("in_maintenance") else "", s.get("maintenance_until") or "",
        ])

    return buf.getvalue()
