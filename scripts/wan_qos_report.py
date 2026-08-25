#!/usr/bin/env python3
"""scripts/wan_qos_report.py — WAN queue/QoS report for a site's border router.

Given a site name, this:
  1. Resolves the site in DNAC (site hierarchy, substring match) — preferring
     the shallowest matching level (Building/Area) over a deeper one
     (Floor), then searching that site plus every descendant site for
     devices. dc.get_site_cache() sorts deepest-first for a different
     caller's needs, and a Floor's hierarchy path always substring-matches
     whenever its parent Building does (it's the Building's path plus a
     suffix) — matching depth-first would silently resolve to a Floor
     instead. This fleet only floor-assigns APs, so a Floor-scoped device
     search finds zero border routers and the report comes back empty even
     though the router is right there on the parent Building. See
     find_best_site_match_prefer_shallow() / site_and_descendant_ids().
  2. Finds the device(s) at that site (or its descendants) whose DNAC role
     is "BORDER ROUTER".
  3. Resolves each border router's WAN interface — first by DNAC "WAN" tag
     membership (the tag scripts/tag_c8k_wan_interfaces.py applies), falling
     back to the same VRF-forwarding heuristic that script uses
     (vrf forwarding WAN/INTERNET on a physical interface, parsed from
     DNAC's cached running-config) if the interface isn't tagged yet.
     Reuses those functions directly from tag_c8k_wan_interfaces.py rather
     than re-implementing "what counts as a WAN interface" a second time.
  4. SSHes to the device (Netmiko) and runs exactly one read-only command:
       show policy-map interface <wan-if> output
     Nothing else is ever sent — no send_config_set, no write verbs.
  5. Parses the policy-map output into per-queue stats and prints a report:
     a "Queue summary" table (packets/bytes share, queue depth vs limit,
     drops, drop % of that queue's own traffic, each queue's share of total
     interface drops, and configured priority/bandwidth) — this table is
     the report's primary output and always prints. A "Detail per queue"
     section with the same data broken out per-queue (matches, 30s
     offered/drop rate, output counters, full config) is opt-in via
     --detail: it's long enough on a multi-queue policy-map to push the
     summary table off screen, so it stays hidden unless asked for.

Handles Cisco's hierarchical (parent-shaper + child-LLQ/CBWFQ) policy-map
shape, which is what this fleet runs: a parent class-default shapes to the
circuit rate and carries a nested child service-policy that does the actual
queuing (priority + bandwidth-remaining-percent classes). Priority classes
on IOS-XE don't print their own "(queue depth/total drops/no-buffer drops)"
line — all priority classes share one physical LLQ system queue, printed
once under "queue stats for all priority classes:" ahead of the Class-map
entries it covers — so that block is captured and attached to every
priority class-map that doesn't have its own per-class queue line, which is
the correct semantic (not an approximation): that queue really is shared.

Nesting depth is inferred from each Class-map line's own indentation rather
than a fixed column count, since exact spacing isn't guaranteed across IOS
versions — indent values seen are sorted and mapped to depth 0, 1, 2, ...
"% of total interface traffic" is each class's packet count divided by the
sum of packet counts at depth 0 (the parent/outermost class(es) — for a
flat, non-hierarchical policy-map every class is depth 0, and the math
still works out to "share of everything counted"). "Share of total
interface drops" is denominated the same way, using depth-0 drops when
present (the parent-level counter is what IOS itself presents as the
interface-wide drop total) so a hierarchical policy's parent and child drop
counters — which on this fleet track the same underlying drops, just
rolled up at different levels — aren't double-counted.

Read-only guarantee: the only DNAC calls made are GETs (device inventory,
site membership, interface list, tag membership, cached config text) and
the only device command is the `show` command above, run once via
Netmiko's send_command. There is no config-mode code path in this script
at all.

Auth:
  DNAC:   the app's shared service account, same as every other script here
          (DOMAIN_USERNAME/DOMAIN_PASSWORD in .env — clients.dnac.get_client()).
  Device: defaults to that same shared account (CLAUDE.md: "shared AD
          credentials used by all platform clients"); override with
          --username/--password for a specific run.

Usage:
    .venv/bin/python -m scripts.wan_qos_report "DCA"
    .venv/bin/python -m scripts.wan_qos_report "DCA" --interface GigabitEthernet0/0/5
    .venv/bin/python -m scripts.wan_qos_report --device RTR-DCA-01
    .venv/bin/python -m scripts.wan_qos_report "DCA" --raw -v
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.dnac as dc  # noqa: E402
from clients.dnac import _dictify  # noqa: E402
from utils.device_ssh import guess_device_type  # noqa: E402
from scripts.tag_c8k_wan_interfaces import (  # noqa: E402
    DEFAULT_TAG_NAME,
    DEFAULT_VRFS,
    fetch_tagged_interface_ids,
    physical_parent,
    vrf_wan_hits,
)

logger = logging.getLogger("wan_qos_report")

SSH_TIMEOUT = 30
DEFAULT_ROLE = "BORDER ROUTER"

# Defense in depth: these values ultimately get interpolated into a CLI
# command string sent over SSH. They normally come from DNAC (trusted) or
# an operator-supplied --interface flag, but validate the charset anyway —
# cheap, and matches the project's existing convention for any name that
# reaches a CLI/SWQL string (routers/firewall.py's _CLI_NAME_RE,
# utils/bandwidth_report.py's _SWQL_NAME_RE).
_IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9/.:_-]{1,64}$")


# ─────────────────────────── DNAC lookups ──────────────────────────────────

def get_site_device_ids(dnac, site_id: str) -> set[str]:
    """DNAC instanceUuids of every device assigned to this site."""
    ids: set[str] = set()
    offset = 1
    while True:
        try:
            resp = dnac.sites.get_devices_that_are_assigned_to_a_site(
                id=site_id, member_type="networkdevice", offset=offset, limit=500,
            )
        except Exception as e:
            logger.error("Site membership fetch failed for site %s: %s", site_id, e)
            break
        items = getattr(resp, "response", None) or []
        if not items:
            break
        for it in items:
            d = _dictify(it)
            uid = d.get("instanceUuid") or d.get("id")
            if uid:
                ids.add(uid)
        if len(items) < 500:
            break
        offset += 500
    return ids


def find_best_site_match_prefer_shallow(site_cache: list[dict], term: str) -> tuple[str | None, str | None]:
    """Like dc.find_best_site_match, but prefers the least-specific
    (shallowest) matching site rather than the most-specific.

    dc.get_site_cache() sorts deepest-first so build_device_site_map's
    "most specific assignment wins" logic works — but that same order means
    a Floor whose hierarchy path is `<Building path>/Floor N` always
    substring-matches a search term whenever its parent Building does too,
    and gets returned first since it's deeper. This fleet only assigns APs
    to floors — border routers sit at the Building/Area level — so
    depth-first matching silently resolves "site" to a floor with no
    border router on it, and the report comes back empty. Matching
    shallowest-first fixes that without touching dc.get_site_cache's
    ordering, which other callers (e.g. device import) rely on as-is.
    """
    for site in sorted(site_cache, key=lambda s: s["name"].count("/")):
        if term.lower() in site["name"].lower():
            return site["id"], site["name"]
    return None, None


def site_and_descendant_ids(site_cache: list[dict], site_name: str) -> set[str]:
    """The matched site's id plus every descendant site's id (Floors under
    a matched Building, sites under a matched Area, ...). Border routers
    live at the Building/Area level in this fleet, but unioning in
    descendants keeps the search correct even where a router genuinely is
    floor-assigned, rather than assuming the hierarchy shape."""
    prefix = site_name + "/"
    return {
        s["id"] for s in site_cache
        if s["name"] == site_name or s["name"].startswith(prefix)
    }


def find_border_routers(devices: list[dict], site_device_ids: set[str], role: str) -> list[dict]:
    role_needle = role.strip().lower()
    return [
        d for d in devices
        if d.get("id") in site_device_ids
        and role_needle in (d.get("role") or "").strip().lower()
    ]


def find_devices_by_name(devices: list[dict], needle: str) -> list[dict]:
    needle = needle.lower()
    return [
        d for d in devices
        if needle in (d.get("hostname") or "").lower()
        or needle in (d.get("managementIpAddress") or "").lower()
    ]


def resolve_wan_interface(dnac, device: dict, tag_name: str, target_vrfs: set[str]) -> tuple[str | None, str]:
    """Best-effort WAN interface for one device. Returns (name, method) —
    method is a human-readable string for the report, or a reason code
    ("ambiguous-tag", "ambiguous-vrf", "not-found") when name is None."""
    device_id = device.get("id")
    device_ifaces = dc.get_device_interfaces(dnac, device_id)
    by_id = {i.get("id"): i for i in device_ifaces if i.get("id")}

    tag_match = None
    try:
        resp = dnac.tag.get_tag(name=tag_name)
        tag_items = [_dictify(t) for t in (getattr(resp, "response", None) or [])]
        tag_match = next((t for t in tag_items if t.get("name") == tag_name), None)
    except Exception as e:
        logger.debug("Tag lookup for '%s' failed: %s", tag_name, e)

    if tag_match:
        tagged_ids = fetch_tagged_interface_ids(dnac, tag_match["id"])
        candidates = [iface for iface_id, iface in by_id.items() if iface_id in tagged_ids]
        if len(candidates) == 1:
            return candidates[0].get("portName"), f"DNAC tag '{tag_name}'"
        if len(candidates) > 1:
            names = ", ".join(sorted(c.get("portName", "?") for c in candidates))
            logger.warning(
                "%s: multiple interfaces tagged '%s' (%s) — pass --interface to disambiguate",
                device.get("hostname"), tag_name, names,
            )
            return None, "ambiguous-tag"

    # Fall back to VRF-forwarding detection (same heuristic as
    # tag_c8k_wan_interfaces.py) for devices not yet tagged.
    config = dc.get_device_config(dnac, device_id)
    hits = vrf_wan_hits(config, target_vrfs) if config else []
    physical: set[str] = set()
    for ifname, _vrf in hits:
        parent = physical_parent(ifname)
        if parent:
            physical.add(parent)
    if len(physical) == 1:
        return physical.pop(), f"VRF forwarding ({sorted(target_vrfs)})"
    if len(physical) > 1:
        logger.warning(
            "%s: multiple physical interfaces carry a WAN VRF (%s) — pass --interface to disambiguate",
            device.get("hostname"), ", ".join(sorted(physical)),
        )
        return None, "ambiguous-vrf"

    return None, "not-found"


# ─────────────────────────── Device SSH (read-only) ────────────────────────

def ssh_run_commands(ip: str, username: str, password: str, device_type: str,
                      commands: list[tuple[str, str]], timeout: int) -> dict[str, str]:
    """SSH to one device and run each (label, command) with send_command
    only. Never issues send_config_set — this function has no write path."""
    from netmiko import ConnectHandler

    out: dict[str, str] = {}
    with ConnectHandler(
        device_type=device_type,
        host=ip,
        username=username,
        password=password,
        timeout=timeout,
        conn_timeout=timeout,
        fast_cli=False,
    ) as conn:
        for label, cmd in commands:
            out[label] = conn.send_command(cmd, read_timeout=timeout) or ""
    return out


# ─────────────────────────── policy-map parsing ────────────────────────────

_RE_CLASS = re.compile(r"^Class-map:\s*(\S.+?)\s*\(match-(any|all)\)\s*$", re.IGNORECASE)
_RE_COUNTS = re.compile(r"^([\d,]+)\s+packets,\s+([\d,]+)\s+bytes\s*$", re.IGNORECASE)
_RE_RATE = re.compile(r"^30 second offered rate\s+(\d+)\s*bps,\s*drop rate\s+(\d+)\s*bps\s*$", re.IGNORECASE)
_RE_MATCH = re.compile(r"^Match:\s*(.+)$", re.IGNORECASE)
_RE_QUEUE_LIMIT = re.compile(r"^queue\s+limit\s+(\d+)\s+packets\s*$", re.IGNORECASE)
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
_RE_SVC_OUTPUT = re.compile(r"^Service policy output:\s*(\S*)\s*$", re.IGNORECASE)
_RE_SVC_NESTED = re.compile(r"^Service policy\s*:\s*(\S+)\s*$", re.IGNORECASE)
_RE_PRIORITY_AGG = re.compile(r"^queue stats for all priority classes:\s*$", re.IGNORECASE)


def _new_class(name: str, match_type: str, indent: int) -> dict:
    return {
        "name": name, "match_type": match_type, "indent": indent,
        "packets": None, "bytes": None,
        "offered_bps": None, "drop_bps": None,
        "matches": [],
        "queue_limit": None, "queue_depth": None, "total_drops": None, "no_buffer_drops": None,
        "pkts_output": None, "bytes_output": None,
        "bandwidth_remaining_pct": None, "bandwidth_kbps": None,
        "priority_pct": None, "priority_kbps": None, "priority_burst_bytes": None, "bw_exceed_drops": None,
        "shape_cir_bps": None, "target_shape_bps": None,
        "shared_priority_queue": False,
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

        if interface_name is None and not stripped.lower().startswith(("service policy", "class-map")):
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
                "queue_limit": None, "queue_depth": None, "total_drops": None,
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
                pending_priority["queue_limit"] = int(m.group(1)); continue
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
            current["queue_limit"] = int(m.group(1)); continue
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


# ─────────────────────────── report rendering ──────────────────────────────

def _fmt_int(n) -> str:
    return f"{n:,}" if n is not None else "n/a"


def _fmt_pct(n) -> str:
    return f"{n:.2f}%" if n is not None else "n/a"


def _bw_config(c: dict) -> str:
    if c["priority_pct"] is not None or c["priority_kbps"] is not None:
        pct = f"{c['priority_pct']}% " if c["priority_pct"] is not None else ""
        return f"priority {pct}({_fmt_int(c['priority_kbps'])} kbps)"
    if c["bandwidth_remaining_pct"] is not None:
        return f"bandwidth remaining {c['bandwidth_remaining_pct']}%"
    if c["bandwidth_kbps"] is not None:
        return f"bandwidth {_fmt_int(c['bandwidth_kbps'])} kbps"
    if c["shape_cir_bps"] is not None:
        return f"shape cir {_fmt_int(c['shape_cir_bps'])} bps"
    return "(none)"


def _display_name(c: dict) -> str:
    if c["name"].lower() == "class-default":
        return "class-default [parent]" if c["depth"] == 0 else "class-default [child default]"
    return c["name"]


def render_report(hostname: str, ip: str, wan_if: str, detection_method: str,
                   parsed: dict, stats: dict, raw_text: str, show_raw: bool,
                   show_detail: bool) -> None:
    classes = stats["classes"]
    print("=" * 88)
    print(f"WAN QoS Queue Report — {hostname} ({ip})")
    print("=" * 88)
    print(f"Interface:        {wan_if}  (detected via: {detection_method})")
    if parsed.get("top_policy_name"):
        print(f"Policy (parent):  {parsed['top_policy_name']}")
    if parsed.get("nested_policy_name"):
        print(f"Policy (nested):  {parsed['nested_policy_name']}")
    print(f"Total traffic:    {_fmt_int(stats['total_traffic_pkts'])} packets (all queues)")
    print(f"Total drops:      {_fmt_int(stats['total_drops'])} packets "
          f"({_fmt_pct((stats['total_drops'] / stats['total_traffic_pkts'] * 100) if stats['total_traffic_pkts'] and stats['total_drops'] is not None else None)} overall)")
    print()

    print("Queue summary:")
    name_w = max(30, max((len(_display_name(c)) for c in classes), default=0) + 2)
    header = f"  {'Queue':<{name_w}}{'% Traffic':>10}{'Depth/Limit':>14}{'Drops':>12}{'Drop% (queue)':>15}{'Drop% (all)':>13}   BW config"
    print(header)
    for c in sorted(classes, key=lambda c: c["depth"]):
        depth_lo = c["queue_depth"] if c["queue_depth"] is not None else "?"
        limit = c["queue_limit"] if c["queue_limit"] is not None else "?"
        row = (
            f"  {_display_name(c):<{name_w}}"
            f"{_fmt_pct(c['pct_of_total_traffic']):>10}"
            f"{f'{depth_lo}/{limit}':>14}"
            f"{_fmt_int(c['total_drops']):>12}"
            f"{_fmt_pct(c['drop_pct_of_queue']):>15}"
            f"{_fmt_pct(c['share_of_total_drops']):>13}   "
            f"{_bw_config(c)}"
        )
        print(row)
    print()

    if show_detail:
        print("Detail per queue:")
        for c in sorted(classes, key=lambda c: c["depth"]):
            print(f"  [{_display_name(c)}] (match-{c['match_type']})")
            if c["matches"]:
                print(f"    Matches:      {', '.join(c['matches'])}")
            print(f"    Traffic:      {_fmt_int(c['packets'])} pkts / {_fmt_int(c['bytes'])} bytes"
                  f"  ({_fmt_pct(c['pct_of_total_traffic'])} of interface total)")
            print(f"    30s rate:     {_fmt_int(c['offered_bps'])} bps offered / {_fmt_int(c['drop_bps'])} bps dropped"
                  f"  ({_fmt_pct(c['instant_drop_pct'])} instantaneous)")
            note = "  [shared priority (LLQ) queue]" if c["shared_priority_queue"] else ""
            print(f"    Queue:        depth {_fmt_int(c['queue_depth'])} / limit {_fmt_int(c['queue_limit'])} packets"
                  f"  ({_fmt_pct(c['queue_fill_pct'])} full){note}")
            print(f"    Drops:        {_fmt_int(c['total_drops'])} total, {_fmt_int(c['no_buffer_drops'])} no-buffer"
                  f"  ({_fmt_pct(c['drop_pct_of_queue'])} of this queue's traffic,"
                  f" {_fmt_pct(c['share_of_total_drops'])} of all interface drops)")
            print(f"    Output:       {_fmt_int(c['pkts_output'])} pkts / {_fmt_int(c['bytes_output'])} bytes")
            cfg_bits = [_bw_config(c)]
            if c["priority_burst_bytes"] is not None:
                cfg_bits.append(f"burst {_fmt_int(c['priority_burst_bytes'])} bytes")
            if c["bw_exceed_drops"] is not None:
                cfg_bits.append(f"b/w exceed drops {_fmt_int(c['bw_exceed_drops'])}")
            if c["target_shape_bps"] is not None:
                cfg_bits.append(f"target shape {_fmt_int(c['target_shape_bps'])} bps")
            print(f"    Config:       {', '.join(cfg_bits)}")
            print()

    if show_raw:
        print("Raw CLI output:")
        print("-" * 88)
        print(raw_text)
        print("-" * 88)


# ─────────────────────────── main ───────────────────────────────────────────

def process_device(dnac, device: dict, args) -> int:
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
        logger.error("%s: resolved interface name '%s' failed validation — refusing to use it", hostname, wan_if)
        return 1

    logger.info("%s (%s): WAN interface %s [%s]", hostname, ip, wan_if, method)

    device_type = guess_device_type(device.get("platformId", ""))
    commands = [
        ("policy", f"show policy-map interface {wan_if} output"),
    ]

    logger.info("%s: connecting via SSH...", hostname)
    try:
        raw = ssh_run_commands(ip, args.username, args.password, device_type, commands, args.timeout)
    except Exception as e:
        logger.error("%s: SSH failed — %s: %s", hostname, type(e).__name__, str(e)[:200])
        return 1

    policy_text = raw.get("policy", "")
    if not policy_text.strip():
        logger.error("%s: empty output for 'show policy-map interface %s output' — "
                      "no service-policy applied, or wrong interface name?", hostname, wan_if)
        return 1

    parsed = parse_policy_map(policy_text)
    stats = compute_stats(parsed)
    render_report(
        hostname, ip, wan_if, method, parsed, stats,
        policy_text, args.raw, args.detail,
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Read-only WAN queue/QoS report for a site's border router(s).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("site", nargs="?", help="Site name (DNAC site hierarchy, substring match)")
    ap.add_argument("--device", help="Skip site/role lookup; target this device directly "
                                      "(hostname or management-IP substring, matched fleet-wide)")
    ap.add_argument("--role", default=DEFAULT_ROLE,
                     help=f"DNAC device role to treat as the border router (substring match, "
                          f"case-insensitive; default: {DEFAULT_ROLE!r})")
    ap.add_argument("--interface", help="Skip WAN-interface auto-detection; use this interface name directly")
    ap.add_argument("--tag-name", default=DEFAULT_TAG_NAME,
                     help=f"DNAC tag that marks a WAN interface (default: {DEFAULT_TAG_NAME})")
    ap.add_argument("--vrf", default=",".join(DEFAULT_VRFS),
                     help=f"Comma-separated VRF names used as the WAN-detection fallback "
                          f"(default: {','.join(DEFAULT_VRFS)})")
    ap.add_argument("--username", default=os.getenv("DOMAIN_USERNAME", ""),
                     help="SSH username (default: DOMAIN_USERNAME from .env)")
    ap.add_argument("--password", default=os.getenv("DOMAIN_PASSWORD", ""),
                     help="SSH password (default: DOMAIN_PASSWORD from .env)")
    ap.add_argument("--timeout", type=int, default=SSH_TIMEOUT, help=f"SSH timeout in seconds (default: {SSH_TIMEOUT})")
    ap.add_argument("--detail", action="store_true",
                     help="Also print the per-queue detail section (matches, 30s rate, config, ...) "
                          "below the queue summary table. Off by default so the summary — the part "
                          "usually being read — doesn't scroll off screen.")
    ap.add_argument("--raw", action="store_true", help="Also print the raw CLI output")
    ap.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        # This script's own logger.info() calls are the one-line-per-step
        # progress output ("Querying DNAC...", "connecting via SSH...", ...).
        # clients.dnac and netmiko/paramiko log their own routine internals
        # at the same INFO/DEBUG levels (per-page DNAC fetches, the SSH
        # connection/auth handshake) — quiet those specifically rather than
        # dropping INFO globally, so this script's steps still show.
        logging.getLogger("clients.dnac").setLevel(logging.WARNING)
        logging.getLogger("netmiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if not args.site and not args.device:
        ap.error("either SITE or --device is required")
    if not args.username or not args.password:
        logger.error("No SSH credentials — set DOMAIN_USERNAME/DOMAIN_PASSWORD in .env or pass --username/--password")
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
            logger.error("No device with role matching '%s' found at site '%s'", args.role, site_name)
            return 1

    logger.info("Target device(s): %s", ", ".join(d.get("hostname") or d.get("id") for d in targets))

    failures = 0
    for device in targets:
        failures += process_device(dnac, device, args)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
