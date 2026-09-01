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
     interface drops, the delay a full queue would impose, and configured
     priority/bandwidth) — this table is the report's primary output and
     always prints. A "Detail per queue" section with the same data broken
     out per-queue (matches, 30s offered/drop rate, output counters, full
     config) is opt-in via --detail: it's long enough on a multi-queue
     policy-map to push the summary table off screen, so it stays hidden
     unless asked for.

The "Full queue" column exists because a queue-limit in packets doesn't
say what it costs. 4096 packets looks like headroom; at a class's guaranteed
share of a 42.5 Mbps shaper it is seconds of delay, and raising queue-limit
to make drops go away trades a loss problem for a latency one without
changing any number this report previously showed. The column is computed
from the class's cumulative counters, so it is a single-snapshot estimate —
scripts/wan_queue_latency.py samples the same interface over a window and
reports the *measured* drain rate, standing queue and windowed drop rate
instead. Reach for that one when this report says "no drops" and users still
say the site is slow.

Parsing and the queue-delay math live in utils/wan_qos.py so this script and
wan_queue_latency.py can't drift; this file keeps the DNAC target resolution,
the CLI and the rendering.

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
from utils.device_ssh import guess_device_type, ssh_run_commands  # noqa: E402
from utils.wan_qos import (  # noqa: E402
    compute_stats,
    full_queue_delay_ms,
    guaranteed_bps,
    parent_shape_bps,
    parse_policy_map,
    total_priority_bps,
)
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


# ─────────────────────────── report rendering ──────────────────────────────

def _fmt_int(n) -> str:
    return f"{n:,}" if n is not None else "n/a"


def _fmt_pct(n) -> str:
    return f"{n:.2f}%" if n is not None else "n/a"


def _fmt_delay(ms) -> str:
    """Queue delay, in whichever unit keeps it readable. These span five
    orders of magnitude on one table — a shallow LLQ measures in single-digit
    ms while a 4096-packet scavenger queue measures in tens of seconds — and
    printing "33043.4 ms" next to "4.2 ms" makes the outlier harder to spot,
    not easier."""
    if ms is None:
        return "n/a"
    if ms >= 10_000:
        return f"{ms / 1000:.0f} s"
    if ms >= 1_000:
        return f"{ms / 1000:.1f} s"
    return f"{ms:.0f} ms"


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

    # "Full queue" is the delay this class's *configured* queue-limit permits
    # at its guaranteed drain rate. It is the column that makes a deep buffer
    # legible: "4096 packets" reads as fine until it reads as "2.7 s". Packet
    # size comes from the class's own cumulative counters here (a single
    # snapshot has no window to average over) — scripts/wan_queue_latency.py
    # samples over time and reports the measured figure instead.
    shape_bps = parent_shape_bps(parsed)
    prio_bps = total_priority_bps(parsed)

    print("Queue summary:")
    name_w = max(30, max((len(_display_name(c)) for c in classes), default=0) + 2)
    header = (f"  {'Queue':<{name_w}}{'% Traffic':>10}{'Depth/Limit':>14}{'Drops':>12}"
              f"{'Drop% (queue)':>15}{'Drop% (all)':>13}{'Full queue':>12}   BW config")
    print(header)
    for c in sorted(classes, key=lambda c: c["depth"]):
        depth_lo = c["queue_depth"] if c["queue_depth"] is not None else "?"
        limit = c["queue_limit"] if c["queue_limit"] is not None else "?"
        pkt_bytes = (c["bytes_output"] / c["pkts_output"]) if c.get("pkts_output") else None
        drain = guaranteed_bps(c, shape_bps, prio_bps)
        row = (
            f"  {_display_name(c):<{name_w}}"
            f"{_fmt_pct(c['pct_of_total_traffic']):>10}"
            f"{f'{depth_lo}/{limit}':>14}"
            f"{_fmt_int(c['total_drops']):>12}"
            f"{_fmt_pct(c['drop_pct_of_queue']):>15}"
            f"{_fmt_pct(c['share_of_total_drops']):>13}"
            f"{_fmt_delay(full_queue_delay_ms(c, pkt_bytes, drain)):>12}   "
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
        raw = ssh_run_commands(ip, args.username, args.password, device_type, commands,
                               args.timeout, required=("policy",))
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
