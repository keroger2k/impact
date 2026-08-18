#!/usr/bin/env python3
"""scripts/tag_c8k_wan_interfaces.py — tag Catalyst 8000 series WAN uplinks.

Applies a DNAC tag (default "WAN") to the *physical* interface carrying WAN
traffic on every Catalyst 8000 series router (C8200/C8300/C8500 hardware,
C8000V virtual) in DNAC's inventory.

"WAN interface" here means: an interface whose VRF forwarding is "WAN" or
"INTERNET" (exact match, case-insensitive; override with --vrf). That VRF
assignment is commonly made on a sub-interface (e.g.
GigabitEthernet0/0/1.100 carrying `vrf forwarding INTERNET`) rather than the
parent — but the tag always goes on the physical parent
(GigabitEthernet0/0/1), never the sub-interface, per how this fleet is
actually addressed. Non-physical interface types that can carry a VRF
(Tunnel, Loopback, Vlan, Port-channel, Virtual-Template/Access, BDI) are
deliberately never tagged even if they match the VRF — the ask is the
physical WAN uplink, not every VRF member.

Device identification is automatic: DNAC's device inventory is filtered by
`platformId` (falling back to `series` when platformId is blank) against the
Catalyst 8000 family. No device list file needed. Every matched device is
printed before anything is written, so a run is easy to sanity-check before
--apply.

VRF membership is read from DNAC's own cached running-config for each device
(`GET /network-device/{id}/config` — the same source config-search and the
device-detail config viewer use), fetched live at run time, not from the
app's disk cache. Reuses the IOS config block-walker from
utils.ipsec_parser (_iter_blocks/_block_lines/_RE_INTERFACE) rather than
duplicating that parsing — same precedent as utils/swim_site_circuit.py.

Tagging itself goes through clients.dnac.tag_interfaces(), which calls
DNAC's single-tag `POST /tag/{id}/member` endpoint (add_members_to_the_tag)
rather than the bulk membership-replace endpoint — see that function's
docstring for why: these interfaces likely already carry other tags, and
only the single-tag endpoint is guaranteed not to touch them. The script
also reads the tag's current membership first and skips anything already
tagged, so a re-run is a no-op for interfaces already done.

Dry-run by default, same posture as every other script here — prints every
device, every interface it would tag, and why anything was skipped. Pass
--apply to actually create the tag (if needed) and write it to interfaces.

Auth: uses the app's shared service account (DOMAIN_USERNAME/DOMAIN_PASSWORD
in .env — same creds clients.dnac.get_client() uses for cache warming), not
a per-user login. That account needs DNAC RBAC permission to create/assign
tags for --apply to succeed.

Usage:
    .venv/bin/python -m scripts.tag_c8k_wan_interfaces                       # dry-run, fleet-wide
    .venv/bin/python -m scripts.tag_c8k_wan_interfaces --device RTR-DCA-01   # dry-run, one device
    .venv/bin/python -m scripts.tag_c8k_wan_interfaces --site DCA            # dry-run, hostname substring
    .venv/bin/python -m scripts.tag_c8k_wan_interfaces --apply               # commit, fleet-wide
    .venv/bin/python -m scripts.tag_c8k_wan_interfaces --tag-name WAN-EDGE --vrf WAN,INTERNET,INET --apply
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import clients.dnac as dc  # noqa: E402
from clients.dnac import _dictify  # noqa: E402
from utils.ipsec_parser import _RE_INTERFACE, _block_lines, _iter_blocks  # noqa: E402

# Catalyst 8000 family: C8200/C8200L, C8300, C8500/C8500L hardware, C8000V
# virtual. Matches on the ordering PID (platformId) — precise and doesn't
# depend on how `family`/`series` happen to be worded in this DNAC instance.
_C8K_PLATFORM_RE = re.compile(r"^C8(200|300|500|000V)", re.IGNORECASE)
# Fallback for inventory rows with a blank platformId — matches the `series`
# string instead (e.g. "Cisco Catalyst 8300 Series Edge Platforms").
_C8K_SERIES_RE = re.compile(r"Catalyst\s+8(200|300|500|000V)", re.IGNORECASE)

_VRF_FORWARDING_RE = re.compile(r"^(?:ip\s+vrf\s+forwarding|vrf\s+forwarding)\s+(\S+)", re.IGNORECASE)

# Interface types this fleet actually terminates a WAN circuit on. Anything
# else that can carry a VRF (Tunnel, Loopback, Vlan, Port-channel,
# Virtual-Template/Access, BDI) is logical, not physical, and is never a
# tagging target even if it matches the VRF.
_PHYSICAL_TYPES = (
    "GigabitEthernet", "TenGigabitEthernet", "TenGigE", "TwentyFiveGigE",
    "FortyGigabitEthernet", "FortyGigE", "HundredGigE", "FastEthernet",
    "Ethernet", "Serial",
)

DEFAULT_TAG_NAME = "WAN"
DEFAULT_VRFS = ["WAN", "INTERNET"]

_TAG_MEMBER_PAGE = 500


def is_c8k(device: dict) -> bool:
    platform_id = (device.get("platformId") or "").strip()
    if platform_id:
        return bool(_C8K_PLATFORM_RE.match(platform_id))
    series = (device.get("series") or "").strip()
    return bool(_C8K_SERIES_RE.search(series))


def physical_parent(interface_name: str) -> str | None:
    """The physical interface a (possibly sub-) interface name hangs off of,
    or None if `interface_name` isn't a physical interface type at all."""
    base = interface_name.split(".", 1)[0]
    lower = base.lower()
    if any(lower.startswith(p.lower()) for p in _PHYSICAL_TYPES):
        return base
    return None


def vrf_wan_hits(config: str, target_vrfs: set[str]) -> list[tuple[str, str]]:
    """Every (interface_name, vrf_name) pair in `config` whose vrf forwarding
    matches target_vrfs (case-insensitive exact match) — physical or not;
    physical-filtering happens in the caller so it can log what got skipped
    and why."""
    if not config:
        return []
    lines = list(_iter_blocks(config))
    hits: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        indent, stripped, _ = lines[i]
        if indent != 0:
            i += 1
            continue
        m = _RE_INTERFACE.match(stripped)
        if not m:
            i += 1
            continue
        name = m.group(1)
        children, i = _block_lines(lines, i + 1)
        for line in children:
            vm = _VRF_FORWARDING_RE.match(line)
            if vm and vm.group(1).upper() in target_vrfs:
                hits.append((name, vm.group(1)))
                break
    return hits


def fetch_tagged_interface_ids(dnac, tag_id: str) -> set[str]:
    """Interface IDs already members of tag_id — paginated, so a re-run
    skips writing to interfaces that are already tagged."""
    tagged: set[str] = set()
    offset = 1
    while True:
        try:
            resp = dnac.tag.get_tag_members_by_id(
                id=tag_id, member_type="interface", limit=_TAG_MEMBER_PAGE, offset=offset
            )
        except Exception as e:
            print(f"    WARNING: could not read existing tag membership ({e}) — "
                  f"treating all matches as untagged", file=sys.stderr)
            return tagged
        items = getattr(resp, "response", None) or []
        if not items:
            break
        for item in items:
            d = _dictify(item)
            if d.get("id"):
                tagged.add(d["id"])
        if len(items) < _TAG_MEMBER_PAGE:
            break
        offset += _TAG_MEMBER_PAGE
    return tagged


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Tag the physical WAN uplink on every Catalyst 8000 series router in DNAC.",
    )
    ap.add_argument("--apply", action="store_true",
                     help="Actually create the tag (if needed) and write it to interfaces. Default: dry-run.")
    ap.add_argument("--tag-name", default=DEFAULT_TAG_NAME,
                     help=f"DNAC tag to apply (default: {DEFAULT_TAG_NAME})")
    ap.add_argument("--vrf", default=",".join(DEFAULT_VRFS),
                     help=f"Comma-separated VRF names that mark an interface as WAN "
                          f"(exact match, case-insensitive; default: {','.join(DEFAULT_VRFS)})")
    ap.add_argument("--site", default=None,
                     help="Limit to devices whose hostname contains this string (case-insensitive)")
    ap.add_argument("--device", default=None,
                     help="Limit to a single device — hostname or management IP substring")
    args = ap.parse_args()

    target_vrfs = {v.strip().upper() for v in args.vrf.split(",") if v.strip()}
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] tag='{args.tag_name}'  vrfs={sorted(target_vrfs)}")

    dnac = dc.get_client()

    print("Fetching DNAC device inventory...")
    devices = dc.get_all_devices(dnac, strict=True)
    candidates = [d for d in devices if is_c8k(d)]
    print(f"  {len(devices)} devices total, {len(candidates)} match the Catalyst 8000 family")

    if args.site:
        needle = args.site.lower()
        candidates = [d for d in candidates if needle in (d.get("hostname") or "").lower()]
        print(f"  --site '{args.site}' narrows to {len(candidates)} device(s)")
    if args.device:
        needle = args.device.lower()
        candidates = [
            d for d in candidates
            if needle in (d.get("hostname") or "").lower()
            or needle in (d.get("managementIpAddress") or "").lower()
        ]
        print(f"  --device '{args.device}' narrows to {len(candidates)} device(s)")

    if not candidates:
        print("\nNo matching devices. Nothing to do.")
        return 0

    print("\nMatched devices:")
    for d in candidates:
        host = d.get("hostname") or "(no hostname)"
        ip = d.get("managementIpAddress") or "(no IP)"
        print(f"  • {host:<32} {ip:<16} "
              f"{d.get('platformId') or d.get('series') or '(unknown platform)'}")

    # Resolve the tag WITHOUT creating it in dry-run mode — get_or_create_tag
    # would create a real tag as a side effect of a "what would happen" run.
    tag_id: str | None = None
    if args.apply:
        print(f"\nResolving tag '{args.tag_name}'...")
        tag_id = dc.get_or_create_tag(dnac, args.tag_name)
        print(f"  tag id: {tag_id}")
    else:
        resp = dnac.tag.get_tag(name=args.tag_name)
        items = [_dictify(t) for t in (getattr(resp, "response", None) or [])]
        match = next((t for t in items if t.get("name") == args.tag_name), None)
        if match:
            tag_id = match["id"]
            print(f"\nTag '{args.tag_name}' already exists (id: {tag_id})")
        else:
            print(f"\nTag '{args.tag_name}' does not exist yet — --apply would create it")

    already_tagged: set[str] = set()
    if tag_id:
        already_tagged = fetch_tagged_interface_ids(dnac, tag_id)
        print(f"  {len(already_tagged)} interface(s) already tagged '{args.tag_name}'")

    stats = {
        "vrf_hits_physical": 0,
        "vrf_hits_non_physical_skipped": 0,
        "already_tagged": 0,
        "newly_tagged": 0,
        "not_found_in_dnac": 0,
        "no_config": 0,
        "no_wan_vrf": 0,
    }
    to_tag: list[tuple[str, str, str]] = []  # (hostname, ifname, interface_id) for the closing summary

    print("\nScanning device configs for VRF-forwarding interfaces...")
    for d in candidates:
        device_id = d.get("id")
        hostname = d.get("hostname") or device_id
        config = dc.get_device_config(dnac, device_id)
        if not config:
            print(f"  {hostname}: no config available — skipped")
            stats["no_config"] += 1
            continue

        hits = vrf_wan_hits(config, target_vrfs)
        if not hits:
            print(f"  {hostname}: no {sorted(target_vrfs)} VRF interfaces found")
            stats["no_wan_vrf"] += 1
            continue

        physical_names: dict[str, str] = {}  # physical name -> originating (sub)interface + vrf, for logging
        for ifname, vrf in hits:
            parent = physical_parent(ifname)
            if parent is None:
                print(f"  {hostname}: {ifname} (vrf {vrf}) is not a physical interface type — skipped")
                stats["vrf_hits_non_physical_skipped"] += 1
                continue
            stats["vrf_hits_physical"] += 1
            note = ifname if parent == ifname else f"{ifname} -> {parent}"
            physical_names.setdefault(parent, note)

        if not physical_names:
            continue

        device_interfaces = dc.get_device_interfaces(dnac, device_id)
        by_name = {(i.get("portName") or "").lower(): i for i in device_interfaces}

        for parent, note in sorted(physical_names.items()):
            iface = by_name.get(parent.lower())
            if not iface or not iface.get("id"):
                print(f"  {hostname}: {parent} ({note}) not found in DNAC interface inventory — skipped")
                stats["not_found_in_dnac"] += 1
                continue
            iface_id = iface["id"]
            if iface_id in already_tagged:
                print(f"  {hostname}: {parent} ({note}) already tagged '{args.tag_name}'")
                stats["already_tagged"] += 1
                continue
            verb = "tagging" if args.apply else "would tag"
            print(f"  {hostname}: {parent} ({note}) — {verb} '{args.tag_name}'")
            to_tag.append((hostname, parent, iface_id))

    if args.apply and to_tag:
        print(f"\nApplying tag '{args.tag_name}' to {len(to_tag)} interface(s)...")
        ids = [iface_id for _, _, iface_id in to_tag]
        # Batch defensively — DNAC's own member-add pagination caps at 500.
        for start in range(0, len(ids), 500):
            batch = ids[start:start + 500]
            dc.tag_interfaces(dnac, tag_id, batch)
        stats["newly_tagged"] = len(to_tag)
        print("  done.")
    elif to_tag:
        stats["newly_tagged"] = len(to_tag)

    print(f"\n[{mode}] summary:")
    for k, v in stats.items():
        if v:
            print(f"  {k:<28} {v}")

    if not args.apply and to_tag:
        print(f"\nDry-run complete. Re-run with --apply to tag "
              f"{len(to_tag)} interface(s) '{args.tag_name}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
