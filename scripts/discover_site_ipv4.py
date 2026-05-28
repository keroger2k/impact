#!/usr/bin/env python3
"""scripts/discover_site_ipv4.py — Discover each IPv6 registry site's IPv4 supernet.

For every site in the IPv6 registry, scans the warmed DNAC/IPAM caches
enterprise-wide and reports candidate IPv4 supernets so the new
`sites.ipv4_supernet` column can be populated.

Discovery sources, per site:
  * DNAC interfaces (`dnac_interfaces` cache) — every IPv4-bearing
    interface on every device whose site-hierarchy path resolves to this
    site (matched via `utils.site_code.site_code_strict` against the
    registry site name).
  * DNAC reserve IP subpools (`dnac_reserve_subpools` cache) — every IPv4
    sub-pool whose `siteName` matches.
  * DNAC global IP pools (`dnac_global_pools` cache) — included only as
    additional context (no site attribution).

For each registry site, the script prints:
  * the suggested supernet (smallest CIDR covering all discovered v4s)
  * the per-source breakdown (interface /24s vs. pool CIDRs)
  * any DNAC sites / pools that matched by site-code OR fuzzy name

Dry-run by default; `--apply` writes the suggested supernet to
`sites.ipv4_supernet` (only when the column is currently empty — won't
overwrite a value an operator already set unless `--force` is passed).

Requires the DNAC caches to be warmed (run the app and POST `/api/warm`
or visit `/cache-mgmt` first). The script never makes live API calls.

Run from the repo root:

    .venv/bin/python -m scripts.discover_site_ipv4              # dry-run
    .venv/bin/python -m scripts.discover_site_ipv4 --apply      # commit suggestions
    .venv/bin/python -m scripts.discover_site_ipv4 --apply --force  # overwrite existing
    .venv/bin/python -m scripts.discover_site_ipv4 --site K024      # one site only
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cache import cache as app_cache  # noqa: E402
from clients import ipv6_registry as registry  # noqa: E402
from utils.site_code import site_code_strict  # noqa: E402


def _smallest_covering_cidr(networks: list[ipaddress.IPv4Network]) -> ipaddress.IPv4Network | None:
    """Return the smallest IPv4Network containing every input network.

    Computes the common-prefix length between the lowest network address
    and the highest broadcast address. None on empty input."""
    if not networks:
        return None
    lo = min(int(n.network_address) for n in networks)
    hi = max(int(n.broadcast_address) for n in networks)
    if lo == hi:
        return ipaddress.IPv4Network((lo, 32))
    diff = lo ^ hi
    # diff.bit_length() = position of the highest differing bit (1-indexed
    # from the LSB). The smallest covering prefix is 32 - that.
    prefix = 32 - diff.bit_length()
    base = lo & (((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1))
    return ipaddress.IPv4Network((base, prefix))


def _collect_dnac_interface_subnets(
    target_device_ids: set[str],
    dnac_interfaces: list[dict],
) -> list[tuple[ipaddress.IPv4Network, dict]]:
    """Return (network, context) for every IPv4 interface on a matched
    device. `context` carries hostname/portName/site for the per-source
    breakdown printout."""
    out: list[tuple[ipaddress.IPv4Network, dict]] = []
    for iface in dnac_interfaces:
        dev_id = iface.get("deviceId")
        if dev_id not in target_device_ids:
            continue
        addr = iface.get("ipv4Address")
        mask = iface.get("ipv4Mask")
        if not addr or not mask:
            continue
        try:
            net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue
        # Skip loopbacks / point-to-point bookkeeping — they bloat the
        # covering supernet without adding real allocation info.
        if net.prefixlen >= 30:
            continue
        out.append((net, {
            "device": iface.get("deviceName") or iface.get("deviceId"),
            "port": iface.get("portName"),
        }))
    return out


def _collect_dnac_pool_subnets(
    site_code: str,
    site_name_lc: str,
    subpools: list[dict],
) -> list[tuple[ipaddress.IPv4Network, dict]]:
    """Return (network, context) for every IPv4 reserve subpool whose
    siteName matches this registry site by code OR name substring."""
    out: list[tuple[ipaddress.IPv4Network, dict]] = []
    target_code = site_code.upper() if site_code else ""
    for sp in subpools:
        sp_site = (sp.get("siteName") or sp.get("groupName") or "")
        sp_code = site_code_strict(sp_site).upper()
        matched_by_code = bool(target_code) and sp_code == target_code
        matched_by_name = bool(site_name_lc) and site_name_lc in sp_site.lower()
        if not (matched_by_code or matched_by_name):
            continue
        for ip_pool in (sp.get("ipPools") or []):
            cidr_str = ip_pool.get("ipPoolCidr") or ip_pool.get("cidr")
            if not cidr_str or ":" in cidr_str:  # skip v6 pools
                continue
            try:
                net = ipaddress.IPv4Network(cidr_str, strict=False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                continue
            out.append((net, {
                "pool_name": ip_pool.get("ipPoolName") or sp.get("groupName") or "",
                "site_name": sp_site,
                "match": "code" if matched_by_code else "name",
            }))
    return out


def _devices_for_site(
    site_code: str,
    site_name_lc: str,
    device_site_map: dict,
) -> tuple[set[str], list[str]]:
    """Find every device whose hierarchy path matches this registry site.
    Returns (device_id_set, matched_site_paths). Code match first; name
    substring fallback for sites that don't carry an extractable code."""
    out: set[str] = set()
    paths: set[str] = set()
    target_code = site_code.upper() if site_code else ""
    for dev_id, site_path in device_site_map.items():
        path = site_path or ""
        path_code = site_code_strict(path).upper()
        matched_by_code = bool(target_code) and path_code == target_code
        matched_by_name = bool(site_name_lc) and site_name_lc in path.lower()
        if matched_by_code or matched_by_name:
            out.add(dev_id)
            paths.add(path)
    return out, sorted(paths)


def _format_breakdown(label: str, items: list[tuple[ipaddress.IPv4Network, dict]],
                      *, limit: int = 5) -> str:
    """Pretty-print a per-source breakdown, with /24-rollup so dozens of
    SVI host networks render as one line per /24 instead of 40 lines."""
    if not items:
        return f"    {label}: (none)"
    # Group by the /24 of each network so a site with VLAN3/100/600/700/800
    # all in 10.4.30.0/22 still shows up as a tight 4-line summary.
    by_supernet: dict[str, list[tuple[ipaddress.IPv4Network, dict]]] = defaultdict(list)
    for net, ctx in items:
        if net.prefixlen >= 24:
            key = str(ipaddress.IPv4Network((int(net.network_address) & 0xFFFFFF00, 24)))
        else:
            key = str(net)
        by_supernet[key].append((net, ctx))
    lines = [f"    {label}: {len(items)} subnet(s) across {len(by_supernet)} /24(s)"]
    for slot, members in sorted(by_supernet.items())[:limit]:
        examples = ", ".join(str(n) for n, _ in members[:3])
        more = f" (+{len(members) - 3} more)" if len(members) > 3 else ""
        lines.append(f"      • {slot}  ← {examples}{more}")
    if len(by_supernet) > limit:
        lines.append(f"      … and {len(by_supernet) - limit} more /24(s)")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true",
                    help="Write the suggested supernet to sites with no existing value")
    ap.add_argument("--force", action="store_true",
                    help="With --apply: overwrite even when ipv4_supernet is already set")
    ap.add_argument("--site", default=None,
                    help="Limit to the registry site whose name contains this string (case-insensitive)")
    args = ap.parse_args()

    device_site_map = app_cache.get("device_site_map") or {}
    dnac_interfaces = app_cache.get("dnac_interfaces") or []
    subpools = app_cache.get("dnac_reserve_subpools") or []

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] enterprise scan")
    print(f"        cache: device_site_map={len(device_site_map)} entries, "
          f"dnac_interfaces={len(dnac_interfaces)} entries, "
          f"dnac_reserve_subpools={len(subpools)} entries")
    if not device_site_map or not dnac_interfaces:
        print("        WARNING: DNAC caches empty. Warm DNAC (sites/devices/interfaces) "
              "via /cache-mgmt before re-running.")

    registry.init_schema()
    sites = registry.list_sites()
    if args.site:
        needle = args.site.lower()
        sites = [s for s in sites if needle in (s["name"] or "").lower()]
        if not sites:
            print(f"\nNo registry site matched --site '{args.site}'.", file=sys.stderr)
            return 1
    print(f"        scanning {len(sites)} registry site(s)\n")

    stats = {
        "would_update": 0,
        "updated": 0,
        "skipped_no_match": 0,
        "skipped_existing": 0,
    }

    for site in sites:
        name = site["name"]
        code = site_code_strict(name)
        name_lc = name.lower()
        existing = site.get("ipv4_supernet") or ""
        print(f"── {name}  ({site['prefix']}::/{site['prefix_length']})  "
              f"code={code or '(none)'}  existing={existing or '(empty)'}")

        device_ids, matched_paths = _devices_for_site(code, name_lc, device_site_map)
        iface_nets = _collect_dnac_interface_subnets(device_ids, dnac_interfaces)
        pool_nets = _collect_dnac_pool_subnets(code, name_lc, subpools)

        all_nets = [n for n, _ in iface_nets] + [n for n, _ in pool_nets]
        suggested = _smallest_covering_cidr(all_nets) if all_nets else None

        if matched_paths:
            preview = ", ".join(matched_paths[:3])
            more = f" (+{len(matched_paths) - 3} more)" if len(matched_paths) > 3 else ""
            print(f"    matched DNAC paths: {preview}{more}")
        else:
            print(f"    matched DNAC paths: (none)")

        print(_format_breakdown("DNAC interfaces", iface_nets))
        print(_format_breakdown("DNAC reserve subpools",
                                [(n, c) for n, c in pool_nets]))

        if suggested is None:
            print(f"    SUGGESTION:    (no IPv4 found — nothing to apply)\n")
            stats["skipped_no_match"] += 1
            continue

        print(f"    SUGGESTION:    {suggested}  "
              f"(covers {len(all_nets)} discovered net(s))")

        if not args.apply:
            print()
            stats["would_update"] += 1
            continue

        if existing and not args.force:
            print(f"    SKIP-EXISTS    site already has ipv4_supernet — pass --force to overwrite\n")
            stats["skipped_existing"] += 1
            continue

        registry.update_site(site["id"], ipv4_supernet=str(suggested))
        print(f"    UPDATED        sites.ipv4_supernet = {suggested}\n")
        stats["updated"] += 1

    print(f"[{mode}] summary:")
    for k, v in stats.items():
        if v:
            print(f"  {k:<18} {v}")
    if not args.apply:
        print("\nDry-run complete. Re-run with --apply to write suggestions "
              "into the registry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
