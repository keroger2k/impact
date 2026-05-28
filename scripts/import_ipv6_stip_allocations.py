#!/usr/bin/env python3
"""scripts/import_ipv6_stip_allocations.py — Bulk-import STIP /64 allocations.

CSV format (header row optional):

    Site Code,STIP Prefix,STIP VLAN
    I002,2600:0400:3059:,0001
    K015,2600:0400:3059:,0002

For each row:
  * Resolves the STIP /48 aggregate site in the Registry by matching
    `STIP Prefix` against existing /48 sites (normalized).
  * Looks up the site's IPv4 VLAN500 subnet from the warmed `dnac_interfaces`
    cache (scans all devices in DNAC sites whose name carries `Site Code`).
  * Creates a /64 allocation under the STIP /48 with vvvv = `STIP VLAN`.
    If the IPv4 lookup fails, the allocation is still created (no `ipv4_subnet`).

Dry-run by default; `--apply` to commit. The DNAC caches must be warmed
beforehand — run the app and warm DNAC interfaces/sites/devices via
`/cache-mgmt` (or POST `/api/warm`) before invoking this script.

Run from the repo root:

    .venv/bin/python -m scripts.import_ipv6_stip_allocations              # dry-run
    .venv/bin/python -m scripts.import_ipv6_stip_allocations --apply      # commit
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

# Allow `python scripts/import_ipv6_stip_allocations.py` to import project modules.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cache import cache as app_cache  # noqa: E402
from clients import ipv6_registry as registry  # noqa: E402
from utils import ipv6_assembler as ipv6  # noqa: E402
from utils.site_code import site_code_strict  # noqa: E402

STIP_PREFIX_LENGTH = 64  # every STIP allocation is a /64
STIP_VLAN_LABEL = "Vlan500"  # what Cisco IOS / DNAC names the SVI


def _normalize_stip_prefix(raw: str) -> str:
    """`2600:0400:3059:` or `2600:400:3059` → canonical 3-hextet form for a /48."""
    return ipv6.normalize_prefix(raw.rstrip(":"), 48)


def _find_stip_aggregate(prefix_48_norm: str) -> dict | None:
    """Return the /48 Registry site whose normalized prefix matches `prefix_48_norm`."""
    for s in registry.list_sites():
        if int(s.get("prefix_length", 48)) != 48:
            continue
        if ipv6.normalize_prefix(s["prefix"], 48) == prefix_48_norm:
            return s
    return None


def _find_vlan500_subnet(site_code: str,
                         device_site_map: dict,
                         dnac_interfaces: list[dict]) -> tuple[str | None, str]:
    """Resolve `site_code`'s VLAN500 IPv4 subnet from cached DNAC data.

    Returns (cidr, detail). `cidr` is None if no match; `detail` is a short
    explanation for the log (e.g., "no devices at this site", "found on
    SW-FOO-01"). Picks the first matching SVI; logs the device name.
    """
    target = site_code.upper()
    # Devices at this site (uppercased site_code match against the site path).
    matching_device_ids = {
        dev_id for dev_id, site_path in device_site_map.items()
        if site_code_strict(site_path or "").upper() == target
    }
    if not matching_device_ids:
        return None, f"no devices at site {site_code} in device_site_map"

    for iface in dnac_interfaces:
        if iface.get("deviceId") not in matching_device_ids:
            continue
        port = (iface.get("portName") or "").strip().lower().replace(" ", "")
        if port != "vlan500":
            continue
        addr = iface.get("ipv4Address")
        mask = iface.get("ipv4Mask")
        if not addr or not mask:
            continue
        try:
            net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        return str(net), f"from {iface.get('deviceName') or iface.get('deviceId')}"
    return None, f"Vlan500 SVI not found on any device at {site_code}"


def _parse_rows(path: Path):
    """Yield (lineno, site_code, stip_prefix_raw, vvvv_normalized)."""
    with path.open(newline="") as f:
        reader = csv.reader(f)
        for lineno, row in enumerate(reader, 1):
            if not row:
                continue
            first = (row[0] or "").strip()
            if not first or first.startswith("#"):
                continue
            if lineno == 1 and "site" in first.lower() and "code" in first.lower():
                # Header row.
                continue
            if len(row) < 3:
                raise ValueError(
                    f"line {lineno}: expected 3 fields "
                    f"(Site Code, STIP Prefix, STIP VLAN), got {len(row)}"
                )
            site_code = first
            stip_prefix = (row[1] or "").strip()
            stip_vvvv_raw = (row[2] or "").strip()
            if not (site_code and stip_prefix and stip_vvvv_raw):
                raise ValueError(f"line {lineno}: empty field(s) in {row!r}")
            try:
                vvvv = ipv6.normalize_vvvv(stip_vvvv_raw)
            except ValueError as e:
                raise ValueError(f"line {lineno}: invalid STIP VLAN '{stip_vvvv_raw}': {e}")
            yield lineno, site_code, stip_prefix, vvvv


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", nargs="?", default="ipv6-stip-allocations.csv",
                    help="Input CSV (default: ipv6-stip-allocations.csv)")
    ap.add_argument("--apply", action="store_true",
                    help="Commit changes (default is dry-run preview)")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        return 2

    device_site_map = app_cache.get("device_site_map") or {}
    dnac_interfaces = app_cache.get("dnac_interfaces") or []

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] reading {path}")
    print(f"        cache: device_site_map={len(device_site_map)} entries, "
          f"dnac_interfaces={len(dnac_interfaces)} entries")
    if not device_site_map or not dnac_interfaces:
        print("        WARNING: DNAC caches empty — IPv4 lookups will all fail. "
              "Warm DNAC (sites/devices/interfaces) before re-running for IPv4 enrichment.")
    print()

    registry.init_schema()

    try:
        rows = list(_parse_rows(path))
    except ValueError as e:
        print(f"  PARSE-ERROR  {e}", file=sys.stderr)
        return 1

    stats = {
        "created": 0,
        "with_ipv4": 0,
        "without_ipv4": 0,
        "skipped_exists": 0,
        "skipped_overlap": 0,
        "skipped_unknown_aggregate": 0,
        "warned_ipv4_dup": 0,
    }
    aggregate_cache: dict[str, dict | None] = {}

    for lineno, site_code, stip_prefix_raw, vvvv in rows:
        try:
            stip_prefix_norm = _normalize_stip_prefix(stip_prefix_raw)
        except ValueError as e:
            print(f"  line {lineno:>4}  PARSE-ERROR    invalid STIP prefix "
                  f"'{stip_prefix_raw}': {e}")
            continue

        if stip_prefix_norm not in aggregate_cache:
            aggregate_cache[stip_prefix_norm] = _find_stip_aggregate(stip_prefix_norm)
        agg = aggregate_cache[stip_prefix_norm]
        if not agg:
            print(f"  line {lineno:>4}  SKIP-UNKNOWN-AGGREGATE  "
                  f"no /48 site in Registry with prefix '{stip_prefix_norm}' "
                  f"(create it once, then re-run)")
            stats["skipped_unknown_aggregate"] += 1
            continue

        ipv4_cidr, detail = _find_vlan500_subnet(site_code, device_site_map, dnac_interfaces)

        existing = registry.list_allocations(site_id=agg["id"])
        same = next((a for a in existing
                     if a["vvvv"] == vvvv
                     and a["prefix_length"] == STIP_PREFIX_LENGTH), None)
        if same:
            print(f"  line {lineno:>4}  SKIP-EXISTS       "
                  f"{site_code} STIP {vvvv}/64 already present (id={same['id']})")
            stats["skipped_exists"] += 1
            continue

        overlaps = ipv6.find_overlap(vvvv, STIP_PREFIX_LENGTH, existing)
        if overlaps:
            conflict = ", ".join(f"#{o['id']}({o['vvvv']}/{o['prefix_length']})"
                                 for o in overlaps)
            print(f"  line {lineno:>4}  SKIP-OVERLAP      "
                  f"{site_code} STIP {vvvv}/64 overlaps {conflict}")
            stats["skipped_overlap"] += 1
            continue

        warn = ""
        if ipv4_cidr:
            v4_hits = registry.find_ipv4_collision(agg["id"], ipv4_cidr)
            if v4_hits:
                others = ", ".join(f"#{h['id']}(vvvv={h['vvvv']})" for h in v4_hits)
                warn = f" [WARN: ipv4 also at {others}]"
                stats["warned_ipv4_dup"] += 1

        action = "CREATE" if args.apply else "WOULD-CREATE"
        ipv4_blurb = f"-> {ipv4_cidr} ({detail})" if ipv4_cidr else f"(IPv4 unresolved: {detail})"
        print(f"  line {lineno:>4}  {action:<13}    "
              f"{site_code:<6} STIP {vvvv}/64  {ipv4_blurb}{warn}")

        if args.apply:
            registry.create_allocation(
                site_id=agg["id"],
                vvvv=vvvv,
                prefix_length=STIP_PREFIX_LENGTH,
                ipv4_subnet=ipv4_cidr,
                purpose=f"STIP ({STIP_VLAN_LABEL}) for {site_code}",
                description=(f"VLAN500 STIP for {site_code}"
                             + ("" if ipv4_cidr else " (IPv4 not resolved in DNAC)")),
            )
        stats["created"] += 1
        if ipv4_cidr:
            stats["with_ipv4"] += 1
        else:
            stats["without_ipv4"] += 1

    label = "created" if args.apply else "would create"
    print()
    print(f"[{mode}] summary:")
    print(f"  {label:<26} {stats.pop('created')}")
    for k, v in stats.items():
        if v:
            print(f"  {k:<26} {v}")
    if not args.apply:
        print("\nDry-run complete. Re-run with --apply to commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
