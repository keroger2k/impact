#!/usr/bin/env python3
"""scripts/import_ipv6_allocations.py — Bulk-import IPv6 allocations.

Reads a flat file (default: ipv6-allocations.txt at the repo root) where each
line is:

    <site_name>,<ipv4_subnet>,<ipv4_mask>,<vvvv>[,<prefix_length>]

Example:
    DC1,1.2.3.0,255.255.255.0,0100
    DC1,1.2.0.0,255.255.0.0,0200,56

Blank lines and lines starting with '#' are ignored. Sites must already exist
in the registry; any site with prefix_length < 64 can carry allocations
(/48 carries the full 16-bit vvvv space; /56 narrows to 256 slots whose
high byte must match the site's prefix, etc.). Sites at /64 are skipped —
they're atomic. Hits the SQLite registry directly — no HTTP/CSRF needed.

Run from the repo root:
    .venv/bin/python -m scripts.import_ipv6_allocations            # dry run
    .venv/bin/python -m scripts.import_ipv6_allocations --apply    # commit
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

# Allow `python scripts/import_ipv6_allocations.py` to import project modules
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clients import ipv6_registry as registry
from utils import ipv6_assembler as ipv6


def parse_line(line: str, lineno: int) -> tuple[str, str, str] | None:
    """Returns (site_name, ipv4_cidr, vvvv, prefix_length) or None to skip."""
    raw = line.split("#", 1)[0].strip()
    if not raw:
        return None
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) not in (4, 5):
        raise ValueError(
            f"line {lineno}: expected 4 or 5 comma-separated fields, got {len(parts)}"
        )
    site, subnet, mask, vvvv = parts[:4]
    prefix_length = int(parts[4]) if len(parts) == 5 else 64

    try:
        net = ipaddress.IPv4Network(f"{subnet}/{mask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        raise ValueError(f"line {lineno}: invalid IPv4 subnet/mask '{subnet}/{mask}': {e}")

    return site, str(net), ipv6.normalize_vvvv(vvvv), prefix_length


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", nargs="?", default="ipv6-allocations.txt",
                    help="Input file (default: ipv6-allocations.txt)")
    ap.add_argument("--apply", action="store_true",
                    help="Commit changes (default is dry-run preview)")
    ap.add_argument("--skip-ipv4-dup", action="store_true",
                    help="Skip rows whose ipv4_subnet is already mapped in the same site "
                         "(default: import with a warning, same as confirm_ipv4_dup=true)")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        return 2

    registry.init_schema()
    sites_by_name = {s["name"]: s for s in registry.list_sites()}

    stats = {"created": 0, "skipped_exists": 0, "skipped_overlap": 0,
             "skipped_unknown_site": 0, "skipped_leaf_site": 0,
             "skipped_ipv4_dup": 0, "warned_ipv4_dup": 0, "parse_errors": 0}

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] reading {path}")
    print(f"        {len(sites_by_name)} registered sites: {sorted(sites_by_name)}")
    print()

    with path.open() as f:
        for lineno, line in enumerate(f, 1):
            try:
                parsed = parse_line(line, lineno)
            except ValueError as e:
                print(f"  PARSE-ERROR  {e}")
                stats["parse_errors"] += 1
                continue
            if parsed is None:
                continue
            site_name, ipv4_cidr, vvvv, prefix_length = parsed

            site = sites_by_name.get(site_name)
            if site is None:
                print(f"  line {lineno:>4}  SKIP-UNKNOWN-SITE  '{site_name}' "
                      f"(register it first; this row maps {ipv4_cidr} -> vvvv {vvvv})")
                stats["skipped_unknown_site"] += 1
                continue

            site_len = int(site.get("prefix_length", 48))
            if site_len >= 64:
                print(f"  line {lineno:>4}  SKIP-LEAF-SITE     '{site_name}' "
                      f"is /{site_len} — only sites with prefix_length < 64 can carry allocations")
                stats["skipped_leaf_site"] += 1
                continue
            if prefix_length <= site_len:
                print(f"  line {lineno:>4}  SKIP-BAD-LENGTH    '{site_name}' "
                      f"is /{site_len}; allocation /{prefix_length} must be more specific")
                stats["skipped_overlap"] += 1
                continue
            if not ipv6.vvvv_conforms_to_site(vvvv, site["prefix"], site_len):
                fixed = ipv6.site_vvvv_fixed_value(site["prefix"], site_len)
                mask = ipv6.site_vvvv_mask(site_len)
                print(f"  line {lineno:>4}  SKIP-VVVV-MISMATCH '{site_name}' "
                      f"vvvv {vvvv} must match fixed=0x{fixed:04x} mask=0x{mask:04x}")
                stats["skipped_overlap"] += 1
                continue

            existing = registry.list_allocations(site_id=site["id"])

            # Exact same allocation already present?
            same = next((a for a in existing
                         if a["vvvv"] == vvvv
                         and a["prefix_length"] == prefix_length
                         and (a["ipv4_subnet"] or "") == ipv4_cidr), None)
            if same:
                print(f"  line {lineno:>4}  SKIP-EXISTS         "
                      f"{site_name}/{vvvv} -> {ipv4_cidr} already present (id={same['id']})")
                stats["skipped_exists"] += 1
                continue

            # vvvv overlap = hard block
            overlaps = ipv6.find_overlap(vvvv, prefix_length, existing)
            if overlaps:
                conflict = ", ".join(f"#{o['id']}({o['vvvv']}/{o['prefix_length']})"
                                     for o in overlaps)
                print(f"  line {lineno:>4}  SKIP-OVERLAP        "
                      f"{site_name}/{vvvv}/{prefix_length} overlaps {conflict}")
                stats["skipped_overlap"] += 1
                continue

            # ipv4 dup = soft warn
            v4_hits = registry.find_ipv4_collision(site["id"], ipv4_cidr)
            warn = ""
            if v4_hits:
                if args.skip_ipv4_dup:
                    others = ", ".join(f"#{h['id']}(vvvv={h['vvvv']})" for h in v4_hits)
                    print(f"  line {lineno:>4}  SKIP-IPV4-DUP       "
                          f"{site_name} {ipv4_cidr} already mapped: {others}")
                    stats["skipped_ipv4_dup"] += 1
                    continue
                others = ", ".join(f"#{h['id']}(vvvv={h['vvvv']})" for h in v4_hits)
                warn = f" [WARN: ipv4 also at {others}]"
                stats["warned_ipv4_dup"] += 1

            action = "CREATE" if args.apply else "WOULD-CREATE"
            print(f"  line {lineno:>4}  {action:<12}        "
                  f"{site_name}/{vvvv}/{prefix_length} -> {ipv4_cidr}{warn}")

            if args.apply:
                registry.create_allocation(
                    site_id=site["id"], vvvv=vvvv,
                    prefix_length=prefix_length, ipv4_subnet=ipv4_cidr,
                )
            stats["created"] += 1  # counts would-creates in dry-run too

    label = "created" if args.apply else "would create"
    print()
    print(f"[{mode}] summary:")
    print(f"  {label:<22} {stats.pop('created')}")
    for k, v in stats.items():
        if v:
            print(f"  {k:<22} {v}")
    if not args.apply:
        print("\nDry-run complete. Re-run with --apply to commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
