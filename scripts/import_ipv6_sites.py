#!/usr/bin/env python3
"""scripts/import_ipv6_sites.py — Bulk-import IPv6 registry sites.

Reads a flat CSV file (default: ipv6-sites.txt at the repo root) where each
line is:

    <name>,<prefix>[,<prefix_length>[,<role>[,<description>]]]

Examples:
    California-State,1000:2000:3031,48,state,California state-level /48
    LAX-airport,1000:2000:3031:0100,56,airport,"Los Angeles, CA"
    DC1,1000:2000:3000

Defaults:
    prefix_length = 48
    role          = (empty)
    description   = (empty)

Fields are parsed via the standard csv module, so values containing commas
must be wrapped in double quotes. Blank lines and lines starting with '#'
are ignored. Hits the SQLite registry directly — no HTTP/CSRF needed.

Run from the repo root:
    .venv/bin/python -m scripts.import_ipv6_sites              # dry run
    .venv/bin/python -m scripts.import_ipv6_sites --apply      # commit
    .venv/bin/python -m scripts.import_ipv6_sites my-file.csv  # custom path
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clients import ipv6_registry as registry
from utils import ipv6_assembler as ipv6


def parse_row(row: list[str], lineno: int) -> tuple[str, str, int, str | None, str | None] | None:
    """Returns (name, normalized_prefix, prefix_length, role, description)
    or None to skip (blank/comment row)."""
    # Strip whitespace from every field
    cells = [c.strip() for c in row]
    # Drop trailing empty cells so optional fields don't trip the length check
    while cells and cells[-1] == "":
        cells.pop()
    if not cells:
        return None
    if cells[0].startswith("#"):
        return None
    if len(cells) < 2:
        raise ValueError(
            f"line {lineno}: need at least <name>,<prefix>; got {len(cells)} field(s)"
        )
    if len(cells) > 5:
        raise ValueError(
            f"line {lineno}: too many fields ({len(cells)}); expected up to 5"
        )

    name = cells[0]
    prefix_raw = cells[1]
    prefix_length = int(cells[2]) if len(cells) >= 3 and cells[2] else 48
    role = cells[3] if len(cells) >= 4 and cells[3] else None
    description = cells[4] if len(cells) == 5 and cells[4] else None

    if not name:
        raise ValueError(f"line {lineno}: name is empty")

    try:
        ipv6.validate_site_prefix_length(prefix_length)
    except ValueError as e:
        raise ValueError(f"line {lineno}: {e}")

    try:
        prefix = ipv6.normalize_prefix(prefix_raw, prefix_length)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise ValueError(
            f"line {lineno}: invalid prefix '{prefix_raw}' for /{prefix_length}: {e}"
        )

    return name, prefix, prefix_length, role, description


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", nargs="?", default="ipv6-sites.txt",
                    help="Input file (default: ipv6-sites.txt)")
    ap.add_argument("--apply", action="store_true",
                    help="Commit changes (default is dry-run preview)")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        return 2

    registry.init_schema()
    by_prefix = {s["prefix"]: s for s in registry.list_sites()}

    stats = {"created": 0, "skipped_exists": 0,
             "skipped_prefix_conflict": 0,
             "parse_errors": 0}

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] reading {path}")
    print(f"        {len(by_prefix)} sites already registered")
    print()

    with path.open(newline="") as f:
        reader = csv.reader(f)
        for lineno, row in enumerate(reader, 1):
            try:
                parsed = parse_row(row, lineno)
            except ValueError as e:
                print(f"  PARSE-ERROR  {e}")
                stats["parse_errors"] += 1
                continue
            if parsed is None:
                continue
            name, prefix, prefix_length, role, description = parsed

            # The prefix is the identity. Same prefix already in the DB?
            existing = by_prefix.get(prefix)
            if existing:
                if (existing["name"] == name
                        and existing["prefix_length"] == prefix_length):
                    print(f"  line {lineno:>4}  SKIP-EXISTS            "
                          f"{name} {prefix}::/{prefix_length} already present (id={existing['id']})")
                    stats["skipped_exists"] += 1
                else:
                    print(f"  line {lineno:>4}  SKIP-PREFIX-CONFLICT   "
                          f"prefix {prefix} already owned by "
                          f"'{existing['name']}' (/{existing['prefix_length']}) — "
                          f"would clash with '{name}' (/{prefix_length})")
                    stats["skipped_prefix_conflict"] += 1
                continue

            action = "CREATE" if args.apply else "WOULD-CREATE"
            extras = []
            if role:
                extras.append(f"role={role}")
            if description:
                extras.append(f"desc={description!r}")
            extras_str = f"  [{', '.join(extras)}]" if extras else ""
            print(f"  line {lineno:>4}  {action:<14}         "
                  f"{name} -> {prefix}::/{prefix_length}{extras_str}")

            if args.apply:
                row = registry.create_site(
                    name=name, prefix=prefix, prefix_length=prefix_length,
                    role=role, description=description,
                )
                by_prefix[prefix] = row
            else:
                # Reserve the prefix in the in-memory map so a later duplicate
                # in the same file still trips SKIP-PREFIX-CONFLICT.
                by_prefix[prefix] = {"id": None, "name": name, "prefix": prefix,
                                     "prefix_length": prefix_length}
            stats["created"] += 1  # counts would-creates in dry-run too

    label = "created" if args.apply else "would create"
    print()
    print(f"[{mode}] summary:")
    print(f"  {label:<24} {stats.pop('created')}")
    for k, v in stats.items():
        if v:
            print(f"  {k:<24} {v}")
    if not args.apply:
        print("\nDry-run complete. Re-run with --apply to commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
