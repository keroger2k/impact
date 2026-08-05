#!/usr/bin/env python3
"""scripts/list_local_usernames.py — Deduplicated local-username audit.

Scans cached/collected running-configs (DNAC-managed IOS/IOS-XE devices +
collected Nexus NX-OS devices) for locally-configured ``username`` lines and
prints a deduplicated list of usernames with a count of how many devices each
one appears on. Useful for spotting stray local accounts that should be on
TACACS/RADIUS instead.

DNAC device configs are fetched the same way the in-app Config Search does
(``cache.get_or_set("config_{device_id}", ...)`` at TTL_LIVE, using the shared
service-account DNAC client) — so a fresh run pulls live if nothing is cached.
Nexus configs are **not** re-collected here; they're read from whatever the
Nexus page's last Collect populated (``config:nexus:{hostname}``), since SSH
collection is a separate, per-user-creds workflow. Panorama/ACI/F5 are out of
scope — this app doesn't cache raw per-device CLI config text for them.

Usage (run as a module from the repo root so imports resolve):

    .venv/bin/python -m scripts.list_local_usernames
    .venv/bin/python -m scripts.list_local_usernames --source nexus
    .venv/bin/python -m scripts.list_local_usernames --devices
    .venv/bin/python -m scripts.list_local_usernames --csv usernames.csv
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import clients.dnac as dc  # noqa: E402
from cache import cache, TTL_STANDARD, TTL_LIVE  # noqa: E402
from routers.nexus import get_cached_nexus_inventory  # noqa: E402

WORKERS = 20

# Matches IOS/NX-OS `username <name> ...` lines. The keyword is always
# lowercase in running-config output, but match case-insensitively to be safe
# and preserve the captured name's original case.
_USERNAME_RE = re.compile(r"^\s*username\s+(\S+)", re.IGNORECASE)


def _extract_usernames(config: str | None) -> set[str]:
    if not config:
        return set()
    return {m.group(1) for line in config.splitlines() if (m := _USERNAME_RE.match(line))}


def _dnac_targets(dnac) -> list[dict]:
    devices = cache.get_or_set("devices", lambda: dc.get_all_devices(dnac), TTL_STANDARD, background=False) or []
    target_families = {"routers", "switches and hubs"}
    return [d for d in devices if (d.get("family") or "").lower() in target_families]


def _collect_dnac(hits: dict[str, set[str]], verbose: bool) -> int:
    dnac = dc.get_client()
    targets = _dnac_targets(dnac)
    if not targets:
        print("No DNAC devices found (cache empty and live fetch returned none).", file=sys.stderr)
        return 0

    def fetch(device: dict) -> tuple[str, set[str]]:
        dev_id = device.get("id", "")
        config = cache.get_or_set(f"config_{dev_id}", lambda: dc.get_device_config(dnac, dev_id), TTL_LIVE)
        return device.get("hostname") or dev_id, _extract_usernames(config)

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for hostname, names in ex.map(fetch, targets):
            for name in names:
                hits[name].add(hostname)

    if verbose:
        print(f"Scanned {len(targets)} DNAC-managed device(s).", file=sys.stderr)
    return len(targets)


def _collect_nexus(hits: dict[str, set[str]], verbose: bool) -> int:
    devices = get_cached_nexus_inventory()
    if not devices:
        print("No cached Nexus inventory found — run a Nexus Collect first.", file=sys.stderr)
        return 0

    scanned = 0
    for device in devices:
        hostname = device.get("hostname")
        if not hostname:
            continue
        config = cache.get(f"config:nexus:{hostname}")
        if not config:
            continue
        scanned += 1
        for name in _extract_usernames(config):
            hits[name].add(hostname)

    if verbose:
        print(f"Scanned {scanned}/{len(devices)} Nexus device(s) with cached config.", file=sys.stderr)
    return scanned


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=["all", "dnac", "nexus"], default="all",
                         help="Which platforms to scan (default: all)")
    parser.add_argument("--devices", action="store_true",
                         help="Also list the hostnames each username was found on")
    parser.add_argument("--csv", metavar="PATH", help="Write results to a CSV file")
    args = parser.parse_args()

    hits: dict[str, set[str]] = defaultdict(set)

    if args.source in ("all", "dnac"):
        _collect_dnac(hits, verbose=True)
    if args.source in ("all", "nexus"):
        _collect_nexus(hits, verbose=True)

    if not hits:
        print("No local usernames found.")
        return

    rows = sorted(hits.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "device_count", "devices"])
            for name, hosts in rows:
                writer.writerow([name, len(hosts), ";".join(sorted(hosts))])
        print(f"Wrote {len(rows)} username(s) to {args.csv}")
        return

    name_width = max(len("USERNAME"), max(len(n) for n, _ in rows))
    print(f"{'USERNAME'.ljust(name_width)}  DEVICES")
    print(f"{'-' * name_width}  -------")
    for name, hosts in rows:
        print(f"{name.ljust(name_width)}  {len(hosts)}")
        if args.devices:
            for h in sorted(hosts):
                print(f"{' ' * name_width}    - {h}")

    print(f"\n{len(rows)} unique username(s) across "
          f"{len({h for _, hosts in rows for h in hosts})} device(s).")


if __name__ == "__main__":
    main()
