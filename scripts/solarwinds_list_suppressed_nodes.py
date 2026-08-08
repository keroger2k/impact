#!/usr/bin/env python3
"""scripts/solarwinds_list_suppressed_nodes.py — list every node with an
active or upcoming alert suppression (Orion.AlertSuppression).

Read-only — the counterpart to clients.solarwinds.suppress_alerts(): this
shows what's currently muted, since SolarWinds' own "Manage Maintenance
Schedules" screen doesn't reflect AlertSuppression entries at all (see
CLAUDE.md's Maintenance Mode Scheduler entry) and there's no dedicated list
view for them elsewhere in the UI either — a node's own detail page is the
only place this shows individually today.

Joins Orion.AlertSuppression to Orion.Nodes on EntityUri = Uri to get a
friendly Caption instead of a bare Uri.

Env vars (.env): SOLARWINDS_URL (required), SOLARWINDS_DOMAIN/PORT/TIMEOUT
(optional), SOLARWINDS_USERNAME/PASSWORD (default to DOMAIN_USERNAME/PASSWORD),
SOLARWINDS_VERIFY_SSL (default false).

Usage:
    python -m scripts.solarwinds_list_suppressed_nodes
    python -m scripts.solarwinds_list_suppressed_nodes --all   # include expired entries too
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import clients.solarwinds as solarwinds  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--all", action="store_true",
                     help="Include entries whose window already ended (default: only current/future)")
    args = ap.parse_args()

    username = os.getenv("SOLARWINDS_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    if not os.getenv("SOLARWINDS_URL"):
        print("ERROR: SOLARWINDS_URL must be set (see .env.template).")
        sys.exit(1)
    if not username or not password:
        print("ERROR: SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD (or DOMAIN_USERNAME/DOMAIN_PASSWORD) must be set.")
        sys.exit(1)

    # No WHERE-clause date filter — SWQL's function surface isn't confirmed
    # against this instance (learned the hard way elsewhere in this project
    # not to guess SWQL syntax), and filtering a handful of rows in Python
    # is just as easy and guaranteed correct.
    swql = """
SELECT n.Caption, n.IPAddress, a.SuppressFrom, a.SuppressUntil, a.Description, a.Reason
FROM Orion.AlertSuppression a
JOIN Orion.Nodes n ON a.EntityUri = n.Uri
ORDER BY a.SuppressFrom
"""
    try:
        rows = solarwinds.query(swql, username, password)
    except Exception as e:
        print(f"Query failed: {e}")
        sys.exit(1)

    if not args.all:
        now = datetime.now(timezone.utc)

        def _still_relevant(row):
            until = row.get("SuppressUntil")
            if not until:
                return True
            try:
                dt = datetime.fromisoformat(str(until).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt >= now
            except ValueError:
                return True  # unparseable — show it rather than silently drop it

        rows = [r for r in rows if _still_relevant(r)]

    if not rows:
        print("No suppressed nodes found" + ("" if args.all else " (current/upcoming only — pass --all to include expired)."))
        return

    print(f"{len(rows)} suppressed node(s):\n")
    print(f"{'Node':<20} {'IP':<16} {'Suppressed From':<26} {'Suppressed Until':<26} Reason")
    print("-" * 110)
    for r in rows:
        print(f"{(r.get('Caption') or ''):<20} {(r.get('IPAddress') or ''):<16} "
              f"{(r.get('SuppressFrom') or ''):<26} {(r.get('SuppressUntil') or ''):<26} "
              f"{r.get('Reason') or r.get('Description') or ''}")


if __name__ == "__main__":
    main()
