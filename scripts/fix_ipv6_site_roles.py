#!/usr/bin/env python3
"""scripts/fix_ipv6_site_roles.py — One-shot cleanup for sites imported with
the description text accidentally placed in the role column.

For every row in the sites table, this script:
  1. Copies the current `role` value into `description`
  2. Sets `role` to the literal string "site"

Dry-run by default. Re-run with --apply to commit. Point at a specific DB
file with --db (defaults to data/ipv6_registry.db relative to repo root).

    .venv/bin/python -m scripts.fix_ipv6_site_roles                       # dry-run
    .venv/bin/python -m scripts.fix_ipv6_site_roles --apply               # commit
    .venv/bin/python -m scripts.fix_ipv6_site_roles --db /path/to/x.db    # custom path
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "ipv6_registry.db"

NEW_ROLE = "site"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", default=str(DEFAULT_DB),
                    help=f"Path to the IPv6 registry DB (default: {DEFAULT_DB})")
    ap.add_argument("--apply", action="store_true",
                    help="Commit changes (default is dry-run preview)")
    args = ap.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        print(f"ERROR: DB file not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    if total == 0:
        print(f"{db_path}: no sites in DB — nothing to do.")
        return 0

    # Counts that matter for the preview:
    #  - rows where description is already populated (would be overwritten)
    #  - rows where role is NULL/empty (description becomes NULL/empty)
    desc_already_set = conn.execute(
        "SELECT COUNT(*) FROM sites WHERE description IS NOT NULL AND description != ''"
    ).fetchone()[0]
    role_empty = conn.execute(
        "SELECT COUNT(*) FROM sites WHERE role IS NULL OR role = ''"
    ).fetchone()[0]

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] target: {db_path}")
    print(f"        sites in DB:                       {total}")
    print(f"        rows with description already set: {desc_already_set} "
          f"(will be OVERWRITTEN with the current role value)")
    print(f"        rows with empty/NULL role:         {role_empty} "
          f"(description will become NULL/empty, role -> '{NEW_ROLE}')")
    print()

    sample = conn.execute(
        "SELECT id, name, role, description FROM sites ORDER BY id LIMIT 5"
    ).fetchall()
    print("Sample of rows before the change:")
    for r in sample:
        print(f"  id={r['id']:>4}  name={r['name']!r:25}  "
              f"role={r['role']!r:25}  description={r['description']!r}")
    print()
    print(f"After the change (sample id={sample[0]['id']}):")
    print(f"  role        -> {NEW_ROLE!r}")
    print(f"  description -> {sample[0]['role']!r}  (was the role)")
    print()

    if not args.apply:
        print("Dry-run complete. Re-run with --apply to commit.")
        conn.close()
        return 0

    try:
        with conn:  # implicit BEGIN/COMMIT, rollback on exception
            cur = conn.execute(
                "UPDATE sites SET description = role, "
                "role = ?, updated_at = datetime('now')",
                (NEW_ROLE,),
            )
            updated = cur.rowcount
        print(f"OK: updated {updated} site row(s).")
    except sqlite3.Error as e:
        print(f"ERROR: SQL failure, rolled back: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
