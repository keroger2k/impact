#!/usr/bin/env python3
"""scripts/import_registry.py — Seed the dual-stack IP registry from 3 CSVs.

Loads a site-centric IPAM registry (``clients.ip_registry`` /
``data/ip_registry.db``) from the three TSA exports, joined on **Site Code**:

  1. IPv4 blocks   — ``Site Code, Site IP Block(s), Subnet Mask``
                     → one ``prefixes`` row per block (role ``site-aggregate``),
                       multiple per site allowed.
  2. IPv6 site /56 — ``Site Code, IPv6 Address Space, Slash``
                     → the site's primary IPv6 prefix (role ``site``).
  3. STIP /64      — ``Site Code, STIP Prefix, STIP VLAN[, MASK]``
                     → one shared STIP /48 container (``site_id IS NULL``) plus a
                       per-site /64 child (role ``stip``) carrying the VLAN as
                       ``vvvv``.

Sites are auto-created by code as they're first seen (the file order doesn't
matter). Everything in the CSVs is imported — there is no decommissioned-row
filtering.

Header handling is tolerant: column headers are matched case-insensitively by
substring, extra columns are ignored, and a missing header row falls back to
positional column order. IPv6 site prefixes are written **high-aligned** — a
2-hex ``…:19`` at /56 is read as ``…:1900::/56`` (the written digits fill the
high bits the mask fixes). The dry-run prints every resulting canonical CIDR so
you can eyeball the interpretation before committing.

Dry-run by default; ``--apply`` commits. Run from the repo root:

    .venv/bin/python -m scripts.import_registry                 # dry-run, data/seed/*.csv
    .venv/bin/python -m scripts.import_registry --apply         # commit
    .venv/bin/python -m scripts.import_registry --seed-dir /tmp/seed --apply
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clients import ip_registry as registry  # noqa: E402
from utils import ipam_net  # noqa: E402
from utils import ipv6_assembler as ipv6  # noqa: E402

DEFAULT_FILES = {"ipv4": "ipv4.csv", "ipv6": "ipv6.csv", "stip": "stip.csv"}


# ── CSV helpers ────────────────────────────────────────────────────────────────

def _match_col(cells: list[str], fragments: tuple[str, ...], fallback: int) -> int:
    """Index of the first header cell containing any fragment (case-insensitive),
    else ``fallback``."""
    for i, c in enumerate(cells):
        cl = (c or "").strip().lower()
        for f in fragments:
            if f in cl:
                return i
    return fallback


def _read_rows(path: Path) -> list[list[str]]:
    """Return non-empty, non-comment rows. Cells stripped."""
    out: list[list[str]] = []
    with path.open(newline="") as f:
        for row in csv.reader(f):
            cells = [(c or "").strip() for c in row]
            if not any(cells):
                continue
            if cells[0].startswith("#"):
                continue
            out.append(cells)
    return out


_HEADER_TOKENS = ("site", "code", "prefix", "mask", "slash", "length", "block",
                  "ipv6", "ipv4", "vlan", "vvvv", "address", "region", "space",
                  "subnet", "name")
_ADDRESSY = re.compile(r"\d+\.\d+|[0-9a-fA-F]+:")


def _is_header(cells: list[str]) -> bool:
    """A row is the header if it carries header-keyword tokens and no cell looks
    like an address. Works regardless of column order (e.g. a leading 'Region'
    column) and won't mistake a data row for a header."""
    if any(_ADDRESSY.search(c) for c in cells):
        return False
    joined = " ".join(c.lower() for c in cells)
    return any(tok in joined for tok in _HEADER_TOKENS)


def _ipv6_high_aligned_cidr(raw: str, length: int) -> str:
    """Build a canonical IPv6 CIDR from a high-aligned written prefix.

    The exports drop trailing zeros, writing the *high* bits the mask fixes:
    ``2600:0400:3010:19`` at /56 means hextet-4 ``0x1900`` → ``…:1900::/56``.
    So the final written group is right-padded to 4 hex digits before parsing.
    """
    s = raw.strip().rstrip(":")
    if "/" in s:
        s = s.split("/", 1)[0]
    groups = [g for g in s.split(":") if g != ""]
    if not groups:
        raise ValueError(f"empty IPv6 prefix {raw!r}")
    groups[-1] = groups[-1].ljust(4, "0")
    joined = ":".join(groups)
    sep = "" if len(groups) >= 8 else "::"
    _, _, _, cidr = ipam_net.canonical(f"{joined}{sep}/{length}")
    return cidr


def _stip_child_cidr(stip48_cidr: str, vvvv: str) -> str:
    """Carve the /64 at ``vvvv`` out of the STIP /48 (vvvv → hextet 4)."""
    base = int(ipaddress.ip_network(stip48_cidr).network_address)
    child = base | (int(vvvv, 16) << 64)
    return str(ipaddress.IPv6Network((child, 64)))


def _ipv4_cidr(block: str, mask: str) -> str:
    """Combine a block + (dotted | slashed | bare) mask into a canonical CIDR."""
    block = block.strip()
    if "/" in block:
        cand = block
    elif mask.strip():
        cand = f"{block}/{mask.strip().lstrip('/')}"
    else:
        cand = block  # ip_network defaults to a host route
    _, _, _, cidr = ipam_net.canonical(cand)
    return cidr


# ── Report model ───────────────────────────────────────────────────────────────

@dataclass
class Action:
    file: str
    kind: str          # site | container | ipv4 | ipv6-site | stip
    site_code: str
    cidr: str
    action: str        # create | exists | skip-dup | error
    detail: str = ""


@dataclass
class Report:
    actions: list[Action] = field(default_factory=list)
    sites_created: set[str] = field(default_factory=set)
    sites_seen: set[str] = field(default_factory=set)

    def add(self, a: Action) -> None:
        self.actions.append(a)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for a in self.actions:
            c[a.action] = c.get(a.action, 0) + 1
        return c


# ── Core import ────────────────────────────────────────────────────────────────

class _Importer:
    """Holds apply-vs-dry-run state and the per-run caches so prefixes can
    reference the sites/containers created earlier in the same run."""

    def __init__(self, db_path: Optional[Path], apply: bool):
        self.db_path = db_path
        self.apply = apply
        self.report = Report()
        # code -> site row (real in apply mode; synthetic {id:None} in dry-run)
        self._sites: dict[str, dict] = {}
        # cidr -> container row (STIP /48s); dry-run uses {id:None}
        self._containers: dict[str, dict] = {}
        # (site_code, cidr) seen this run → within-file dedupe
        self._seen_prefixes: set[tuple[str, str]] = set()

    # -- sites --
    def ensure_site(self, code: str, **fields) -> dict:
        key = code.upper()
        self.report.sites_seen.add(key)
        if key in self._sites:
            return self._sites[key]
        existing = registry.get_site_by_code(code, path=self.db_path)
        if existing:
            self._sites[key] = existing
            return existing
        # New site.
        if self.apply:
            row, _ = registry.upsert_site(code, path=self.db_path, **fields)
        else:
            row = {"id": None, "site_code": code, **fields}
        self._sites[key] = row
        self.report.sites_created.add(key)
        self.report.add(Action("(sites)", "site", code, "", "create",
                               "new site"))
        return row

    # -- shared containers --
    def ensure_container(self, cidr: str, *, label: str) -> dict:
        if cidr in self._containers:
            return self._containers[cidr]
        existing = registry.find_prefix_by_cidr(cidr, site_id=None, path=self.db_path)
        if existing:
            self._containers[cidr] = existing
            return existing
        if self.apply:
            row, _ = registry.get_or_create_container(
                cidr, role="container", label=label, source="csv",
                description=f"{label} shared aggregate", path=self.db_path)
        else:
            row = {"id": None, "cidr": cidr}
        self._containers[cidr] = row
        self.report.add(Action("stip", "container", "(shared)", cidr, "create",
                               f"{label} /48 aggregate"))
        return row

    # -- prefixes --
    def add_prefix(self, *, file: str, kind: str, code: str, cidr: str,
                   role: str, site: dict, parent_id: Optional[int] = None,
                   vvvv: Optional[str] = None, vlan_id: Optional[int] = None,
                   label: Optional[str] = None) -> None:
        dedup_key = (code.upper(), cidr)
        if dedup_key in self._seen_prefixes:
            self.report.add(Action(file, kind, code, cidr, "skip-dup",
                                   "duplicate within this import run"))
            return
        self._seen_prefixes.add(dedup_key)

        # Already in the DB for this site?
        if site.get("id") is not None:
            if registry.find_prefix_by_cidr(cidr, site_id=site["id"],
                                            path=self.db_path):
                self.report.add(Action(file, kind, code, cidr, "exists",
                                       "already present for this site"))
                return

        if not self.apply:
            self.report.add(Action(file, kind, code, cidr, "create", role))
            return

        try:
            registry.create_prefix(
                cidr, site_id=site["id"], parent_id=parent_id, role=role,
                vlan_id=vlan_id, vvvv=vvvv, label=label, source="csv",
                path=self.db_path)
            self.report.add(Action(file, kind, code, cidr, "create", role))
        except sqlite3.IntegrityError as e:
            self.report.add(Action(file, kind, code, cidr, "skip-dup", str(e)))
        except ValueError as e:
            self.report.add(Action(file, kind, code, cidr, "error", str(e)))

    # -- file processors --
    def import_ipv4(self, path: Path) -> None:
        rows = _read_rows(path)
        if not rows:
            return
        i_code, i_block, i_mask = 0, 1, 2
        if _is_header(rows[0]):
            h = rows[0]
            i_code = _match_col(h, ("site code", "code", "site"), 0)
            i_block = _match_col(h, ("block", "ip block", "subnet", "address"), 1)
            i_mask = _match_col(h, ("mask", "slash", "length", "cidr"), 2)
            rows = rows[1:]
        for r in rows:
            code = r[i_code] if i_code < len(r) else ""
            block = r[i_block] if i_block < len(r) else ""
            mask = r[i_mask] if i_mask < len(r) else ""
            if not code or not block:
                continue
            try:
                cidr = _ipv4_cidr(block, mask)
            except ValueError as e:
                self.report.add(Action("ipv4", "ipv4", code, f"{block}/{mask}",
                                       "error", str(e)))
                continue
            site = self.ensure_site(code)
            self.add_prefix(file="ipv4", kind="ipv4", code=code, cidr=cidr,
                            role="site-aggregate", site=site,
                            label="IPv4 block")

    def import_ipv6_sites(self, path: Path) -> None:
        rows = _read_rows(path)
        if not rows:
            return
        i_code, i_pfx, i_slash = 0, 1, 2
        if _is_header(rows[0]):
            h = rows[0]
            i_code = _match_col(h, ("site code", "code", "site"), 0)
            i_pfx = _match_col(h, ("ipv6", "address space", "prefix", "space"), 1)
            i_slash = _match_col(h, ("slash", "mask", "length", "/"), 2)
            rows = rows[1:]
        for r in rows:
            code = r[i_code] if i_code < len(r) else ""
            raw = r[i_pfx] if i_pfx < len(r) else ""
            slash = (r[i_slash] if i_slash < len(r) else "").strip().lstrip("/")
            if not code or not raw:
                continue
            try:
                length = int(slash) if slash else 56
                cidr = _ipv6_high_aligned_cidr(raw, length)
            except ValueError as e:
                self.report.add(Action("ipv6", "ipv6-site", code, raw, "error",
                                       str(e)))
                continue
            site = self.ensure_site(code)
            self.add_prefix(file="ipv6", kind="ipv6-site", code=code, cidr=cidr,
                            role="site", site=site, label="IPv6 site prefix")

    def import_stip(self, path: Path) -> None:
        rows = _read_rows(path)
        if not rows:
            return
        i_code, i_pfx, i_vlan, i_mask = 0, 1, 2, 3
        if _is_header(rows[0]):
            h = rows[0]
            i_code = _match_col(h, ("site code", "code", "site"), 0)
            i_pfx = _match_col(h, ("stip prefix", "prefix", "address"), 1)
            i_vlan = _match_col(h, ("vlan", "vvvv"), 2)
            i_mask = _match_col(h, ("mask", "slash", "length"), 3)
            rows = rows[1:]
        for r in rows:
            code = r[i_code] if i_code < len(r) else ""
            raw48 = r[i_pfx] if i_pfx < len(r) else ""
            vlan_raw = r[i_vlan] if i_vlan < len(r) else ""
            if not code or not raw48 or not vlan_raw:
                continue
            try:
                cidr48 = _ipv6_high_aligned_cidr(raw48, 48)
                vvvv = ipv6.normalize_vvvv(vlan_raw)
                child = _stip_child_cidr(cidr48, vvvv)
            except ValueError as e:
                self.report.add(Action("stip", "stip", code,
                                       f"{raw48}/{vlan_raw}", "error", str(e)))
                continue
            container = self.ensure_container(cidr48, label="STIP")
            site = self.ensure_site(code)
            self.add_prefix(file="stip", kind="stip", code=code, cidr=child,
                            role="stip", site=site,
                            parent_id=container.get("id"), vvvv=vvvv,
                            label=f"STIP VLAN {vvvv}")


def run_import(*, ipv4_path: Optional[Path] = None, ipv6_path: Optional[Path] = None,
               stip_path: Optional[Path] = None, db_path: Optional[Path] = None,
               apply: bool = False) -> Report:
    """Importable entry point (used by tests). Always ensures the schema, then
    processes whichever of the three files were provided and exist."""
    registry.init_schema(db_path)
    imp = _Importer(db_path, apply)
    # IPv6 sites first so the 'site' role lands before STIP children reference
    # the same site; order is otherwise immaterial (sites upsert by code).
    if ipv6_path and ipv6_path.exists():
        imp.import_ipv6_sites(ipv6_path)
    if ipv4_path and ipv4_path.exists():
        imp.import_ipv4(ipv4_path)
    if stip_path and stip_path.exists():
        imp.import_stip(stip_path)
    return imp.report


# ── CLI ────────────────────────────────────────────────────────────────────────

def _print_report(report: Report, *, apply: bool) -> None:
    mode = "APPLY" if apply else "DRY-RUN"
    verb = {"create": "CREATE" if apply else "would-create",
            "exists": "exists", "skip-dup": "skip-dup", "error": "ERROR"}
    print(f"\n[{mode}] actions:")
    for a in report.actions:
        tag = verb.get(a.action, a.action)
        loc = a.site_code or "—"
        print(f"  {tag:<14} {a.kind:<11} {loc:<7} {a.cidr or '':<24} {a.detail}")
    print(f"\n[{mode}] summary:")
    print(f"  sites seen        {len(report.sites_seen)}")
    print(f"  sites new         {len(report.sites_created)}")
    for k, v in sorted(report.counts().items()):
        print(f"  {k:<17} {v}")
    if not apply:
        print("\nDry-run complete. Re-run with --apply to commit.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed-dir", default=str(ROOT / "data" / "seed"),
                    help="Directory holding ipv4.csv / ipv6.csv / stip.csv")
    ap.add_argument("--ipv4", default=None, help="Override IPv4 CSV path")
    ap.add_argument("--ipv6", default=None, help="Override IPv6 CSV path")
    ap.add_argument("--stip", default=None, help="Override STIP CSV path")
    ap.add_argument("--apply", action="store_true", help="Commit (default: dry-run)")
    args = ap.parse_args()

    seed = Path(args.seed_dir)
    ipv4_path = Path(args.ipv4) if args.ipv4 else seed / DEFAULT_FILES["ipv4"]
    ipv6_path = Path(args.ipv6) if args.ipv6 else seed / DEFAULT_FILES["ipv6"]
    stip_path = Path(args.stip) if args.stip else seed / DEFAULT_FILES["stip"]

    found = {name: p for name, p in (("ipv4", ipv4_path), ("ipv6", ipv6_path),
                                     ("stip", stip_path)) if p.exists()}
    if not found:
        print(f"ERROR: no seed CSVs found. Looked for:\n"
              f"  {ipv4_path}\n  {ipv6_path}\n  {stip_path}", file=sys.stderr)
        return 2
    print(f"[{'APPLY' if args.apply else 'DRY-RUN'}] seed files: "
          f"{', '.join(found)}")

    report = run_import(ipv4_path=ipv4_path, ipv6_path=ipv6_path,
                        stip_path=stip_path, apply=args.apply)
    _print_report(report, apply=args.apply)
    if any(a.action == "error" for a in report.actions):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
