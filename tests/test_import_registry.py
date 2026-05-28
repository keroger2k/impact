"""Tests for scripts.import_registry — the 3-CSV seed importer.

Uses synthetic CSVs with fake addressing (repo convention: 1000:2000:3000 /
4000:5000:6000 for IPv6, 10.x for IPv4) against a tmp DB. No real data here."""
from __future__ import annotations

from pathlib import Path

import pytest

from clients import ip_registry as reg
from scripts.import_registry import (
    run_import, _ipv6_high_aligned_cidr, _stip_child_cidr, _ipv4_cidr,
)

IPV4_CSV = """\
Site Code,Site IP Block(s),Subnet Mask
A001,10.0.0.0,255.255.254.0
A001,10.0.2.0,255.255.255.0
B002,10.5.0.0,255.255.0.0
"""

IPV6_CSV = """\
Site Code,IPv6 Address Space,Slash
A001,1000:2000:3000:19,/56
B002,1000:2000:3000:03,/56
"""

STIP_CSV = """\
Site Code,STIP Prefix,STIP VLAN,MASK
A001,4000:5000:6000:,0000,/64
B002,4000:5000:6000:,0001,/64
"""


@pytest.fixture
def seed(tmp_path: Path) -> dict:
    d = tmp_path / "seed"
    d.mkdir()
    (d / "ipv4.csv").write_text(IPV4_CSV)
    (d / "ipv6.csv").write_text(IPV6_CSV)
    (d / "stip.csv").write_text(STIP_CSV)
    return {
        "ipv4": d / "ipv4.csv", "ipv6": d / "ipv6.csv", "stip": d / "stip.csv",
        "db": tmp_path / "reg.db",
    }


def _run(seed: dict, apply: bool):
    return run_import(ipv4_path=seed["ipv4"], ipv6_path=seed["ipv6"],
                      stip_path=seed["stip"], db_path=seed["db"], apply=apply)


# ── pure helpers ───────────────────────────────────────────────────────────────

def test_ipv6_high_aligned_expansion():
    assert _ipv6_high_aligned_cidr("1000:2000:3000:19", 56) == "1000:2000:3000:1900::/56"
    assert _ipv6_high_aligned_cidr("1000:2000:3000:03", 56) == "1000:2000:3000:300::/56"
    # Already-full final group is left as written.
    assert _ipv6_high_aligned_cidr("1000:2000:3000:1900", 56) == "1000:2000:3000:1900::/56"
    # STIP /48: trailing colon, 3 groups.
    assert _ipv6_high_aligned_cidr("4000:5000:6000:", 48) == "4000:5000:6000::/48"


def test_stip_child_carving():
    assert _stip_child_cidr("4000:5000:6000::/48", "0000") == "4000:5000:6000::/64"
    assert _stip_child_cidr("4000:5000:6000::/48", "0001") == "4000:5000:6000:1::/64"
    assert _stip_child_cidr("4000:5000:6000::/48", "00ff") == "4000:5000:6000:ff::/64"


def test_ipv4_cidr_mask_forms():
    assert _ipv4_cidr("10.0.0.0", "255.255.254.0") == "10.0.0.0/23"
    assert _ipv4_cidr("10.0.0.0", "/24") == "10.0.0.0/24"
    assert _ipv4_cidr("10.0.0.0", "16") == "10.0.0.0/16"
    assert _ipv4_cidr("10.0.0.0/22", "") == "10.0.0.0/22"


# ── dry-run writes nothing ─────────────────────────────────────────────────────

def test_dry_run_makes_no_changes(seed: dict):
    report = _run(seed, apply=False)
    assert report.sites_created == {"A001", "B002"}
    # Every action is a "would create"; nothing committed.
    assert {a.action for a in report.actions} == {"create"}
    assert reg.list_sites(path=seed["db"]) == []
    assert reg.list_prefixes(path=seed["db"]) == []


# ── apply: full dual-stack load ────────────────────────────────────────────────

def test_apply_loads_sites_and_prefixes(seed: dict):
    _run(seed, apply=True)

    sites = {s["site_code"]: s for s in reg.list_sites(path=seed["db"])}
    assert set(sites) == {"A001", "B002"}

    a = sites["A001"]
    a_prefixes = reg.list_prefixes(site_id=a["id"], path=seed["db"])
    roles = sorted(p["role"] for p in a_prefixes)
    # 2 IPv4 blocks + 1 IPv6 site /56 + 1 STIP /64
    assert roles == ["site", "site-aggregate", "site-aggregate", "stip"]

    by_role = {}
    for p in a_prefixes:
        by_role.setdefault(p["role"], []).append(p)

    # IPv6 site /56 — high-aligned, vvvv left null on the site prefix.
    site6 = by_role["site"][0]
    assert site6["cidr"] == "1000:2000:3000:1900::/56"
    assert site6["family"] == 6 and site6["vvvv"] is None

    # IPv4 blocks, both families represented.
    v4 = sorted(p["cidr"] for p in by_role["site-aggregate"])
    assert v4 == ["10.0.0.0/23", "10.0.2.0/24"]

    # STIP child carries the VLAN as vvvv and points at the shared /48.
    stip = by_role["stip"][0]
    assert stip["cidr"] == "4000:5000:6000::/64"
    assert stip["vvvv"] == "0000"
    container = reg.get_prefix(stip["parent_id"], path=seed["db"])
    assert container["site_id"] is None and container["cidr"] == "4000:5000:6000::/48"


def test_stip_container_is_shared_singleton(seed: dict):
    _run(seed, apply=True)
    containers = reg.list_prefixes(containers_only=True, path=seed["db"])
    assert len(containers) == 1
    assert containers[0]["cidr"] == "4000:5000:6000::/48"
    # Both sites' STIP children hang off that one container.
    children = [p for p in reg.list_prefixes(path=seed["db"]) if p["role"] == "stip"]
    assert len(children) == 2
    assert all(c["parent_id"] == containers[0]["id"] for c in children)


def test_reapply_is_idempotent(seed: dict):
    _run(seed, apply=True)
    before = len(reg.list_prefixes(path=seed["db"]))
    report2 = _run(seed, apply=True)
    after = len(reg.list_prefixes(path=seed["db"]))
    assert before == after  # no duplicates
    assert "create" not in report2.counts()  # everything already exists
    assert report2.counts().get("exists", 0) > 0


# ── tolerant parsing ───────────────────────────────────────────────────────────

def test_headerless_positional_fallback(tmp_path: Path):
    d = tmp_path / "seed"
    d.mkdir()
    (d / "ipv4.csv").write_text("C003,10.9.0.0,255.255.255.0\n")
    db = tmp_path / "r.db"
    report = run_import(ipv4_path=d / "ipv4.csv", db_path=db, apply=True)
    assert "C003" in report.sites_created
    prefixes = reg.list_prefixes(path=db)
    assert len(prefixes) == 1 and prefixes[0]["cidr"] == "10.9.0.0/24"


def test_reordered_and_extra_columns(tmp_path: Path):
    d = tmp_path / "seed"
    d.mkdir()
    # Columns reordered, an extra 'Region' column added, different header wording.
    (d / "ipv6.csv").write_text(
        "Region,Site,IPv6 Prefix,Length\n"
        "West,D004,1000:2000:3000:42,56\n"
    )
    db = tmp_path / "r.db"
    run_import(ipv6_path=d / "ipv6.csv", db_path=db, apply=True)
    site = reg.get_site_by_code("D004", path=db)
    assert site is not None
    p = reg.list_prefixes(site_id=site["id"], path=db)[0]
    assert p["cidr"] == "1000:2000:3000:4200::/56"
