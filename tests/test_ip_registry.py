"""Tests for clients.ip_registry — dual-stack site-centric schema + CRUD,
plus the family-agnostic CIDR helpers in utils.ipam_net."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from clients import ip_registry as reg
from utils import ipam_net


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "ip_registry_test.db"
    reg.init_schema(path)
    return path


# ── schema ────────────────────────────────────────────────────────────────────

def test_init_schema_is_idempotent(tmp_path: Path):
    path = tmp_path / "x.db"
    reg.init_schema(path)
    reg.init_schema(path)  # second call must not raise
    with reg.connect(path) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert {"sites", "prefixes"}.issubset(tables)


# ── sites ──────────────────────────────────────────────────────────────────────

def test_site_crud_and_code_is_join_key(db: Path):
    site = reg.create_site("K015", name="Site K015", region="CA",
                           role="airport", path=db)
    assert site["id"] > 0
    assert site["site_code"] == "K015"

    by_code = reg.get_site_by_code("k015", path=db)  # NOCASE
    assert by_code and by_code["id"] == site["id"]

    updated = reg.update_site(site["id"], description="updated", path=db)
    assert updated["description"] == "updated"

    assert reg.delete_site(site["id"], path=db) == 1
    assert reg.get_site(site["id"], path=db) is None


def test_site_code_is_unique(db: Path):
    reg.create_site("K015", path=db)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_site("K015", path=db)


def test_upsert_site_creates_then_updates(db: Path):
    row, created = reg.upsert_site("I001", name="first", path=db)
    assert created is True and row["name"] == "first"

    row2, created2 = reg.upsert_site("I001", region="MS", path=db)
    assert created2 is False
    assert row2["id"] == row["id"]
    assert row2["region"] == "MS"
    assert row2["name"] == "first"  # untouched (None means leave alone)
    assert len(reg.list_sites(path=db)) == 1


# ── prefixes: dual stack + canonicalization ────────────────────────────────────

def test_create_prefix_canonicalizes_both_families(db: Path):
    site = reg.create_site("K032", path=db)

    # IPv4 supplied as address + netmask, with host bits set.
    v4 = reg.create_prefix("10.45.44.7/255.255.255.0", site_id=site["id"],
                           role="site-aggregate", source="csv", path=db)
    assert v4["family"] == 4
    assert v4["cidr"] == "10.45.44.0/24"
    assert v4["network"] == "10.45.44.0"
    assert v4["prefix_length"] == 24

    # IPv6 /56 with messy host bits.
    v6 = reg.create_prefix("2600:400:3007:0700::/56", site_id=site["id"],
                           role="site", path=db)
    assert v6["family"] == 6
    assert v6["cidr"] == "2600:400:3007:700::/56"


def test_create_prefix_rejects_garbage(db: Path):
    site = reg.create_site("K023", path=db)
    with pytest.raises(ValueError):
        reg.create_prefix("not-a-network", site_id=site["id"], path=db)


def test_duplicate_cidr_per_site_blocked_but_cross_site_ok(db: Path):
    a = reg.create_site("AAA1", path=db)
    b = reg.create_site("BBB1", path=db)
    reg.create_prefix("10.0.0.0/24", site_id=a["id"], path=db)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_prefix("10.0.0.0/24", site_id=a["id"], path=db)
    # Same CIDR under a different site is allowed (the registry doesn't enforce
    # global uniqueness — overlap is a soft audit signal, not a hard block).
    reg.create_prefix("10.0.0.0/24", site_id=b["id"], path=db)
    assert len(reg.list_prefixes(path=db)) == 2


def test_list_prefixes_filters_by_site_and_family(db: Path):
    s = reg.create_site("K033", path=db)
    reg.create_prefix("10.161.192.0/22", site_id=s["id"], path=db)
    reg.create_prefix("2600:400:3010:1400::/56", site_id=s["id"], path=db)

    assert len(reg.list_prefixes(site_id=s["id"], path=db)) == 2
    assert len(reg.list_prefixes(site_id=s["id"], family=4, path=db)) == 1
    assert len(reg.list_prefixes(site_id=s["id"], family=6, path=db)) == 1
    # Joined site_code comes through for the UI.
    assert reg.list_prefixes(site_id=s["id"], path=db)[0]["site_code"] == "K033"


# ── shared containers (STIP /48) + hierarchy ───────────────────────────────────

def test_stip_container_shared_with_per_site_children(db: Path):
    stip, created = reg.get_or_create_container(
        "2600:400:3059::/48", role="container", label="STIP", path=db)
    assert created is True
    # Idempotent: second call returns the same row, doesn't duplicate.
    stip2, created2 = reg.get_or_create_container("2600:0400:3059::/48", path=db)
    assert created2 is False and stip2["id"] == stip["id"]

    i001 = reg.create_site("I001", path=db)
    child = reg.create_prefix("2600:400:3059:0::/64", site_id=i001["id"],
                              parent_id=stip["id"], role="stip", vvvv="0000",
                              label="STIP VLAN", path=db)
    assert child["parent_id"] == stip["id"]
    assert child["site_id"] == i001["id"]

    # Container is excluded from a site's own list, surfaced via containers_only.
    assert reg.list_prefixes(site_id=i001["id"], path=db) == [
        p for p in reg.list_prefixes(site_id=i001["id"], path=db)
    ]
    assert len(reg.list_prefixes(site_id=i001["id"], path=db)) == 1
    containers = reg.list_prefixes(containers_only=True, path=db)
    assert len(containers) == 1 and containers[0]["cidr"] == "2600:400:3059::/48"


def test_deleting_site_cascades_prefixes_but_keeps_container(db: Path):
    stip, _ = reg.get_or_create_container("2600:400:3059::/48", path=db)
    site = reg.create_site("I002", path=db)
    reg.create_prefix("2600:400:3059:1::/64", site_id=site["id"],
                      parent_id=stip["id"], role="stip", path=db)

    reg.delete_site(site["id"], path=db)
    assert reg.list_prefixes(site_id=site["id"], path=db) == []
    # The shared /48 survives the site deletion.
    assert reg.find_prefix_by_cidr("2600:400:3059::/48", path=db) is not None


# ── audit columns + overlap ────────────────────────────────────────────────────

def test_set_audit_state_stamps_seen(db: Path):
    s = reg.create_site("T573", path=db)
    p = reg.create_prefix("10.1.2.0/24", site_id=s["id"], path=db)
    assert p["audit_state"] is None and p["last_seen_at"] is None

    stamped = reg.set_audit_state(p["id"], "in-sync", last_seen_source="dnac",
                                  seen=True, path=db)
    assert stamped["audit_state"] == "in-sync"
    assert stamped["last_seen_source"] == "dnac"
    assert stamped["last_seen_at"] is not None


def test_find_overlapping_prefixes(db: Path):
    s = reg.create_site("K037", path=db)
    reg.create_prefix("10.251.192.0/18", site_id=s["id"], path=db)
    hits = reg.find_overlapping_prefixes("10.251.200.0/24", site_id=s["id"], path=db)
    assert len(hits) == 1
    # A disjoint block does not overlap.
    assert reg.find_overlapping_prefixes("10.99.0.0/24", site_id=s["id"], path=db) == []


# ── utils.ipam_net ─────────────────────────────────────────────────────────────

def test_ipam_net_canonical_and_relations():
    assert ipam_net.canonical("10.0.0.5/24") == (4, "10.0.0.0", 24, "10.0.0.0/24")
    fam, net, plen, cidr = ipam_net.canonical("2600:400:3059:0::/64")
    assert (fam, plen, cidr) == (6, 64, "2600:400:3059::/64")

    assert ipam_net.contains("10.0.0.0/16", "10.0.5.0/24") is True
    assert ipam_net.contains("10.0.5.0/24", "10.0.0.0/16") is False
    # Cross-family never overlaps and never raises.
    assert ipam_net.overlaps("10.0.0.0/24", "2600:400::/48") is False


# ── R2: shared-container uniqueness (partial unique index) ─────────────────────

def test_duplicate_container_is_rejected_by_index(db: Path):
    reg.create_prefix("10.100.0.0/21", site_id=None, role="container", path=db)
    # A second NULL-site row with the same CIDR must be rejected — plain
    # UNIQUE(site_id, cidr) wouldn't catch it because NULL is distinct.
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_prefix("10.100.0.0/21", site_id=None, role="container", path=db)
    # A same-CIDR row owned by a site is still allowed (different scope).
    s = reg.create_site("K100", path=db)
    reg.create_prefix("10.100.0.0/21", site_id=s["id"], path=db)


def test_get_or_create_container_idempotent_under_index(db: Path):
    c1, new1 = reg.get_or_create_container("10.100.0.0/21", path=db)
    c2, new2 = reg.get_or_create_container("10.100.0.0/21", path=db)
    assert new1 is True and new2 is False
    assert c1["id"] == c2["id"]
    assert len(reg.list_prefixes(containers_only=True, path=db)) == 1


def test_init_schema_dedupes_legacy_duplicate_containers(tmp_path: Path):
    # Simulate a pre-index DB: build just the tables, insert two identical
    # containers + a child pointing at the second, then run init_schema (which
    # de-dupes before building the partial unique index).
    path = tmp_path / "legacy.db"
    conn = reg._connect_raw(path)
    conn.executescript(reg.SCHEMA)  # tables + regular indexes, no partial index
    for _ in range(2):
        conn.execute(
            "INSERT INTO prefixes (site_id, family, network, prefix_length, cidr, "
            "role, status, source) VALUES (NULL,4,'10.100.0.0',21,'10.100.0.0/21',"
            "'container','allocated','manual')")
    keep, victim = [r[0] for r in conn.execute(
        "SELECT id FROM prefixes WHERE site_id IS NULL ORDER BY id").fetchall()]
    cur = conn.execute("INSERT INTO sites (site_code) VALUES ('K900')")
    sid = cur.lastrowid
    conn.execute(
        "INSERT INTO prefixes (site_id, parent_id, family, network, prefix_length, "
        "cidr, role, status, source) VALUES (?,?,6,'2600:400:3059:1',64,"
        "'2600:400:3059:1::/64','stip','allocated','manual')", (sid, victim))
    conn.commit()
    conn.close()

    reg.init_schema(path)  # de-dupe + create the partial unique index

    containers = reg.list_prefixes(containers_only=True, path=path)
    assert len(containers) == 1 and containers[0]["id"] == keep
    # The orphaned child was re-pointed to the surviving container.
    child = reg.list_prefixes(site_id=sid, path=path)[0]
    assert child["parent_id"] == keep


def test_ipam_net_find_container_longest_prefix():
    rows = [{"id": 1, "cidr": "10.0.0.0/8"}, {"id": 2, "cidr": "10.45.0.0/16"}]
    best = ipam_net.find_container("10.45.44.0/24", rows)
    assert best["id"] == 2  # the /16, not the /8


def test_ipam_net_smallest_covering():
    assert ipam_net.smallest_covering(["10.0.0.0/24", "10.0.1.0/24"]) == "10.0.0.0/23"
    assert ipam_net.smallest_covering([]) is None
    # Mixed families have no single cover.
    assert ipam_net.smallest_covering(["10.0.0.0/24", "2600:400::/48"]) is None
