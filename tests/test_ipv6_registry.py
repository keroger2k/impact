"""Tests for clients.ipv6_registry — schema + CRUD against a tmp SQLite file."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from clients import ipv6_registry as reg


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "ipv6_registry_test.db"
    reg.init_schema(path)
    return path


def test_init_schema_is_idempotent(tmp_path: Path):
    path = tmp_path / "x.db"
    reg.init_schema(path)
    reg.init_schema(path)  # second call must not raise
    with reg.connect(path) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert {"sites", "allocations"}.issubset(tables)


def test_site_crud_roundtrip(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", role="datacenter",
                           description="Primary DC", path=db_path)
    assert site["id"] > 0
    assert site["prefix"] == "1000:2000:3000"
    assert site["prefix_length"] == 48

    fetched = reg.get_site(site["id"], path=db_path)
    assert fetched["name"] == "DC1"

    updated = reg.update_site(site["id"], description="Primary DC east", path=db_path)
    assert updated["description"] == "Primary DC east"

    assert reg.delete_site(site["id"], path=db_path) == 1
    assert reg.get_site(site["id"], path=db_path) is None


def test_create_site_with_non_default_prefix_length(db_path: Path):
    airport = reg.create_site("LAX-airport", "2600:0400:3031:0100",
                              prefix_length=56, role="airport", path=db_path)
    assert airport["prefix"] == "2600:0400:3031:0100"
    assert airport["prefix_length"] == 56


def test_site_prefix_is_unique_but_name_is_not(db_path: Path):
    """A site is identified by its prefix; names can repeat so one logical
    site can hold multiple disjoint IPv6 prefixes."""
    reg.create_site("DC1", "1000:2000:3000", path=db_path)
    # Duplicate name with a different prefix is allowed
    reg.create_site("DC1", "4000:5000:6000", path=db_path)
    assert len(reg.list_sites(path=db_path)) == 2
    # Duplicate prefix is still rejected
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_site("DC2", "1000:2000:3000", path=db_path)


def test_allocation_unique_vvvv_within_site(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    reg.create_allocation(site["id"], "0100", 64,
                          ipv4_subnet="1.2.3.0/24", path=db_path)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_allocation(site["id"], "0100", 56, path=db_path)


def test_same_vvvv_allowed_across_sites(db_path: Path):
    a = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    b = reg.create_site("DC2", "4000:5000:6000", path=db_path)
    reg.create_allocation(a["id"], "0100", 56, path=db_path)
    reg.create_allocation(b["id"], "0100", 56, path=db_path)  # not a conflict
    assert len(reg.list_allocations(path=db_path)) == 2


def test_cascade_delete_removes_allocations(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    reg.create_allocation(site["id"], "0100", 64, path=db_path)
    reg.create_allocation(site["id"], "0200", 64, path=db_path)
    assert len(reg.list_allocations(path=db_path)) == 2

    reg.delete_site(site["id"], path=db_path)
    assert reg.list_allocations(path=db_path) == []


def test_list_allocations_filters_by_site(db_path: Path):
    a = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    b = reg.create_site("DC2", "4000:5000:6000", path=db_path)
    reg.create_allocation(a["id"], "0100", 64, path=db_path)
    reg.create_allocation(b["id"], "0100", 64, path=db_path)
    assert len(reg.list_allocations(site_id=a["id"], path=db_path)) == 1
    assert len(reg.list_allocations(path=db_path)) == 2


def test_list_allocations_includes_site_metadata(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    reg.create_allocation(site["id"], "0100", 64, path=db_path)
    rows = reg.list_allocations(path=db_path)
    assert rows[0]["site_name"] == "DC1"
    assert rows[0]["site_prefix"] == "1000:2000:3000"
    assert rows[0]["site_prefix_length"] == 48


def test_find_ipv4_collision(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    a1 = reg.create_allocation(site["id"], "0100", 64,
                               ipv4_subnet="1.2.3.0/24", path=db_path)

    hits = reg.find_ipv4_collision(site["id"], "1.2.3.0/24", path=db_path)
    assert len(hits) == 1 and hits[0]["id"] == a1["id"]

    # Same v4 in a different site is not a collision (scoped per site)
    other = reg.create_site("DC2", "4000:5000:6000", path=db_path)
    assert reg.find_ipv4_collision(other["id"], "1.2.3.0/24", path=db_path) == []

    # Exclude-self lets update-in-place pass its own row
    assert reg.find_ipv4_collision(site["id"], "1.2.3.0/24",
                                   exclude_alloc_id=a1["id"], path=db_path) == []


def test_update_allocation_changes_only_supplied_fields(db_path: Path):
    site = reg.create_site("DC1", "1000:2000:3000", path=db_path)
    a = reg.create_allocation(site["id"], "0100", 64,
                              ipv4_subnet="1.2.3.0/24",
                              purpose="user-vlan", path=db_path)
    updated = reg.update_allocation(a["id"], status="reserved", path=db_path)
    assert updated["status"] == "reserved"
    assert updated["purpose"] == "user-vlan"  # untouched
    assert updated["ipv4_subnet"] == "1.2.3.0/24"


def test_migration_from_legacy_prefix_48_schema(tmp_path: Path):
    """An older DB with the prefix_48 column gets migrated in place to the
    current shape (prefix + prefix_length) without losing rows."""
    path = tmp_path / "legacy.db"
    legacy = """
        CREATE TABLE sites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            prefix_48   TEXT    NOT NULL UNIQUE,
            role        TEXT,
            description TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """
    with reg._connect_raw(path) as conn:
        conn.executescript(legacy)
        conn.execute("INSERT INTO sites (name, prefix_48) VALUES (?, ?)",
                     ("DC1", "1000:2000:3000"))

    reg.init_schema(path)

    sites = reg.list_sites(path=path)
    assert len(sites) == 1
    assert sites[0]["prefix"] == "1000:2000:3000"
    assert sites[0]["prefix_length"] == 48


def test_migration_drops_unique_on_name(tmp_path: Path):
    """A DB that still carries UNIQUE on sites.name gets migrated to allow
    duplicate names. The prefix UNIQUE survives, and existing allocations
    keep their FK pointing at the recreated parent row."""
    path = tmp_path / "legacy_name_unique.db"
    legacy = """
        CREATE TABLE sites (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL UNIQUE,
            prefix        TEXT    NOT NULL UNIQUE,
            prefix_length INTEGER NOT NULL DEFAULT 48,
            role          TEXT,
            description   TEXT,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE allocations (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id        INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            vvvv           TEXT    NOT NULL,
            prefix_length  INTEGER NOT NULL,
            ipv4_subnet    TEXT,
            purpose        TEXT,
            status         TEXT    NOT NULL DEFAULT 'allocated',
            owner          TEXT,
            description    TEXT,
            created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE (site_id, vvvv)
        );
    """
    with reg._connect_raw(path) as conn:
        conn.executescript(legacy)
        cur = conn.execute(
            "INSERT INTO sites (name, prefix) VALUES (?, ?)",
            ("DC1", "1000:2000:3000"),
        )
        site_id = cur.lastrowid
        conn.execute(
            "INSERT INTO allocations (site_id, vvvv, prefix_length) VALUES (?, ?, ?)",
            (site_id, "0100", 64),
        )

    reg.init_schema(path)

    # UNIQUE on name is gone — duplicate names now allowed
    reg.create_site("DC1", "4000:5000:6000", path=path)
    assert len(reg.list_sites(path=path)) == 2

    # Prefix UNIQUE is preserved
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_site("DC1-dup", "1000:2000:3000", path=path)

    # FK from the pre-existing allocation still resolves to the original site
    allocs = reg.list_allocations(path=path)
    assert len(allocs) == 1
    assert allocs[0]["site_id"] == site_id
    assert allocs[0]["site_name"] == "DC1"
