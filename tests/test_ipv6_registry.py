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
    site = reg.create_site("DC1", "2600:0400:3001", role="datacenter",
                           description="Primary DC", path=db_path)
    assert site["id"] > 0
    assert site["prefix_48"] == "2600:0400:3001"

    fetched = reg.get_site(site["id"], path=db_path)
    assert fetched["name"] == "DC1"

    updated = reg.update_site(site["id"], description="Primary DC east", path=db_path)
    assert updated["description"] == "Primary DC east"

    assert reg.delete_site(site["id"], path=db_path) == 1
    assert reg.get_site(site["id"], path=db_path) is None


def test_site_unique_name_and_prefix(db_path: Path):
    reg.create_site("DC1", "2600:0400:3001", path=db_path)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_site("DC1", "2600:0400:3002", path=db_path)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_site("DC2", "2600:0400:3001", path=db_path)


def test_allocation_unique_vvvv_within_site(db_path: Path):
    site = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    reg.create_allocation(site["id"], "0134", 64,
                          ipv4_subnet="10.16.109.0/24", path=db_path)
    with pytest.raises(sqlite3.IntegrityError):
        reg.create_allocation(site["id"], "0134", 56, path=db_path)


def test_same_vvvv_allowed_across_sites(db_path: Path):
    a = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    b = reg.create_site("DC2", "2600:0400:3002", path=db_path)
    reg.create_allocation(a["id"], "0100", 56, path=db_path)
    reg.create_allocation(b["id"], "0100", 56, path=db_path)  # not a conflict
    assert len(reg.list_allocations(path=db_path)) == 2


def test_cascade_delete_removes_allocations(db_path: Path):
    site = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    reg.create_allocation(site["id"], "0100", 64, path=db_path)
    reg.create_allocation(site["id"], "0200", 64, path=db_path)
    assert len(reg.list_allocations(path=db_path)) == 2

    reg.delete_site(site["id"], path=db_path)
    assert reg.list_allocations(path=db_path) == []


def test_list_allocations_filters_by_site(db_path: Path):
    a = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    b = reg.create_site("DC2", "2600:0400:3002", path=db_path)
    reg.create_allocation(a["id"], "0100", 64, path=db_path)
    reg.create_allocation(b["id"], "0100", 64, path=db_path)
    assert len(reg.list_allocations(site_id=a["id"], path=db_path)) == 1
    assert len(reg.list_allocations(path=db_path)) == 2


def test_list_allocations_includes_site_metadata(db_path: Path):
    site = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    reg.create_allocation(site["id"], "0134", 64, path=db_path)
    rows = reg.list_allocations(path=db_path)
    assert rows[0]["site_name"] == "DC1"
    assert rows[0]["site_prefix_48"] == "2600:0400:3001"


def test_find_ipv4_collision(db_path: Path):
    site = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    a1 = reg.create_allocation(site["id"], "0134", 64,
                               ipv4_subnet="10.16.109.0/24", path=db_path)

    hits = reg.find_ipv4_collision(site["id"], "10.16.109.0/24", path=db_path)
    assert len(hits) == 1 and hits[0]["id"] == a1["id"]

    # Same v4 in a different site is not a collision (scoped per site)
    other = reg.create_site("DC2", "2600:0400:3002", path=db_path)
    assert reg.find_ipv4_collision(other["id"], "10.16.109.0/24", path=db_path) == []

    # Exclude-self lets update-in-place pass its own row
    assert reg.find_ipv4_collision(site["id"], "10.16.109.0/24",
                                   exclude_alloc_id=a1["id"], path=db_path) == []


def test_update_allocation_changes_only_supplied_fields(db_path: Path):
    site = reg.create_site("DC1", "2600:0400:3001", path=db_path)
    a = reg.create_allocation(site["id"], "0134", 64,
                              ipv4_subnet="10.16.109.0/24",
                              purpose="user-vlan", path=db_path)
    updated = reg.update_allocation(a["id"], status="reserved", path=db_path)
    assert updated["status"] == "reserved"
    assert updated["purpose"] == "user-vlan"  # untouched
    assert updated["ipv4_subnet"] == "10.16.109.0/24"
