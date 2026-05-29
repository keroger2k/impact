"""Tests for utils.site_aggregator.registry_for_site — the Site Lookup page's
IP Registry rollup (now backed by the dual-stack clients.ip_registry, keyed on
site_code, replacing the deprecated IPv6-only registry lookup)."""
from __future__ import annotations

from pathlib import Path

import pytest

import clients.ip_registry as registry
from utils import site_aggregator as agg


@pytest.fixture
def tmpdb(tmp_path: Path, monkeypatch):
    db = tmp_path / "reg.db"
    monkeypatch.setattr(registry, "DB_PATH", db)
    monkeypatch.setattr(registry, "_initialized", False)
    registry.init_schema(db)
    return db


def test_registry_for_site_returns_both_families(tmpdb):
    s = registry.create_site("K023", path=tmpdb)
    registry.create_prefix("10.45.0.0/16", site_id=s["id"], role="site-aggregate", path=tmpdb)
    registry.create_prefix("1000:2000:3000::/56", site_id=s["id"], role="site", path=tmpdb)

    out = agg.registry_for_site("k023")  # case-insensitive on the join key
    assert out is not None
    assert out["site"]["site_code"] == "K023"
    assert len(out["v4"]) == 1
    assert len(out["v6"]) == 1
    assert len(out["prefixes"]) == 2


def test_registry_for_site_unknown_code_is_none(tmpdb):
    assert agg.registry_for_site("ZZZZ") is None


def test_registry_for_site_blank_is_none(tmpdb):
    assert agg.registry_for_site("") is None


def test_registry_for_site_with_no_prefixes(tmpdb):
    registry.create_site("K099", path=tmpdb)
    out = agg.registry_for_site("K099")
    assert out is not None and out["prefixes"] == []
    assert out["v4"] == [] and out["v6"] == []


def test_dmvpn_overlays_for_site(tmpdb):
    registry.bulk_accept([{
        "cidr": "10.100.216.0/21", "container": True, "role": "dmvpn",
        "label": "Tunnel200", "participants": ["K010", "K020"],
    }], path=tmpdb)

    out = agg.dmvpn_overlays_for_site("k010")  # case-insensitive
    assert len(out) == 1
    assert out[0]["cidr"] == "10.100.216.0/21"
    assert out[0]["label"] == "Tunnel200"
    assert "K010" in out[0]["participants"]

    # A site that isn't a participant gets nothing — even with no registry row.
    assert agg.dmvpn_overlays_for_site("K999") == []
