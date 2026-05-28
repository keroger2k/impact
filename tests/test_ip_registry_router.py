"""Router-level tests for routers.ip_registry — calls the async endpoints
directly (the project's pattern, see test_aci_interfaces) against a tmp DB, so
auth/CSRF middleware is out of scope here. All Form params are passed
explicitly because unfilled Form(...) defaults are FieldInfo objects, not None."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import clients.ip_registry as registry
from fastapi import HTTPException
from routers import ip_registry as r


@pytest.fixture
def tmpdb(tmp_path: Path, monkeypatch):
    db = tmp_path / "reg.db"
    monkeypatch.setattr(registry, "DB_PATH", db)
    monkeypatch.setattr(registry, "_initialized", False)
    registry.init_schema(db)
    return db


def _req(hx: bool = False):
    m = MagicMock()
    m.headers = {"HX-Request": "true"} if hx else {}
    return m


@pytest.mark.asyncio
async def test_create_site_uppercases_and_rejects_dupes(tmpdb):
    site = await r.create_site(site_code="k001", name="Site 1", region=None,
                               role=None, status="active", description=None,
                               session=None)
    assert site["site_code"] == "K001"
    with pytest.raises(HTTPException) as exc:
        await r.create_site(site_code="k001", name=None, region=None, role=None,
                            status="active", description=None, session=None)
    assert exc.value.status_code == 409

    listed = await r.list_sites(_req(), session=None)
    assert listed["total"] == 1
    assert listed["items"][0]["v4_count"] == 0


@pytest.mark.asyncio
async def test_prefix_overlap_is_soft_blocked(tmpdb):
    site = await r.create_site(site_code="K032", name=None, region=None,
                               role=None, status="active", description=None,
                               session=None)
    sid = site["id"]
    ok = await r.create_prefix(cidr="10.45.0.0/16", site_id=sid, parent_id=None,
                               role="site-aggregate", vlan_id=None, label=None,
                               status="allocated", source="manual", owner=None,
                               description=None, confirm_overlap=False, session=None)
    assert ok["prefix"]["cidr"] == "10.45.0.0/16"

    with pytest.raises(HTTPException) as exc:
        await r.create_prefix(cidr="10.45.44.0/24", site_id=sid, parent_id=None,
                              role=None, vlan_id=None, label=None,
                              status="allocated", source="manual", owner=None,
                              description=None, confirm_overlap=False, session=None)
    assert exc.value.status_code == 409

    # Same submission with the confirm flag goes through.
    forced = await r.create_prefix(cidr="10.45.44.0/24", site_id=sid, parent_id=None,
                                   role=None, vlan_id=None, label=None,
                                   status="allocated", source="manual", owner=None,
                                   description=None, confirm_overlap=True, session=None)
    assert forced["prefix"]["cidr"] == "10.45.44.0/24"


@pytest.mark.asyncio
async def test_bad_cidr_is_400(tmpdb):
    with pytest.raises(HTTPException) as exc:
        await r.create_prefix(cidr="not-a-network", site_id=None, parent_id=None,
                              role=None, vlan_id=None, label=None,
                              status="allocated", source="manual", owner=None,
                              description=None, confirm_overlap=False, session=None)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_bulk_accept_creates_sites_and_dedupes(tmpdb):
    existing = await r.create_site(site_code="K001", name=None, region=None,
                                   role=None, status="active", description=None,
                                   session=None)
    items = json.dumps([
        {"cidr": "10.1.0.0/24", "site_id": existing["id"]},   # into existing site
        {"cidr": "10.9.0.0/24", "site_code": "K050"},          # auto-create site
        {"cidr": "10.9.0.0/24", "site_code": "K050"},          # dup → skipped
        {"cidr": "garbage", "site_code": "K050"},              # error
    ])
    res = await r.audit_accept(items=items, session=None)
    assert res["created"] == 2
    assert res["skipped"] == 1
    assert res["sites_created"] == ["K050"]
    assert len(res["errors"]) == 1

    # K050 was created and carries exactly the one accepted prefix.
    k050 = registry.get_site_by_code("K050", path=tmpdb)
    assert k050 is not None
    k050_prefixes = registry.list_prefixes(site_id=k050["id"], path=tmpdb)
    assert len(k050_prefixes) == 1
    assert k050_prefixes[0]["source"] == "audit"
    assert k050_prefixes[0]["status"] == "deployed"


@pytest.mark.asyncio
async def test_bulk_accept_rejects_non_array(tmpdb):
    with pytest.raises(HTTPException) as exc:
        await r.audit_accept(items='{"cidr": "10.0.0.0/24"}', session=None)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_export_csv(tmpdb):
    site = await r.create_site(site_code="K015", name="K015", region=None,
                               role=None, status="active", description=None,
                               session=None)
    await r.create_prefix(cidr="10.25.0.0/16", site_id=site["id"], parent_id=None,
                          role="site-aggregate", vlan_id=None, label=None,
                          status="allocated", source="csv", owner=None,
                          description=None, confirm_overlap=False, session=None)
    resp = await r.export_csv(session=None)
    body = resp.body.decode("utf-8-sig")
    assert "site_code,site_name,family,cidr" in body
    assert "K015" in body and "10.25.0.0/16" in body


@pytest.mark.asyncio
async def test_assemble_uses_registry_v6_prefix(tmpdb):
    site = await r.create_site(site_code="K015", name=None, region=None,
                               role=None, status="active", description=None,
                               session=None)
    v6 = await r.create_prefix(cidr="1000:2000:3000:1900::/56", site_id=site["id"],
                               parent_id=None, role="site", vlan_id=None,
                               label=None, status="allocated", source="manual",
                               owner=None, description=None, confirm_overlap=False,
                               session=None)
    out = await r.assemble(_req(), prefix_id=v6["prefix"]["id"], ipv4="1.2.3.4",
                           vvvv="1900", session=None)
    # vvvv 1900 + ipv4 1.2.3.4 under 1000:2000:3000::/48-style carve.
    assert out["ipv6"].startswith("1000:2000:3000:1900")
    assert out["ipv4"] == "1.2.3.4"
