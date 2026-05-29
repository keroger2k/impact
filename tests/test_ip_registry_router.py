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
async def test_bulk_accept_container_is_shared_and_idempotent(tmpdb):
    items = json.dumps([{"cidr": "10.100.216.5/21", "container": True,
                         "role": "dmvpn", "label": "Tunnel200"}])
    res = await r.audit_accept(items=items, session=None)
    assert res["created"] == 1
    res2 = await r.audit_accept(items=items, session=None)   # idempotent
    assert res2["created"] == 0 and res2["skipped"] == 1

    containers = registry.list_prefixes(containers_only=True, path=tmpdb)
    assert len(containers) == 1
    assert containers[0]["cidr"] == "10.100.216.0/21"
    assert containers[0]["role"] == "dmvpn"
    assert containers[0]["site_id"] is None


@pytest.mark.asyncio
async def test_bulk_accept_rejects_non_array(tmpdb):
    with pytest.raises(HTTPException) as exc:
        await r.audit_accept(items='{"cidr": "10.0.0.0/24"}', session=None)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_bulk_accept_links_child_to_container_parent(tmpdb):
    # Accept a shared /48 container, then a site /64 that falls under it.
    await r.audit_accept(items=json.dumps([
        {"cidr": "2600:400:3059::/48", "container": True, "role": "stip-agg"}]),
        session=None)
    container = registry.list_prefixes(containers_only=True, path=tmpdb)[0]

    res = await r.audit_accept(items=json.dumps([
        {"cidr": "2600:400:3059:1::/64", "site_code": "K700", "role": "stip"}]),
        session=None)
    assert res["created"] == 1

    k700 = registry.get_site_by_code("K700", path=tmpdb)
    child = registry.list_prefixes(site_id=k700["id"], path=tmpdb)[0]
    assert child["parent_id"] == container["id"]  # R3: nested, not flat


@pytest.mark.asyncio
async def test_list_containers_reports_child_sites(tmpdb):
    # A STIP-style /48 container with one site /64 carved under it…
    await r.audit_accept(items=json.dumps([
        {"cidr": "1000:2000:3000::/48", "container": True, "role": "stip-agg"}]),
        session=None)
    await r.audit_accept(items=json.dumps([
        {"cidr": "1000:2000:3000:1::/64", "site_code": "K700"}]), session=None)
    # …plus a DMVPN overlay that has no children in the registry.
    await r.audit_accept(items=json.dumps([
        {"cidr": "10.100.216.0/21", "container": True, "role": "dmvpn"}]),
        session=None)

    out = await r.list_containers(_req(), session=None)
    by_cidr = {c["cidr"]: c for c in out["items"]}
    assert out["total"] == 2
    assert by_cidr["1000:2000:3000::/48"]["child_count"] == 1
    assert by_cidr["1000:2000:3000::/48"]["child_sites"] == ["K700"]
    assert by_cidr["10.100.216.0/21"]["child_count"] == 0
    assert by_cidr["10.100.216.0/21"]["role"] == "dmvpn"


@pytest.mark.asyncio
async def test_bulk_accept_persists_dmvpn_participants(tmpdb):
    items = json.dumps([{"cidr": "10.100.216.0/21", "container": True, "role": "dmvpn",
                         "label": "Tunnel200", "participants": ["K010", "K020", "K030"]}])
    res = await r.audit_accept(items=items, session=None)
    assert res["created"] == 1

    c = next(x for x in registry.list_shared_containers(path=tmpdb)
             if x["cidr"] == "10.100.216.0/21")
    assert c["participants"] == ["K010", "K020", "K030"]

    # The Shared tab surfaces the persisted participants as child sites.
    out = await r.list_containers(_req(), session=None)
    ov = next(x for x in out["items"] if x["cidr"] == "10.100.216.0/21")
    assert ov["child_sites"] == ["K010", "K020", "K030"]
    assert ov["child_count"] == 3


@pytest.mark.asyncio
async def test_reaccepting_overlay_refreshes_participants(tmpdb):
    await r.audit_accept(items=json.dumps([
        {"cidr": "10.100.0.0/21", "container": True, "role": "dmvpn",
         "participants": ["K010"]}]), session=None)
    res = await r.audit_accept(items=json.dumps([
        {"cidr": "10.100.0.0/21", "container": True, "role": "dmvpn",
         "participants": ["K010", "K099"]}]), session=None)
    assert res["skipped"] == 1  # already present, not duplicated
    c = next(x for x in registry.list_shared_containers(path=tmpdb)
             if x["cidr"] == "10.100.0.0/21")
    assert c["participants"] == ["K010", "K099"]  # membership refreshed


@pytest.mark.asyncio
async def test_list_containers_attributes_by_containment_without_parent_id(tmpdb):
    # Mimics seeded/legacy data: a shared supernet and a site block inside it,
    # with NO parent_id link. Child attribution must still find the site.
    registry.create_prefix("10.40.0.0/14", site_id=None, role="supernet",
                           source="manual", path=tmpdb)
    site = registry.create_site("K500", path=tmpdb)
    registry.create_prefix("10.41.0.0/16", site_id=site["id"], parent_id=None,
                           role="site-aggregate", path=tmpdb)

    out = await r.list_containers(_req(), session=None)
    sup = next(c for c in out["items"] if c["cidr"] == "10.40.0.0/14")
    assert sup["child_sites"] == ["K500"]
    assert sup["child_count"] == 1


@pytest.mark.asyncio
async def test_bulk_accept_validates_vlan_id(tmpdb):
    res = await r.audit_accept(items=json.dumps([
        {"cidr": "10.5.0.0/24", "site_code": "K800", "vlan_id": "99999"},  # out of range
        {"cidr": "10.6.0.0/24", "site_code": "K800", "vlan_id": "abc"},      # not an int
        {"cidr": "10.7.0.0/24", "site_code": "K800", "vlan_id": "100"},      # ok
    ]), session=None)
    assert res["created"] == 1
    assert len(res["errors"]) == 2
    # The bad rows errored before the site was touched, so it was created once.
    assert res["sites_created"] == ["K800"]


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
