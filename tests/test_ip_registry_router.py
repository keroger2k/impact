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
        {"cidr": "1000:2000:3059::/48", "container": True, "role": "stip-agg"}]),
        session=None)
    container = registry.list_prefixes(containers_only=True, path=tmpdb)[0]

    res = await r.audit_accept(items=json.dumps([
        {"cidr": "1000:2000:3059:1::/64", "site_code": "K700", "role": "stip"}]),
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


@pytest.mark.asyncio
async def test_assemble_auto_vvvv_keeps_non48_site_fixed_bits(tmpdb):
    # A /56 site fixes the high byte of hextet 4. With vvvv on "auto" the
    # assembled address must stay inside the site prefix (…:1200::), not zero
    # those bits out to …::.
    site = registry.create_site("K040", path=tmpdb)
    v6 = registry.create_prefix("1000:2000:3000:1200::/56", site_id=site["id"],
                                role="site", path=tmpdb)
    out = await r.assemble(_req(), prefix_id=v6["id"], ipv4="1.2.3.4",
                           vvvv=None, session=None)
    assert out["ipv6"] == "1000:2000:3000:1200::102:304"
    assert out["vvvv"] == "1200"


@pytest.mark.asyncio
async def test_assemble_bulk_resolves_vvvv_per_host_via_vlan(tmpdb):
    site = registry.create_site("K015", path=tmpdb)
    sid = site["id"]
    # The site's IPv6 /56, a VLAN-tagged IPv4 subnet, and the /64 carrying the
    # same VLAN (whose vvvv the host should resolve to). Created via the client
    # directly so the router's soft-overlap guard doesn't block the nested rows.
    v6 = registry.create_prefix("1000:2000:3000:1900::/56", site_id=sid,
                                role="site", path=tmpdb)
    registry.create_prefix("1.2.3.0/24", site_id=sid, role="subnet",
                           vlan_id=500, path=tmpdb)
    registry.create_prefix("1000:2000:3000:1900::/64", site_id=sid, role="stip",
                           vlan_id=500, vvvv="1900", path=tmpdb)

    out = await r.assemble_bulk(
        _req(),
        prefix_id=v6["id"],
        # in-subnet host, an out-of-subnet host, and a garbage token
        ipv4_list="1.2.3.4\n9.9.9.9\nnonsense",
        session=None,
    )
    assert out["counts"] == {"ok": 1, "no_match": 1, "invalid": 1}
    by_ip = {row["ipv4"]: row for row in out["rows"]}
    assert by_ip["1.2.3.4"]["status"] == "ok"
    assert by_ip["1.2.3.4"]["ipv6"] == "1000:2000:3000:1900::102:304"
    assert by_ip["1.2.3.4"]["vvvv"] == "1900"
    assert by_ip["1.2.3.4"]["vlan"] == 500
    assert by_ip["9.9.9.9"]["status"] == "no_match"
    assert by_ip["nonsense"]["status"] == "invalid"


@pytest.mark.asyncio
async def test_assemble_bulk_no_match_when_vlan_has_no_v6(tmpdb):
    # IPv4 prefix is VLAN-tagged but no IPv6 /64 carries that VLAN → no match,
    # and the reason names the VLAN so it's diagnosable.
    site = registry.create_site("K016", path=tmpdb)
    sid = site["id"]
    v6 = registry.create_prefix("1000:2000:3000::/48", site_id=sid,
                                role="site", path=tmpdb)
    registry.create_prefix("1.2.3.0/24", site_id=sid, role="subnet",
                           vlan_id=700, path=tmpdb)

    out = await r.assemble_bulk(_req(), prefix_id=v6["id"], ipv4_list="1.2.3.4",
                                session=None)
    assert out["counts"]["no_match"] == 1
    assert "VLAN 700" in out["rows"][0]["detail"]


@pytest.mark.asyncio
async def test_assemble_bulk_rejects_too_specific_prefix(tmpdb):
    site = registry.create_site("K017", path=tmpdb)
    v6 = registry.create_prefix("1000:2000:3000:1900::/64", site_id=site["id"],
                                role="stip", vvvv="1900", path=tmpdb)
    with pytest.raises(HTTPException) as exc:
        await r.assemble_bulk(_req(), prefix_id=v6["id"], ipv4_list="1.2.3.4",
                              session=None)
    assert exc.value.status_code == 400
