import pytest
from unittest.mock import MagicMock, patch
from routers.aci import get_l3out_route_table

@pytest.fixture
def mock_aci():
    aci = MagicMock()
    aci.get.return_value = {"imdata": []}
    # Mock VRF bindings
    aci.get_l3out_vrf_bindings.return_value = {
        "imdata": [
            {"l3extRsEctx": {"attributes": {"dn": "uni/tn-COMMON/out-L3OUT-CORE/rsectx", "tDn": "uni/tn-COMMON/ctx-default"}}},
            {"l3extRsEctx": {"attributes": {"dn": "uni/tn-COMMON/out-L3OUT-SHARED/rsectx", "tDn": "uni/tn-COMMON/ctx-default"}}}
        ]
    }
    # Mock L3Out details
    aci.get_l3out_details.return_value = {
        "imdata": [{
            "l3extOut": {
                "attributes": {"name": "L3OUT-CORE", "dn": "uni/tn-COMMON/out-L3OUT-CORE"},
                "children": [
                    {
                        "l3extLNodeP": {
                            "attributes": {"name": "BorderLeafs", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs"},
                            "children": [
                                {"l3extRsNodeL3OutAtt": {"attributes": {"tDn": "topology/pod-1/node-101"}}},
                                {
                                    "l3extLIfP": {
                                        "attributes": {"name": "IF1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/lifp-IF1"},
                                        "children": [
                                            {"l3extRsPathL3OutAtt": {"attributes": {
                                                "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/lifp-IF1/rspathL3OutAtt-[topology/pod-1/paths-101/pathep-[eth1/49]]",
                                                "tDn": "topology/pod-1/paths-101/pathep-[eth1/49]",
                                                "addr": "10.255.0.254/30"
                                            }}}
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {"bgpPeerP": {"attributes": {"addr": "10.255.0.1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.1]"}}},
                ]
            }
        }]
    }
    return aci

# Helper to mock asyncio.gather correctly in our specific tests
async def mock_gather_local(*aws, **kwargs):
    results = []
    for aw in aws:
        results.append(await aw)
    return results

@pytest.mark.asyncio
async def test_route_table_returns_owned_and_other_routes(mock_aci):
    # Setup URIB mock
    urib_data = {
        "imdata": [
            {
                "uribv4Route": {
                    "attributes": {"prefix": "10.100.1.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/..."},
                    "children": [{"uribv4Nexthop": {"attributes": {"addr": "10.255.0.1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/.../intf-[eth1/49]"}}}]
                }
            },
            {
                "uribv4Route": {
                    "attributes": {"prefix": "172.16.100.0/24", "modTs": "2026-04-26T14:39:11.000Z", "dn": "topology/pod-1/node-101/..."},
                    "children": [{"uribv4Nexthop": {"attributes": {"addr": "172.16.99.1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/.../intf-[eth1/50]"}}}]
                }
            }
        ]
    }

    mock_aci.get_with_meta.return_value = {"data": urib_data, "status": 200}

    with patch("routers.aci._get_aci_async", return_value=mock_aci), \
         patch("routers.aci._get_bgp_caps", return_value={"uribv4": True, "uribv6": False, "apic_version": "5.2"}), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "name": "LEAF-101"}], {})), \
         patch("routers.aci.require_auth", return_value=None), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()), \
         patch("routers.aci._get_processed_bgp_peers", return_value=([], [], {}, {})), \
         patch("routers.aci._get_processed_ospf_peers", return_value=([], [], {})), \
         patch("routers.aci.asyncio.gather", side_effect=mock_gather_local):

        request = MagicMock()
        request.headers.get.return_value = None

        response = await get_l3out_route_table(request, dn="uni/tn-COMMON/out-L3OUT-CORE", family="v4", fabric_id="dc1")

        assert response["l3out_name"] == "L3OUT-CORE"
        assert len(response["routes"]) == 1
        assert response["routes"][0]["prefix"] == "10.100.1.0/24"
        assert len(response["vrf_other_routes"]) == 1
        assert response["vrf_other_routes"][0]["prefix"] == "172.16.100.0/24"

@pytest.mark.asyncio
async def test_route_table_filters_isis(mock_aci):
    urib_data = {
        "imdata": [{
            "uribv4Route": {
                "attributes": {"prefix": "10.255.99.0/24", "modTs": "2026-04-26T14:38:11.000Z"},
                "children": [{"uribv4Nexthop": {"attributes": {"addr": "1.1.1.1", "pref": "115", "routeType": "isis"}}}]
            }
        }]
    }
    mock_aci.get_with_meta.return_value = {"data": urib_data, "status": 200}

    with patch("routers.aci._get_aci_async", return_value=mock_aci), \
         patch("routers.aci._get_bgp_caps", return_value={"uribv4": True, "uribv6": False}), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "name": "LEAF-101"}], {})), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()), \
         patch("routers.aci._get_processed_bgp_peers", return_value=([], [], {}, {})), \
         patch("routers.aci._get_processed_ospf_peers", return_value=([], [], {})), \
         patch("routers.aci.asyncio.gather", side_effect=mock_gather_local):

        request = MagicMock()
        request.headers.get.return_value = None
        response = await get_l3out_route_table(request, dn="uni/tn-COMMON/out-L3OUT-CORE", family="v4", fabric_id="dc1")
        assert len(response["routes"]) == 0
        assert len(response["vrf_other_routes"]) == 0

@pytest.mark.asyncio
async def test_route_table_resolves_shared_vrf_banner(mock_aci):
    mock_aci.get_with_meta.return_value = {"data": {"imdata": []}, "status": 200}

    with patch("routers.aci._get_aci_async", return_value=mock_aci), \
         patch("routers.aci._get_bgp_caps", return_value={"uribv4": True, "uribv6": False}), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "name": "LEAF-101"}], {})), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()), \
         patch("routers.aci._get_processed_bgp_peers", return_value=([], [], {}, {})), \
         patch("routers.aci._get_processed_ospf_peers", return_value=([], [], {})), \
         patch("routers.aci.asyncio.gather", side_effect=mock_gather_local):

        request = MagicMock()
        request.headers.get.return_value = None
        response = await get_l3out_route_table(request, dn="uni/tn-COMMON/out-L3OUT-CORE", fabric_id="dc1")
        assert "L3OUT-SHARED" in response["shared_with"]

@pytest.mark.asyncio
async def test_route_table_handles_node_fetch_failure(mock_aci):
    mock_aci.get_with_meta.return_value = {"data": None, "status": 500, "error": "boom"}

    with patch("routers.aci._get_aci_async", return_value=mock_aci), \
         patch("routers.aci._get_bgp_caps", return_value={"uribv4": True, "uribv6": False}), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "name": "LEAF-101"}], {})), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()), \
         patch("routers.aci._get_processed_bgp_peers", return_value=([], [], {}, {})), \
         patch("routers.aci._get_processed_ospf_peers", return_value=([], [], {})), \
         patch("routers.aci.asyncio.gather", side_effect=mock_gather_local):

        request = MagicMock()
        request.headers.get.return_value = None
        response = await get_l3out_route_table(request, dn="uni/tn-COMMON/out-L3OUT-CORE", fabric_id="dc1")
        assert len(response["fetch_errors"]) == 1
        assert response["fetch_errors"][0]["error"] == "boom"
