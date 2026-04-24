import pytest
from routers.aci import get_node_interfaces
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_aci():
    aci = MagicMock()
    # Mock data using the corrected DN structure and attribute names
    aci.get_node_interfaces.return_value = {
        "imdata": [
            {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]", "id": "eth1/1", "adminSt": "up", "speed": "10G", "mtu": "9000", "layer": "Layer2", "mode": "trunk", "descr": "Direct"}}},
            {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]/phys", "operSt": "up", "operSpeed": "10G", "operDuplex": "full", "lastLinkStChg": "2023-10-27T10:00:00"}}},
            {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-101/sys/aggr-[po10]", "id": "po10", "pcMode": "active", "operSt": "up", "name": "PC-Policy"}}},
            {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-101/sys/aggr-[po10]/rsmbrIfs-[topology/pod-1/node-101/sys/phys-[eth1/1]]", "tDn": "topology/pod-1/node-101/sys/phys-[eth1/1]"}}},
            {"pcAggrMbrIf": {"attributes": {"dn": "topology/pod-1/node-101/sys/phys-[eth1/1]/aggrmbrif", "channelingSt": "channeling", "pcMode": "active"}}},
            {"vpcRsVpcConf": {"attributes": {"dn": "topology/pod-1/node-101/sys/vpc/inst/dom-1/if-10/rsvpcConf", "parentSKey": "10", "tDn": "topology/pod-1/node-101/sys/aggr-[po10]"}}}
        ]
    }
    return aci

@pytest.mark.asyncio
async def test_node_interfaces_join_logic(mock_aci):
    with patch("routers.aci._get_aci", return_value=mock_aci), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "dn": "topology/pod-1/node-101"}], {})), \
         patch("routers.aci.require_auth", return_value=None):

        request = MagicMock()
        request.headers = {}
        request.query_params = {}

        # Calling the router function directly
        response = await get_node_interfaces(request, "101", session=MagicMock(), fabric_id="dc1")

        interfaces = response["interfaces"]
        aggregates = response["aggregates"]

        # Verify eth1/1 is joined correctly
        eth1 = next(i for i in interfaces if i["id"] == "eth1/1")
        assert eth1["operSt"] == "up"
        assert eth1["channel"] == "po10"
        assert eth1["lacp"] == "active"
        assert eth1["lacp_state"] == "channeling"
        assert eth1["vpc"] == "vPC-10"
        assert eth1["descr"] == "Direct" # Preference for direct descr

        # Verify aggregate
        po10 = next(a for a in aggregates if a["id"] == "po10")
        assert po10["pcMode"] == "active"
        assert "eth1/1" in po10["members"]
        assert po10["vpc"] == "vPC-10"

@pytest.mark.asyncio
async def test_node_interfaces_descr_fallback(mock_aci):
    from cache import cache
    cache.invalidate_prefix("aci_")

    # Set physical descr to empty to test fallback
    mock_aci.get_node_interfaces.return_value["imdata"][0]["l1PhysIf"]["attributes"]["descr"] = ""

    with patch("routers.aci._get_aci", return_value=mock_aci), \
         patch("routers.aci._get_processed_nodes", return_value=([{"id": "101", "dn": "topology/pod-1/node-101"}], {})), \
         patch("routers.aci.require_auth", return_value=None):

        request = MagicMock()
        request.headers = {}
        request.query_params = {}

        response = await get_node_interfaces(request, "101", session=MagicMock(), fabric_id="dc1")
        interfaces = response["interfaces"]
        eth1 = next(i for i in interfaces if i["id"] == "eth1/1")
        assert eth1["descr"] == "PC-Policy" # Fallback to PC policy name
