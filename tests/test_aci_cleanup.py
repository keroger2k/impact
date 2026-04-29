import pytest
from unittest.mock import MagicMock, patch
from routers.aci import bgp_map, ospf_map, _get_processed_bgp_peers, _parse_l3out_from_dn

@pytest.mark.asyncio
async def test_bgp_map_response_structure():
    # Use DEV_MODE to get mock data
    from clients.aci import ACIClient
    client = ACIClient("http://apic", "admin", "pwd")

    with patch("dev.DEV_MODE", True), \
         patch("routers.aci.require_auth", return_value=None), \
         patch("routers.aci._get_aci_async", return_value=client), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()):

        request = MagicMock()
        request.query_params = {"debug": "1"}
        request.headers = {"Accept": "application/json"}

        response = await bgp_map(request, fabric_id="dc1")

        assert "leaves" in response
        assert "peers" in response
        assert "edges" in response
        assert "stats" in response
        assert "_debug" in response
        # In DEV_MODE, MOCK_ACI_BGP_PEERS has 3 peers, all ebgp
        assert response["stats"]["peer_count"] > 0

@pytest.mark.asyncio
async def test_ospf_map_response_structure():
    from clients.aci import ACIClient
    client = ACIClient("http://apic", "admin", "pwd")

    with patch("dev.DEV_MODE", True), \
         patch("routers.aci.require_auth", return_value=None), \
         patch("routers.aci._get_aci_async", return_value=client), \
         patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()):

        request = MagicMock()
        request.query_params = {"debug": "1"}
        request.headers = {"Accept": "application/json"}

        response = await ospf_map(request, fabric_id="dc1")

        assert "leaves" in response
        assert "peers" in response
        assert "edges" in response
        assert "stats" in response
        assert "_debug" in response

@pytest.mark.asyncio
async def test_processed_bgp_peers_returns_peer_to_l3out():
    mock_aci = MagicMock()
    mock_aci.get_bgp_peers.return_value = {"imdata": []}
    mock_aci.get_l3_subnets.return_value = {"imdata": []}
    mock_aci.get_bgp_peer_configs.return_value = {
        "imdata": [
            {"bgpPeerP": {"attributes": {"addr": "10.1.1.1", "dn": "uni/tn-T1/out-L1/..."}}}
        ]
    }

    import asyncio
    loop = asyncio.get_event_loop()

    with patch("routers.aci._cached", side_effect=lambda k, l, t=None: l()):
        res = await _get_processed_bgp_peers(mock_aci, loop, "dc1")

        assert len(res) == 4
        processed, deduped, raw, peer_to_l3out = res
        assert "10.1.1.1" in peer_to_l3out
        assert peer_to_l3out["10.1.1.1"]["l3out"] == "L1"

def test_parse_l3out_from_dn():
    # BGP peer DN
    dn1 = "topology/pod-1/node-101/sys/bgp/inst/dom-COMMON:default/peer-[10.255.0.1]/ent-[10.255.0.1]"
    p1 = _parse_l3out_from_dn(dn1)
    assert p1["node"] == "101"
    assert p1["pod"] == "1"
    assert p1["vrf"] == "COMMON:default"

    # L3Out DN
    dn2 = "uni/tn-PROD/out-L3OUT-CORE"
    p2 = _parse_l3out_from_dn(dn2)
    assert p2["tenant"] == "PROD"
    assert p2["l3out"] == "L3OUT-CORE"

    # URIB DN
    dn3 = "topology/pod-1/node-101/sys/uribv4/dom-COMMON:default"
    p3 = _parse_l3out_from_dn(dn3)
    assert p3["vrf"] == "COMMON:default"
    assert p3["node"] == "101"

    # No match
    dn4 = "uni/infra/funcprof"
    p4 = _parse_l3out_from_dn(dn4)
    assert all(v is None for v in p4.values())
