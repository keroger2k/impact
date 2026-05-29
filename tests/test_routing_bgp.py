"""Tests for the VRF/all-AF-aware BGP neighbor parser (routers.routing).

The BGP health panel now collects `show ip bgp all neighbors` (IOS) /
`show bgp all neighbors` (NXOS) so neighbors in *any* VRF and either family are
captured — the old per-AF summary commands only saw the global table.
"""
from routers.routing import _parse_bgp_neighbors


IOS_OUTPUT = """BGP neighbor is 10.0.0.1,  remote AS 65010, external link
  BGP version 4, remote router ID 10.0.0.1
  BGP state = Established, up for 2w1d
BGP neighbor is 10.0.0.5,  vrf RED,  remote AS 65020, external link
  BGP version 4, remote router ID 10.0.0.5
  BGP state = Idle
BGP neighbor is 1000:2000:3000::2,  vrf RED,  remote AS 65020, external link
  BGP version 4
  BGP state = Established, up for 00:10:00
"""


def test_parses_all_families_and_vrfs():
    n = _parse_bgp_neighbors(IOS_OUTPUT)
    assert len(n) == 3
    by_ip = {x["ip"]: x for x in n}

    assert by_ip["10.0.0.1"]["family"] == 4
    assert by_ip["10.0.0.1"]["vrf"] == "default"      # global table
    assert by_ip["10.0.0.1"]["remote_as"] == "65010"
    assert by_ip["10.0.0.1"]["established"] is True

    # A VRF neighbor — previously invisible to the summary command.
    assert by_ip["10.0.0.5"]["vrf"] == "RED"
    assert by_ip["10.0.0.5"]["established"] is False
    assert by_ip["10.0.0.5"]["state"] == "Idle"

    # IPv6 neighbor inside a VRF.
    assert by_ip["1000:2000:3000::2"]["family"] == 6
    assert by_ip["1000:2000:3000::2"]["vrf"] == "RED"
    assert by_ip["1000:2000:3000::2"]["established"] is True


def test_family_and_up_counts():
    n = _parse_bgp_neighbors(IOS_OUTPUT)
    assert sum(1 for x in n if x["family"] == 4) == 2
    assert sum(1 for x in n if x["family"] == 6) == 1
    assert sum(1 for x in n if x["established"]) == 2


def test_nxos_style_block_parses():
    nxos = (
        "BGP neighbor is 10.0.0.9, remote AS 65030, ebgp link, Peer index 1\n"
        "  BGP version 4, remote router ID 10.0.0.9\n"
        "  BGP state = Established, up for 1d2h\n"
    )
    n = _parse_bgp_neighbors(nxos)
    assert len(n) == 1
    assert n[0]["ip"] == "10.0.0.9" and n[0]["remote_as"] == "65030"
    assert n[0]["vrf"] == "default" and n[0]["established"] is True


def test_empty_and_none_are_safe():
    assert _parse_bgp_neighbors(None) == []
    assert _parse_bgp_neighbors("") == []
    assert _parse_bgp_neighbors("no neighbors configured") == []
