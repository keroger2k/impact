"""Tests for the EIGRP/OSPF neighbor row parsers (routers.routing) that back
the structured neighbor tables on the Site Lookup routing panels. The count
helpers stay authoritative for the header badge; these add per-row structure.

All addressing here is fake per the repo IP policy (docs/IP_ADDRESS_POLICY.md):
documentation/example values only — never real network data."""
from routers.routing import (
    _parse_eigrp_v4,
    _parse_eigrp_v6,
    _parse_ospf_neighbors,
    _ospf_state_class,
)


EIGRP_V4 = """EIGRP-IPv4 Neighbors for AS(22)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
2   1.2.3.4                 Vl199                    12 7w1d        1   100  0  4205269
0   5.6.7.8                 Twe1/0/5                 14 19w1d       1   100  3  5151
"""

# IPv6 EIGRP: the neighbor prints "Link-local address:" on the row and the
# FE80:: address on the following line.
EIGRP_V6 = """EIGRP-IPv6 Neighbors for AS(22)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   Link-local address:     Vl199                    13 7w1d        1   100  0  1192311
    FE80::1
"""

OSPF_V4 = """Neighbor ID     Pri   State           Dead Time   Address         Interface
1.1.1.1           1   FULL/DR         00:00:31    1.1.1.1         Vlan99
2.2.2.2           1   EXSTART         00:00:31    5.6.7.8         Vlan99
"""


def test_parse_eigrp_v4():
    rows = _parse_eigrp_v4(EIGRP_V4)
    assert len(rows) == 2
    r0 = rows[0]
    assert r0["h"] == "2"
    assert r0["address"] == "1.2.3.4"
    assert r0["interface"] == "Vl199"
    assert r0["hold"] == "12"
    assert r0["uptime"] == "7w1d"
    assert r0["q"] == "0"
    # A stuck queue is preserved so the template can flag it.
    assert rows[1]["q"] == "3"


def test_parse_eigrp_v6_lifts_linklocal_from_next_line():
    rows = _parse_eigrp_v6(EIGRP_V6)
    assert len(rows) == 1
    r = rows[0]
    assert r["address"] == "FE80::1"
    assert r["interface"] == "Vl199"
    assert r["hold"] == "13"
    assert r["seq"] == "1192311"


def test_parse_ospf_neighbors_and_state_class():
    rows = _parse_ospf_neighbors(OSPF_V4)
    assert len(rows) == 2
    assert rows[0]["neighbor_id"] == "1.1.1.1"
    assert rows[0]["state"] == "FULL/DR"
    assert rows[0]["state_class"] == "success"
    assert rows[0]["address"] == "1.1.1.1"
    assert rows[0]["interface"] == "Vlan99"
    # A transitional state is flagged amber, not green.
    assert rows[1]["state_class"] == "warning"


def test_ospf_state_class_buckets():
    assert _ospf_state_class("FULL/BDR") == "success"
    assert _ospf_state_class("2-WAY/DROTHER") == "secondary"
    assert _ospf_state_class("INIT") == "warning"
    assert _ospf_state_class("DOWN") == "warning"


def test_parsers_tolerate_empty_and_garbage():
    assert _parse_eigrp_v4(None) == []
    assert _parse_eigrp_v4("") == []
    assert _parse_eigrp_v6("no neighbors here") == []
    assert _parse_ospf_neighbors("Neighbor ID  Pri  State\n") == []
