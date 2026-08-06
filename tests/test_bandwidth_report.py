"""tests/test_bandwidth_report.py — find_node_ip and Site Information panel.

Field mapping (Site/Airport_Code/AirportCategory/Building/City/State custom
properties, standard Nodes.Contact, and Interfaces.Speed) confirmed against a
real SolarWinds instance — see scripts/solarwinds_discover_site_properties.py's
module docstring for the discovery trail. Circuit Provider, FRM, and
Transition Date aren't tracked in SolarWinds anywhere and are intentionally
absent from _build_site_info's output.
"""
from unittest.mock import patch

import pytest
from utils.bandwidth_report import (
    InvalidNameError,
    _build_site_info,
    bare_interface_name,
    find_node_ip,
    generate_bandwidth_report,
    list_interfaces_for_router,
    short_hostname,
)


# ── short_hostname ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("R-SITE-01.network.ad.tsa.gov", "R-SITE-01"),
    ("R-SITE-01", "R-SITE-01"),
    ("  R-SITE-01.network.ad.tsa.gov  ", "R-SITE-01"),
    ("", ""),
    (None, ""),
])
def test_short_hostname(raw, expected):
    assert short_hostname(raw) == expected


# ── bare_interface_name ──────────────────────────────────────────────────────

@pytest.mark.parametrize("caption,expected", [
    ("Tunnel5000 · DMVPN Tunnel for TSA (ATT)", "Tunnel5000"),
    ("GigabitEthernet0/0/3 · ATT AVPN 10MB | BBEC651703..ATI | Terms: 36mo", "GigabitEthernet0/0/3"),
    ("Tunnel5000", "Tunnel5000"),
    ("ifIndex-68", "ifIndex-68"),
    # A dot is part of a subinterface name — this must NOT behave like
    # short_hostname, which splits on the first dot.
    ("GigabitEthernet0/0/0.100 · Site VLAN", "GigabitEthernet0/0/0.100"),
    ("  Tunnel10  ", "Tunnel10"),
    ("", ""),
    (None, ""),
])
def test_bare_interface_name(caption, expected):
    assert bare_interface_name(caption) == expected


def test_bare_interface_name_output_passes_swql_validation():
    """The whole point: the decorated caption fails the charset/length check
    that every SWQL-bound name must pass, and the bare form doesn't."""
    from utils.bandwidth_report import _validate_name

    decorated = "GigabitEthernet0/0/3 · ATT AVPN 10MB | BBEC651703..ATI | Terms: 36mo"
    with pytest.raises(InvalidNameError):
        _validate_name(decorated, "Interface name")

    assert _validate_name(bare_interface_name(decorated), "Interface name") == "GigabitEthernet0/0/3"


# ── FQDN normalization across every router-name entry point ──────────────────

def _capture_swql():
    captured = {}

    def fake_query(swql, username, password, timeout=None):
        captured["swql"] = swql
        return []

    return captured, fake_query


def test_find_interfaces_normalizes_fqdn_router_name():
    from utils.bandwidth_report import find_interfaces

    captured, fake_query = _capture_swql()
    with patch("clients.solarwinds.query", side_effect=fake_query):
        find_interfaces("R-SITE-01.network.ad.tsa.gov", "Tunnel5000", "dev", "dev")

    assert "n.Caption = 'R-SITE-01'" in captured["swql"]
    assert "tsa.gov" not in captured["swql"]


def test_find_node_ip_normalizes_fqdn_router_name():
    captured, fake_query = _capture_swql()
    with patch("clients.solarwinds.query", side_effect=fake_query):
        find_node_ip("R-SITE-01.network.ad.tsa.gov", "dev", "dev")

    assert "tsa.gov" not in captured["swql"]


def test_list_interfaces_for_router_normalizes_fqdn_router_name():
    captured, fake_query = _capture_swql()
    with patch("clients.solarwinds.query", side_effect=fake_query):
        list_interfaces_for_router("R-SITE-01.network.ad.tsa.gov", "dev", "dev")

    assert "tsa.gov" not in captured["swql"]


def test_generate_bandwidth_report_accepts_fqdn_router_name():
    """Application Traffic already normalized FQDNs while the In/Out chart
    didn't — the same typed name resolved on one half of the page and came
    back empty on the other."""
    with patch("clients.solarwinds.query") as mock_query:
        mock_query.side_effect = [[_fake_meta()], [], []]
        result = generate_bandwidth_report(
            "R-SITE-01.network.ad.tsa.gov", "Tunnel5000", None, "dev", "dev",
        )

    assert result["status"] == "ok"
    assert "n.Caption = 'R-SITE-01'" in mock_query.call_args_list[0][0][0]


def test_find_node_ip_exact_match_preferred():
    rows = [
        {"NodeName": "R-SITE-01-OLD", "NodeIpAddress": "5.6.7.8"},
        {"NodeName": "R-SITE-01", "NodeIpAddress": "1.2.3.4"},
    ]
    with patch("clients.solarwinds.query", return_value=rows):
        ip = find_node_ip("R-SITE-01", "dev", "dev")
    assert ip == "1.2.3.4"


def test_find_node_ip_falls_back_to_first_like_match():
    rows = [{"NodeName": "R-SITE-01-SUB", "NodeIpAddress": "5.6.7.8"}]
    with patch("clients.solarwinds.query", return_value=rows):
        ip = find_node_ip("R-SITE-01", "dev", "dev")
    assert ip == "5.6.7.8"


def test_find_node_ip_no_match_returns_none():
    with patch("clients.solarwinds.query", return_value=[]):
        ip = find_node_ip("nonexistent-router", "dev", "dev")
    assert ip is None


def test_find_node_ip_rejects_bad_charset():
    with pytest.raises(InvalidNameError):
        find_node_ip("bad;name", "dev", "dev")


def test_find_node_ip_like_fallback_is_deterministically_ordered():
    """Without an ORDER BY, which row wins the LIKE fallback (when there's no
    exact match) depends on DB-internal ordering, not any real property of
    the data — assert the query now asks SolarWinds to sort by Caption, same
    as find_interfaces() already does."""
    captured = {}

    def fake_query(swql, username, password):
        captured["swql"] = swql
        return []

    with patch("clients.solarwinds.query", side_effect=fake_query):
        find_node_ip("R-SITE-01", "dev", "dev")

    assert "ORDER BY n.Caption" in captured["swql"]


# ── list_interfaces_for_router (Interface dropdown source) ───────────────────

def test_list_interfaces_prefers_exact_node_match():
    """A LIKE match pulls in near-duplicate node names (e.g. "-OLD" spares).
    When the exact node exists, only its interfaces may be offered — otherwise
    the dropdown lists another device's interfaces under this router's name."""
    rows = [
        {"NodeName": "R-SITE-01-OLD", "InterfaceID": 1, "InterfaceCaption": "Tunnel9999"},
        {"NodeName": "R-SITE-01", "InterfaceID": 2, "InterfaceCaption": "Tunnel100"},
    ]
    with patch("clients.solarwinds.query", return_value=rows):
        result = list_interfaces_for_router("R-SITE-01", "dev", "dev")

    assert [r["InterfaceCaption"] for r in result] == ["Tunnel100"]


def test_list_interfaces_falls_back_to_like_matches():
    rows = [{"NodeName": "R-SITE-01-SUB", "InterfaceID": 1, "InterfaceCaption": "Tunnel20"}]
    with patch("clients.solarwinds.query", return_value=rows):
        result = list_interfaces_for_router("R-SITE-01", "dev", "dev")

    assert len(result) == 1


def test_list_interfaces_no_rows_returns_empty():
    with patch("clients.solarwinds.query", return_value=[]):
        assert list_interfaces_for_router("nonexistent", "dev", "dev") == []


def test_list_interfaces_rejects_bad_charset():
    with pytest.raises(InvalidNameError):
        list_interfaces_for_router("bad;name", "dev", "dev")


def test_list_interfaces_uses_short_timeout():
    """This backs an interactive dropdown, not a report build — it must not
    inherit SOLARWINDS_TIMEOUT's 180s default, or an unreachable Orion hangs
    the control the user is waiting on."""
    captured = {}

    def fake_query(swql, username, password, timeout=None):
        captured["timeout"] = timeout
        return []

    with patch("clients.solarwinds.query", side_effect=fake_query):
        list_interfaces_for_router("R-SITE-01", "dev", "dev")

    assert captured["timeout"] is not None and captured["timeout"] <= 30


# ── _build_site_info ─────────────────────────────────────────────────────────

def _fake_meta(**overrides):
    meta = {
        "NodeID": 1,
        "NodeName": "R-SITE-01",
        "NodeIpAddress": "1.2.3.4",
        "NodeContact": "Jane Doe @ 555-000-1234",
        "InterfaceID": 42,
        "InterfaceCaption": "Tunnel5000",
        "InterfaceName": "Tunnel5000",
        "InterfaceSpeed": 10_000_000.0,
        "Site": "S001",
        "Building": "Fake Municipal Airport",
        "City": "Faketown",
        "State": "CA",
        "Airport_Code": "KFAK",
        "AirportCategory": "II",
    }
    meta.update(overrides)
    return meta


def test_build_site_info_maps_confirmed_fields():
    info = _build_site_info(_fake_meta())
    assert info == {
        "site_code": "S001",
        "airport_code": "KFAK",
        "category": "II",
        "building": "Fake Municipal Airport",
        "city": "Faketown",
        "state": "CA",
        "local_poc": "Jane Doe @ 555-000-1234",
        "circuit_size_mbps": 10.0,
    }


def test_build_site_info_converts_bps_to_mbps():
    info = _build_site_info(_fake_meta(InterfaceSpeed=1_544_000.0))
    assert info["circuit_size_mbps"] == 1.5


def test_build_site_info_handles_missing_fields():
    info = _build_site_info(_fake_meta(Site=None, Building="", NodeContact=None, InterfaceSpeed=None))
    assert info["site_code"] is None
    assert info["building"] is None
    assert info["local_poc"] is None
    assert info["circuit_size_mbps"] is None


def test_build_site_info_handles_bad_speed_value():
    info = _build_site_info(_fake_meta(InterfaceSpeed="not-a-number"))
    assert info["circuit_size_mbps"] is None


# ── generate_bandwidth_report site_info wiring ───────────────────────────────

def test_generate_bandwidth_report_includes_site_info():
    with patch("clients.solarwinds.query") as mock_query:
        mock_query.side_effect = [
            [_fake_meta()],  # find_interfaces
            [],  # series_24h
            [],  # series_7d
        ]
        result = generate_bandwidth_report("R-SITE-01", "Tunnel5000", None, "dev", "dev")

    assert result["status"] == "ok"
    assert result["site_info"]["site_code"] == "S001"
    assert result["site_info"]["circuit_size_mbps"] == 10.0


def test_generate_bandwidth_report_24h_and_7d_windows_land_correctly_when_run_concurrently():
    """The 24h and 7d SolarWinds queries now run concurrently (ThreadPoolExecutor)
    rather than back-to-back — key the fake response off the SWQL text (not call
    order) to make sure results still land in the right window regardless of
    which thread's request the mock happens to service first."""
    def fake_query(swql, username, password):
        if "ADDHOUR(-24," in swql:
            return [{"DateTime": "2026-08-04T00:00:00Z", "InPercentUtil": "1.0", "OutPercentUtil": "2.0"}]
        if "ADDHOUR(-168," in swql:
            return [{"DateTime": "2026-07-29T00:00:00Z", "InPercentUtil": "3.0", "OutPercentUtil": "4.0"}]
        return [_fake_meta()]

    with patch("clients.solarwinds.query", side_effect=fake_query):
        result = generate_bandwidth_report("R-SITE-01", "Tunnel5000", None, "dev", "dev")

    assert result["series_24h"] == [{"t": "2026-08-04T00:00:00Z", "in": 1.0, "out": 2.0}]
    assert result["series_7d"] == [{"t": "2026-07-29T00:00:00Z", "in": 3.0, "out": 4.0}]
