"""tests/test_sna_report.py — router/interface -> SNA ID resolution.

Covers the real production bug found on 2026-08-05: SNA's Report Builder
Exporters are keyed by IP, not hostname, so a hostname-only substring match
came up empty for a router that resolved fine everywhere else on the
Reports page. find_exporters now matches by SolarWinds-resolved IP first,
falling back to the old hostname substring match.
"""
from unittest.mock import patch

import clients.sna as sna_client
import pytest
import utils.sna_report as sna_report
from utils.bandwidth_report import InvalidNameError


# ── find_exporters ───────────────────────────────────────────────────────────

def test_find_exporters_matches_by_ip():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [
        {"id": "1.2.3.4", "name": ""},
        {"id": "5.6.7.8", "name": "some-other-router"},
    ]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "RTRYL005AA001", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_ip"] == "1.2.3.4"
    # No hostname in the exporter's name field — display name falls back to the IP.
    assert matches[0]["exporter_name"] == "1.2.3.4"


def test_find_exporters_falls_back_to_name_when_no_ip_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [{"id": "9.9.9.9", "name": "RTRYL005AA001.network.ad.tsa.gov"}]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        # IP resolved from SolarWinds doesn't match any exporter's id.
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "RTRYL005AA001", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_name"] == "RTRYL005AA001.network.ad.tsa.gov"


def test_find_exporters_no_ip_resolved_uses_name_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [{"id": "9.9.9.9", "name": "RTRYL005AA001"}]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "RTRYL005AA001", None)

    assert len(matches) == 1


def test_find_exporters_ip_match_wins_over_name_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [
        {"id": "1.2.3.4", "name": "unrelated-name"},
        {"id": "9.9.9.9", "name": "RTRYL005AA001"},
    ]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "RTRYL005AA001", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_ip"] == "1.2.3.4"


def test_find_exporters_no_match_at_all():
    with patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "nope"}]):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "RTRYL005AA001", "1.2.3.4")

    assert matches == []


# ── generate_application_traffic_report (wiring) ─────────────────────────────

def test_generate_report_resolves_ip_before_matching_exporters():
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4") as mock_find_ip, \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "1.2.3.4", "name": ""}]), \
         patch("clients.sna.list_interfaces", return_value=[{"id": 68, "name": "Tunnel5000"}]), \
         patch("clients.sna.get_interface_application_traffic", return_value=[
             {"applicationName": "Teams", "time": "2026-08-04T00:00:00Z", "trafficInboundBps": 1000, "trafficOutboundBps": 500},
         ]):
        result = sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev", "RTRYL005AA001", "Tunnel5000", 24,
        )

    mock_find_ip.assert_called_once_with("RTRYL005AA001", "dev", "dev")
    assert result["status"] == "ok"
    assert result["interface_name"] == "Tunnel5000"


def test_generate_report_no_exporter_match_raises_lookup_error_with_ip_hint():
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "nope"}]):
        with pytest.raises(LookupError, match="1.2.3.4"):
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "dev", "dev", "RTRYL005AA001", "Tunnel5000", 24,
            )


def test_generate_report_propagates_solarwinds_failure():
    with patch("utils.sna_report.find_node_ip", side_effect=RuntimeError("SolarWinds credentials are required")):
        with pytest.raises(RuntimeError):
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "", "", "RTRYL005AA001", "Tunnel5000", 24,
            )


def test_generate_report_invalid_router_name():
    with pytest.raises(InvalidNameError):
        sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev", "bad;name", "Tunnel5000", 24,
        )
