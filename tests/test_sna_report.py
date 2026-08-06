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
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "R-SITE-01", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_ip"] == "1.2.3.4"
    # No hostname in the exporter's name field — display name falls back to the IP.
    assert matches[0]["exporter_name"] == "1.2.3.4"


def test_find_exporters_falls_back_to_name_when_no_ip_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [{"id": "9.9.9.9", "name": "R-SITE-01.network.ad.tsa.gov"}]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        # IP resolved from SolarWinds doesn't match any exporter's id.
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "R-SITE-01", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_name"] == "R-SITE-01.network.ad.tsa.gov"


def test_find_exporters_no_ip_resolved_uses_name_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [{"id": "9.9.9.9", "name": "R-SITE-01"}]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "R-SITE-01", None)

    assert len(matches) == 1


def test_find_exporters_ip_match_wins_over_name_match():
    flow_collectors = [{"id": 1, "name": "fc01"}]
    exporters = [
        {"id": "1.2.3.4", "name": "unrelated-name"},
        {"id": "9.9.9.9", "name": "R-SITE-01"},
    ]
    with patch("clients.sna.list_flow_collectors", return_value=flow_collectors), \
         patch("clients.sna.list_exporters", return_value=exporters):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "R-SITE-01", "1.2.3.4")

    assert len(matches) == 1
    assert matches[0]["exporter_ip"] == "1.2.3.4"


def test_find_exporters_no_match_at_all():
    with patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "nope"}]):
        matches = sna_report.find_exporters(None, "https://sna.example.com", "999", "R-SITE-01", "1.2.3.4")

    assert matches == []


# ── find_interfaces (SolarWinds Caption -> SNA interface name) ───────────────

def test_find_interfaces_matches_bare_name():
    with patch("clients.sna.list_interfaces", return_value=[{"id": 68, "name": "Tunnel5000"}]):
        matches = sna_report.find_interfaces(None, "https://sna.example.com", "999", 1, "1.2.3.4", "Tunnel5000")

    assert matches == [{"interface_id": 68, "interface_name": "Tunnel5000"}]


def test_find_interfaces_strips_solarwinds_caption_decoration():
    """The real production bug: the Interface dropdown posts SolarWinds'
    Caption, which carries free-text circuit decoration after the interface
    name. SNA stores a bare identifier, so the decorated string is longer
    than what's stored and can never substring-match it."""
    with patch("clients.sna.list_interfaces", return_value=[
        {"id": 68, "name": "Tunnel5000"},
        {"id": 69, "name": "GigabitEthernet0/0/0"},
    ]):
        matches = sna_report.find_interfaces(
            None, "https://sna.example.com", "999", 1, "1.2.3.4",
            "Tunnel5000 · DMVPN Tunnel for TSA (ATT)",
        )

    assert matches == [{"interface_id": 68, "interface_name": "Tunnel5000"}]


def test_find_interfaces_strips_decoration_on_physical_interface():
    with patch("clients.sna.list_interfaces", return_value=[{"id": 70, "name": "GigabitEthernet0/0/3"}]):
        matches = sna_report.find_interfaces(
            None, "https://sna.example.com", "999", 1, "1.2.3.4",
            "GigabitEthernet0/0/3 · ATT AVPN 10MB | Terms: 36mo",
        )

    assert matches == [{"interface_id": 70, "interface_name": "GigabitEthernet0/0/3"}]


def test_find_interfaces_prefers_full_string_over_leading_token():
    """An SNA whose own names carry decoration must still win on the exact
    match rather than being narrowed to the bare leading identifier."""
    with patch("clients.sna.list_interfaces", return_value=[
        {"id": 1, "name": "Tunnel5000 · DMVPN"},
        {"id": 2, "name": "Tunnel5000"},
    ]):
        matches = sna_report.find_interfaces(
            None, "https://sna.example.com", "999", 1, "1.2.3.4", "Tunnel5000 · DMVPN",
        )

    assert matches == [{"interface_id": 1, "interface_name": "Tunnel5000 · DMVPN"}]


def test_find_interfaces_no_match_returns_empty():
    with patch("clients.sna.list_interfaces", return_value=[{"id": 1, "name": "Tunnel99"}]):
        matches = sna_report.find_interfaces(
            None, "https://sna.example.com", "999", 1, "1.2.3.4", "Tunnel5000 · DMVPN",
        )

    assert matches == []


@pytest.mark.parametrize("raw,expected", [
    ("Tunnel5000 · DMVPN Tunnel for TSA (ATT)", ["Tunnel5000 · DMVPN Tunnel for TSA (ATT)", "Tunnel5000"]),
    ("Tunnel5000", ["Tunnel5000"]),
    ("ifIndex-68", ["ifIndex-68"]),
    ("GigabitEthernet0/0/3 (WAN)", ["GigabitEthernet0/0/3 (WAN)", "GigabitEthernet0/0/3"]),
])
def test_interface_name_candidates(raw, expected):
    assert sna_report._interface_name_candidates(raw) == expected


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
            "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
        )

    mock_find_ip.assert_called_once_with("R-SITE-01", "dev", "dev")
    assert result["status"] == "ok"
    assert result["interface_name"] == "Tunnel5000"
    assert "traffic_24h" in result and "traffic_7d" in result
    assert result["traffic_24h"]["applications"] == ["Teams"]


def test_generate_report_24h_and_7d_pulls_land_correctly_when_run_concurrently():
    """The 24h and 7d report pulls now run concurrently (ThreadPoolExecutor)
    rather than back-to-back — key the fake response off the `hours` argument
    (not call order) to make sure results still land in the right window
    regardless of which thread's request the mock happens to service first."""
    def fake_traffic(session, base_url, domain_id, device_id, device_name, exporter_ip, exporter_name,
                      interface_id, interface_name, hours, timeout=60):
        if hours == 24:
            return [{"applicationName": "Teams", "time": "2026-08-04T00:00:00Z",
                      "trafficInboundBps": 1000, "trafficOutboundBps": 0}]
        return [{"applicationName": "Splunk", "time": "2026-07-29T00:00:00Z",
                  "trafficInboundBps": 2000, "trafficOutboundBps": 0}]

    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "1.2.3.4", "name": ""}]), \
         patch("clients.sna.list_interfaces", return_value=[{"id": 68, "name": "Tunnel5000"}]), \
         patch("clients.sna.get_interface_application_traffic", side_effect=fake_traffic):
        result = sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
        )

    assert result["traffic_24h"]["applications"] == ["Teams"]
    assert result["traffic_7d"]["applications"] == ["Splunk"]


def test_generate_report_normalizes_fqdn_router_name_for_sna_match():
    """The real bug this guards against: DNAC's device inventory (which now
    feeds the Router Name autofill datalist) sometimes carries a device's
    FQDN as its hostname. Passed through unchanged, that FQDN is longer than
    both SolarWinds' short Node Caption (breaks find_node_ip's exact/LIKE
    match) and SNA's short Exporter name (breaks find_exporters' substring
    fallback) — a longer string can never be found inside a shorter one.
    generate_application_traffic_report must reduce it to short_hostname()
    before either lookup runs."""
    with patch("utils.sna_report.find_node_ip", return_value=None) as mock_find_ip, \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "R-SITE-01"}]), \
         patch("clients.sna.list_interfaces", return_value=[{"id": 68, "name": "Tunnel5000"}]), \
         patch("clients.sna.get_interface_application_traffic", return_value=[]):
        result = sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev",
            "R-SITE-01.network.ad.tsa.gov", "Tunnel5000",
        )

    mock_find_ip.assert_called_once_with("R-SITE-01", "dev", "dev")
    assert result["status"] == "ok"
    assert result["node_name"] == "R-SITE-01"


def test_generate_report_no_interface_match_lists_what_sna_has():
    """Name-matching between SolarWinds and SNA is the recurring failure mode
    here, so the error must name SNA's actual interfaces — that's what makes
    the mismatch diagnosable without another round trip through the user."""
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "1.2.3.4", "name": "R-SITE-01"}]), \
         patch("clients.sna.list_interfaces", return_value=[
             {"id": 1, "name": "ifIndex-7"}, {"id": 2, "name": "ifIndex-9"},
         ]):
        with pytest.raises(LookupError) as excinfo:
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
            )

    message = str(excinfo.value)
    assert "ifIndex-7" in message and "ifIndex-9" in message


def test_generate_report_no_exporter_match_raises_lookup_error_with_ip_hint():
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "nope"}]):
        with pytest.raises(LookupError, match="1.2.3.4"):
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
            )


def test_generate_report_propagates_solarwinds_failure():
    with patch("utils.sna_report.find_node_ip", side_effect=RuntimeError("SolarWinds credentials are required")):
        with pytest.raises(RuntimeError):
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "", "", "R-SITE-01", "Tunnel5000",
            )


# ── Session teardown ─────────────────────────────────────────────────────────

def test_generate_report_logs_out_on_success():
    """Every run authenticates fresh, so a missing logout leaks an SMC
    session per Generate click."""
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.logout") as mock_logout, \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "1.2.3.4", "name": ""}]), \
         patch("clients.sna.list_interfaces", return_value=[{"id": 68, "name": "Tunnel5000"}]), \
         patch("clients.sna.get_interface_application_traffic", return_value=[]):
        sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
        )

    mock_logout.assert_called_once_with("fake-session", "https://sna.example.com")


def test_generate_report_logs_out_even_when_the_report_fails():
    with patch("utils.sna_report.find_node_ip", return_value="1.2.3.4"), \
         patch("clients.sna.login", return_value="fake-session"), \
         patch("clients.sna.logout") as mock_logout, \
         patch("clients.sna.get_tenant_id", return_value="999"), \
         patch("clients.sna.list_flow_collectors", return_value=[{"id": 1, "name": "fc01"}]), \
         patch("clients.sna.list_exporters", return_value=[{"id": "9.9.9.9", "name": "nope"}]):
        with pytest.raises(LookupError):
            sna_report.generate_application_traffic_report(
                "https://sna.example.com", "network", "dev", "dev", "R-SITE-01", "Tunnel5000",
            )

    mock_logout.assert_called_once()


def test_logout_never_raises():
    """It runs in a finally — a teardown failure must not replace a real
    error, or mask a successful report."""
    class ExplodingSession:
        def delete(self, *a, **k):
            raise ConnectionError("SMC unreachable")

        def close(self):
            raise RuntimeError("already closed")

    sna_client.logout(ExplodingSession(), "https://sna.example.com")


def test_generate_report_invalid_router_name():
    with pytest.raises(InvalidNameError):
        sna_report.generate_application_traffic_report(
            "https://sna.example.com", "network", "dev", "dev", "bad;name", "Tunnel5000",
        )
