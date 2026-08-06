"""tests/test_reports.py — Reports router tests (DEV_MODE).

CDRL49 and Bandwidth generation talk to SolarWinds; SNA application traffic
talks to Cisco Secure Network Analytics. Both are mocked here at the
orchestration-function boundary (utils.cdrl49_report / utils.bandwidth_report /
utils.sna_report) rather than the HTTP layer, since those functions are exactly
what routers/reports.py calls.
"""
import time

import clients.sna as sna_client
import pytest
from dev import DEV_TOKEN
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_dev_session():
    from auth import SessionEntry, _sessions, _store_lock

    entry = SessionEntry(username="dev", password="dev", expires_at=time.monotonic() + 3600)
    with _store_lock:
        _sessions[DEV_TOKEN] = entry


@pytest.fixture
def auth_headers():
    return {
        "Cookie": f"impact_token={DEV_TOKEN}; csrf_token=test-csrf",
        "X-CSRF-Token": "test-csrf",
    }


# ── Bandwidth generate (In/Out + Site Information) ───────────────────────────

def test_bandwidth_generate_ok(auth_headers, monkeypatch):
    def fake_report(router_name, interface_name, interface_id, username, password):
        assert router_name == "R-SITE-01"
        return {
            "status": "ok",
            "node_name": "R-SITE-01",
            "node_ip": "1.2.3.4",
            "interface_caption": "Tunnel5000",
            "interface_id": 42,
            "site_info": {
                "site_code": "S001", "airport_code": "KFAK", "category": "II",
                "building": "Fake Municipal Airport", "city": "Faketown", "state": "CA",
                "local_poc": "Jane Doe @ 555-000-1234", "circuit_size_mbps": 10.0,
            },
            "series_24h": [{"t": "2026-08-04T00:00:00Z", "in": 5.0, "out": 3.0}],
            "series_7d": [{"t": "2026-08-01T00:00:00Z", "in": 4.0, "out": 2.0}],
        }

    monkeypatch.setattr("routers.reports.generate_bandwidth_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/generate",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["site_info"]["site_code"] == "S001"
    assert data["site_info"]["circuit_size_mbps"] == 10.0


def test_bandwidth_generate_ambiguous(auth_headers, monkeypatch):
    def fake_report(*args, **kwargs):
        return {
            "status": "ambiguous",
            "candidates": [
                {"interface_id": 1, "node_name": "R-SITE-01", "node_ip": "1.2.3.4",
                 "caption": "Tunnel5000", "name": "Tunnel5000", "alias": None, "status": "Up"},
                {"interface_id": 2, "node_name": "R-SITE-01", "node_ip": "1.2.3.4",
                 "caption": "Tunnel5001", "name": "Tunnel5001", "alias": None, "status": "Up"},
            ],
        }

    monkeypatch.setattr("routers.reports.generate_bandwidth_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/generate",
        data={"router": "R-SITE-01", "interface": "Tunnel"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ambiguous"
    assert len(data["candidates"]) == 2


def test_bandwidth_generate_not_found(auth_headers, monkeypatch):
    def fake_report(*args, **kwargs):
        raise LookupError("No matching interface found")

    monkeypatch.setattr("routers.reports.generate_bandwidth_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/generate",
        data={"router": "nope", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 404


def test_bandwidth_generate_requires_router_or_interface_id(auth_headers):
    r = client.post(
        "/api/reports/bandwidth/generate",
        data={"interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 400


# ── DNAC-backed autofill datalists ────────────────────────────────────────────

def test_router_options_filters_by_substring(auth_headers, monkeypatch):
    def fake_stale(key):
        if key == "devices":
            return [
                {"hostname": "R-SITE-01"}, {"hostname": "R-SITE-02"}, {"hostname": "SW-SITE-01"},
            ]
        return None

    monkeypatch.setattr("routers.reports.cache.get_stale", fake_stale)

    r = client.get("/api/reports/bandwidth/router-options", params={"router": "r-site"}, headers=auth_headers)
    assert r.status_code == 200
    assert "R-SITE-01" in r.text
    assert "R-SITE-02" in r.text
    assert "SW-SITE-01" not in r.text


def test_router_options_empty_query_returns_full_list(auth_headers, monkeypatch):
    monkeypatch.setattr("routers.reports.cache.get_stale", lambda key: [{"hostname": "R-SITE-01"}] if key == "devices" else None)

    r = client.get("/api/reports/bandwidth/router-options", headers=auth_headers)
    assert r.status_code == 200
    assert "R-SITE-01" in r.text


def test_router_options_no_cache_returns_empty(auth_headers, monkeypatch):
    monkeypatch.setattr("routers.reports.cache.get_stale", lambda key: None)

    r = client.get("/api/reports/bandwidth/router-options", params={"router": "r-"}, headers=auth_headers)
    assert r.status_code == 200
    assert r.text == ""


def test_interfaces_requires_router(auth_headers):
    r = client.get("/api/reports/bandwidth/interfaces", headers=auth_headers)
    assert r.status_code == 200
    assert "Select a router first" in r.text


def test_interfaces_no_match_returns_placeholder(auth_headers, monkeypatch):
    monkeypatch.setattr("routers.reports.list_interfaces_for_router", lambda *a, **k: [])

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "R-SITE-01"}, headers=auth_headers)
    assert r.status_code == 200
    assert "No router matching this name" in r.text


def test_interfaces_lists_solarwinds_interfaces_with_ids(auth_headers, monkeypatch):
    """Every option must carry its SolarWinds InterfaceID — that's what lets
    Generate post interface_id and bypass the name-based lookup entirely."""
    def fake_list(router_name, username, password):
        assert router_name == "R-SITE-01"
        return [
            {"NodeName": "R-SITE-01", "InterfaceID": 11, "InterfaceCaption": "GigabitEthernet0/0/0",
             "InterfaceName": "Gi0/0/0", "StatusDescription": "Up"},
            {"NodeName": "R-SITE-01", "InterfaceID": 12, "InterfaceCaption": "Tunnel100",
             "InterfaceName": "Tu100", "StatusDescription": "Up"},
        ]

    monkeypatch.setattr("routers.reports.list_interfaces_for_router", fake_list)

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "R-SITE-01"}, headers=auth_headers)
    assert r.status_code == 200
    assert 'data-interface-id="11"' in r.text
    assert "GigabitEthernet0/0/0 — Up" in r.text
    assert 'data-interface-id="12"' in r.text
    # This router has no Tunnel5000 — nothing may be pre-selected, which is
    # the whole point: a hardcoded default silently mismatching was the bug.
    assert "selected" not in r.text


def test_interfaces_preselects_default_only_when_present(auth_headers, monkeypatch):
    monkeypatch.setattr(
        "routers.reports.list_interfaces_for_router",
        lambda *a, **k: [
            {"NodeName": "R-SITE-01", "InterfaceID": 1, "InterfaceCaption": "Tunnel5000", "StatusDescription": "Up"},
            {"NodeName": "R-SITE-01", "InterfaceID": 2, "InterfaceCaption": "Loopback0", "StatusDescription": "Up"},
        ],
    )

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "R-SITE-01"}, headers=auth_headers)
    assert r.status_code == 200
    assert '<option value="Tunnel5000" data-interface-id="1" selected>' in r.text


def test_interfaces_solarwinds_failure_degrades_to_placeholder(auth_headers, monkeypatch):
    """A live query backing an autocomplete must never 500 the fragment —
    it degrades to an inline message the user can act on."""
    def boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("routers.reports.list_interfaces_for_router", boom)

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "R-SITE-01"}, headers=auth_headers)
    assert r.status_code == 200
    assert "Could not reach SolarWinds" in r.text


def test_interfaces_invalid_name_degrades_to_placeholder(auth_headers, monkeypatch):
    from utils.bandwidth_report import InvalidNameError

    def boom(*a, **k):
        raise InvalidNameError("Router name contains unsupported characters")

    monkeypatch.setattr("routers.reports.list_interfaces_for_router", boom)

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "bad;name"}, headers=auth_headers)
    assert r.status_code == 200
    assert "Invalid router name" in r.text


def test_router_options_strips_fqdn_to_short_hostname(auth_headers, monkeypatch):
    """DNAC's `devices` cache sometimes carries a device's FQDN as its
    hostname — the datalist must never suggest that form, since neither
    SolarWinds' Node Caption nor SNA's Exporter name downstream are FQDNs."""
    monkeypatch.setattr(
        "routers.reports.cache.get_stale",
        lambda key: [{"hostname": "R-SITE-01.network.ad.tsa.gov"}] if key == "devices" else None,
    )

    r = client.get("/api/reports/bandwidth/router-options", params={"router": "r-site"}, headers=auth_headers)
    assert r.status_code == 200
    assert r.text == '<option value="R-SITE-01"></option>'
    assert "tsa.gov" not in r.text


def test_interfaces_falls_back_to_interface_name_when_no_caption(auth_headers, monkeypatch):
    monkeypatch.setattr(
        "routers.reports.list_interfaces_for_router",
        lambda *a, **k: [{"NodeName": "R-SITE-01", "InterfaceID": 3, "InterfaceCaption": None,
                          "InterfaceName": "Gi0/0/1", "StatusDescription": None}],
    )

    r = client.get("/api/reports/bandwidth/interfaces", params={"router": "R-SITE-01"}, headers=auth_headers)
    assert r.status_code == 200
    assert '<option value="Gi0/0/1" data-interface-id="3">Gi0/0/1</option>' in r.text


# ── Application traffic (SNA Report Builder) ─────────────────────────────────

def test_application_traffic_ok(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(base_url, domain, username, password, router_name, interface_name):
        assert router_name == "R-SITE-01"
        assert interface_name == "Tunnel5000"
        return {
            "status": "ok",
            "node_name": "R-SITE-01",
            "interface_name": "Tunnel5000",
            "traffic_24h": {
                "buckets": ["2026-08-04T00:00:00Z", "2026-08-04T01:00:00Z"],
                "applications": ["Teams", "Other Apps"],
                "series": {"Teams": [1000.0, 2000.0], "Other Apps": [500.0, 500.0]},
            },
            "traffic_7d": {
                "buckets": ["2026-07-29T00:00:00Z", "2026-07-30T00:00:00Z"],
                "applications": ["Teams", "Other Apps"],
                "series": {"Teams": [900.0, 1500.0], "Other Apps": [400.0, 450.0]},
            },
        }

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["node_name"] == "R-SITE-01"
    assert data["traffic_24h"]["applications"] == ["Teams", "Other Apps"]
    assert data["traffic_7d"]["applications"] == ["Teams", "Other Apps"]


def test_application_traffic_ambiguous_exporter(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(*args, **kwargs):
        return {
            "status": "ambiguous",
            "level": "exporter",
            "candidates": [
                {"device_id": 1, "exporter_ip": "1.2.3.4", "exporter_name": "R-SITE-01a"},
                {"device_id": 1, "exporter_ip": "5.6.7.8", "exporter_name": "R-SITE-01b"},
            ],
        }

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ambiguous"
    assert data["level"] == "exporter"
    assert len(data["candidates"]) == 2


def test_application_traffic_not_found(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(*args, **kwargs):
        raise LookupError("No SNA exporter found matching 'nope'")

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "nope", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 404


def test_application_traffic_sna_error(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(*args, **kwargs):
        raise sna_client.SNAError("SNA authentication failed")

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 502


def test_application_traffic_requires_base_url(auth_headers, monkeypatch):
    monkeypatch.delenv("SNA_BASE_URL", raising=False)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 503


def test_application_traffic_invalid_router_name(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    from utils.bandwidth_report import InvalidNameError

    def fake_report(*args, **kwargs):
        raise InvalidNameError("Router name contains unsupported characters")

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "bad;name", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 400


def test_application_traffic_solarwinds_failure(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(*args, **kwargs):
        raise RuntimeError("SolarWinds credentials are required")

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000"},
        headers=auth_headers,
    )
    assert r.status_code == 502
