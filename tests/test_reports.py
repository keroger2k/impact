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


# ── Application traffic (SNA Report Builder) ─────────────────────────────────

def test_application_traffic_ok(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    def fake_report(base_url, domain, username, password, router_name, interface_name, hours):
        assert router_name == "R-SITE-01"
        assert interface_name == "Tunnel5000"
        assert hours == 24
        return {
            "status": "ok",
            "node_name": "R-SITE-01",
            "interface_name": "Tunnel5000",
            "buckets": ["2026-08-04T00:00:00Z", "2026-08-04T01:00:00Z"],
            "applications": ["Teams", "Other"],
            "series": {"Teams": [1000.0, 2000.0], "Other": [500.0, 500.0]},
        }

    monkeypatch.setattr("routers.reports.generate_application_traffic_report", fake_report)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 24},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["node_name"] == "R-SITE-01"
    assert data["applications"] == ["Teams", "Other"]


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
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 24},
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
        data={"router": "nope", "interface": "Tunnel5000", "hours": 24},
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
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 24},
        headers=auth_headers,
    )
    assert r.status_code == 502


def test_application_traffic_requires_base_url(auth_headers, monkeypatch):
    monkeypatch.delenv("SNA_BASE_URL", raising=False)

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 24},
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
        data={"router": "bad;name", "interface": "Tunnel5000", "hours": 24},
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
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 24},
        headers=auth_headers,
    )
    assert r.status_code == 502


def test_application_traffic_invalid_hours(auth_headers, monkeypatch):
    monkeypatch.setenv("SNA_BASE_URL", "https://sna.example.com")

    r = client.post(
        "/api/reports/bandwidth/application-traffic",
        data={"router": "R-SITE-01", "interface": "Tunnel5000", "hours": 12},
        headers=auth_headers,
    )
    assert r.status_code == 400
