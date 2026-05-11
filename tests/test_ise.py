"""tests/test_ise.py — ISE router tests (DEV_MODE)."""
import pytest
from fastapi.testclient import TestClient
from main import app
from dev import DEV_TOKEN

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_dev_session():
    from auth import SessionEntry, _sessions, _store_lock
    import time
    entry = SessionEntry(
        username="dev",
        password="dev",
        expires_at=time.monotonic() + 3600,
    )
    with _store_lock:
        _sessions[DEV_TOKEN] = entry

@pytest.fixture
def auth_headers():
    return {
        "Cookie": f"impact_token={DEV_TOKEN}; csrf_token=test-csrf",
        "X-CSRF-Token": "test-csrf"
    }

@pytest.fixture
def htmx_headers(auth_headers):
    return {**auth_headers, "HX-Request": "true"}


# ── Cache ─────────────────────────────────────────────────────────────────────

def test_cache_info(auth_headers):
    r = client.get("/api/ise/cache/info", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert "ise_nads" in data["keys"]
    assert "ise_sgts" in data["keys"]

def test_cache_refresh(auth_headers):
    r = client.post("/api/ise/cache/refresh", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "ise cache cleared"


# ── Network Access Devices ────────────────────────────────────────────────────

def test_list_nads_json(auth_headers):
    r = client.get("/api/ise/nads", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert data["total"] == len(data["items"])
    assert data["total"] >= 5

def test_list_nads_htmx(htmx_headers):
    r = client.get("/api/ise/nads", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Network Access Devices" in r.content

def test_list_nads_search(auth_headers):
    r = client.get("/api/ise/nads?search=SW-DCA", headers=auth_headers)
    assert r.status_code == 200

def test_list_nad_groups(auth_headers):
    r = client.get("/api/ise/device-groups", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["total"] >= 1

def test_list_nad_groups_htmx(htmx_headers):
    r = client.get("/api/ise/device-groups", headers=htmx_headers)
    assert r.status_code == 200
    assert b"NAD" in r.content


# ── Endpoints ─────────────────────────────────────────────────────────────────

def test_endpoint_search_json(auth_headers):
    r = client.get("/api/ise/endpoints?mac=A4:C3", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert data["total"] >= 1
    assert data["items"][0]["mac"] == "A4:C3:F0:11:22:33"

def test_endpoint_search_htmx(htmx_headers):
    r = client.get("/api/ise/endpoints?mac=A4:C3", headers=htmx_headers)
    assert r.status_code == 200
    assert b"A4:C3" in r.content  # partial renders the MAC in the result
    assert b"Endpoint Search" in r.content

def test_endpoint_search_no_results(htmx_headers):
    r = client.get("/api/ise/endpoints?mac=ZZ:ZZ", headers=htmx_headers)
    assert r.status_code == 200
    assert b"No endpoints found" in r.content

def test_endpoint_detail_htmx(htmx_headers):
    from dev import MOCK_ENDPOINTS
    ep_id = MOCK_ENDPOINTS[0]["id"]
    r = client.get(f"/api/ise/endpoints/{ep_id}", headers=htmx_headers)
    assert r.status_code == 200
    assert b"A4:C3:F0:11:22:33" in r.content

def test_endpoint_detail_not_found(htmx_headers):
    r = client.get("/api/ise/endpoints/nonexistent-id", headers=htmx_headers)
    assert r.status_code == 404

def test_endpoint_groups_htmx(htmx_headers):
    r = client.get("/api/ise/endpoint-groups", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Workstation" in r.content


# ── Sessions ──────────────────────────────────────────────────────────────────

def test_active_sessions_json(auth_headers):
    r = client.get("/api/ise/sessions/active", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert data["total"] >= 3

def test_active_sessions_htmx(htmx_headers):
    r = client.get("/api/ise/sessions/active", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Active Sessions" in r.content
    assert b"<table" in r.content  # rendered as HTML table, not raw JSON

def test_active_sessions_mac_filter(auth_headers):
    r = client.get("/api/ise/sessions/active?mac=A4:C3", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    # All returned sessions should match the MAC filter
    for s in data["items"]:
        assert "A4" in s["calling_station_id"].upper()

def test_auth_history_htmx(htmx_headers):
    r = client.get("/api/ise/sessions/auth-history?mac=A4:C3:F0:11:22:33", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Auth History" in r.content

def test_recent_sessions_json(auth_headers):
    r = client.get("/api/ise/sessions/recent", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    # Two mock active sessions have acct_session_time within the default 5min window.
    assert data["total"] >= 2
    for item in data["items"]:
        assert item["age_seconds"] <= 300

def test_recent_sessions_htmx(htmx_headers):
    r = client.get("/api/ise/sessions/recent", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Recent Sessions" in r.content
    assert b"s ago" in r.content


# ── TrustSec ──────────────────────────────────────────────────────────────────

def test_sgts_json(auth_headers):
    r = client.get("/api/ise/sgts", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 4
    # Should be sorted by numeric value
    values = [int(str(item["value"])) for item in data["items"] if str(item["value"]).isdigit()]
    assert values == sorted(values)
    # Employees SGT should be present
    names = [item["name"] for item in data["items"]]
    assert "Employees" in names

def test_sgts_htmx(htmx_headers):
    r = client.get("/api/ise/sgts", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Security Group Tags" in r.content or b"Scalable Group Tags" in r.content

def test_sgacls_htmx(htmx_headers):
    r = client.get("/api/ise/sgacls", headers=htmx_headers)
    assert r.status_code == 200
    assert b"SGACL" in r.content or b"Security Group ACL" in r.content

def test_egress_matrix_htmx(htmx_headers):
    r = client.get("/api/ise/egress-matrix", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Egress" in r.content or b"Matrix" in r.content
    assert b"Employees" in r.content


# ── Policy ────────────────────────────────────────────────────────────────────

def test_policy_sets_json(auth_headers):
    r = client.get("/api/ise/policy-sets", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 3
    names = [p["name"] for p in data["items"]]
    assert "Wired_MAB" in names

def test_policy_sets_htmx(htmx_headers):
    r = client.get("/api/ise/policy-sets", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Policy Sets" in r.content
    assert b"Wired_MAB" in r.content

def test_auth_rules_htmx(htmx_headers):
    from dev import MOCK_POLICY_SETS
    ps_id = MOCK_POLICY_SETS[0]["id"]
    r = client.get(f"/api/ise/policy-sets/{ps_id}/auth-rules", headers=htmx_headers)
    assert r.status_code == 200
    assert b"MAB" in r.content or b"Dot1X" in r.content

def test_authz_rules_htmx(htmx_headers):
    from dev import MOCK_POLICY_SETS
    ps_id = MOCK_POLICY_SETS[0]["id"]
    r = client.get(f"/api/ise/policy-sets/{ps_id}/authz-rules", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Employee" in r.content

def test_authz_profiles_htmx(htmx_headers):
    r = client.get("/api/ise/authz-profiles", headers=htmx_headers)
    assert r.status_code == 200
    assert b"PermitAccess" in r.content
    assert b"DenyAccess" in r.content

def test_allowed_protocols_htmx(htmx_headers):
    r = client.get("/api/ise/allowed-protocols", headers=htmx_headers)
    assert r.status_code == 200
    assert b"EAP-TLS" in r.content


# ── Identity ──────────────────────────────────────────────────────────────────

def test_list_users_json(auth_headers):
    r = client.get("/api/ise/users", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 2
    names = [u["name"] for u in data["items"]]
    assert "admin" in names

def test_list_users_htmx(htmx_headers):
    r = client.get("/api/ise/users", headers=htmx_headers)
    assert r.status_code == 200
    assert b"admin" in r.content

def test_profiling_policies_htmx(htmx_headers):
    r = client.get("/api/ise/profiling-policies", headers=htmx_headers)
    assert r.status_code == 200
    assert b"Cisco-IP-Phone" in r.content or b"Windows10" in r.content

def test_profiling_policies_search(htmx_headers):
    r = client.get("/api/ise/profiling-policies?search=phone", headers=htmx_headers)
    assert r.status_code == 200
    # "Cisco-IP-Phone" matches "phone"; "Windows10-Workstation" should not
    assert b"Cisco-IP-Phone" in r.content
    assert b"Windows10" not in r.content

def test_profiling_policies_search_no_results(htmx_headers):
    r = client.get("/api/ise/profiling-policies?search=zzznotexist", headers=htmx_headers)
    assert r.status_code == 200
    # Returns empty list, total 0 — still valid HTTP 200
    data_check = client.get("/api/ise/profiling-policies?search=zzznotexist", headers={"Cookie": htmx_headers["Cookie"]})
    assert data_check.json()["total"] == 0


# ── Admin ─────────────────────────────────────────────────────────────────────

def test_deployment_nodes_htmx(htmx_headers):
    r = client.get("/api/ise/deployment-nodes", headers=htmx_headers)
    assert r.status_code == 200
    assert b"ise-pan-01" in r.content
    assert b"PAN" in r.content
