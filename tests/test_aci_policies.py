import pytest
from fastapi.testclient import TestClient
from main import app
from dev import DEV_TOKEN

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_dev_mode(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("AD_LDAP_URL", "ldaps://localhost")
    monkeypatch.setenv("ACI_FABRICS", "dc1")
    monkeypatch.setenv("ACI_DC1_URL", "http://aci-dc1.local")
    monkeypatch.setenv("ACI_DC1_LABEL", "DC1")

    # Manually seed the session since lifespan doesn't run in TestClient with manual calls
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
    return {"Cookie": f"impact_token={DEV_TOKEN}"}

def test_list_tenants(auth_headers):
    response = client.get("/api/aci/tenants", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert any(t["name"] == "PROD" for t in data["items"])
    # Check counts
    prod = next(t for t in data["items"] if t["name"] == "PROD")
    assert prod["vrf_count"] >= 2
    assert prod["bd_count"] >= 2

def test_tenant_detail(auth_headers):
    headers = {**auth_headers, "HX-Request": "true"}
    response = client.get("/api/aci/tenants/PROD/detail", headers=headers)
    assert response.status_code == 200
    assert b"Tenant: PROD" in response.content

def test_list_vrfs(auth_headers):
    response = client.get("/api/aci/vrfs", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 3

def test_list_contracts(auth_headers):
    response = client.get("/api/aci/contracts", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    contract = next(c for c in data["items"] if c["name"] == "WEB-to-DB")
    assert contract["provider_count"] == 1
    assert contract["consumer_count"] == 1

def test_contract_detail(auth_headers):
    dn = "uni/tn-PROD/brc-WEB-to-DB"
    headers = {**auth_headers, "X-ACI-Fabric": "dc1"}
    response = client.get(f"/api/aci/contracts/detail?dn={dn}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["contract"]["name"] == "WEB-to-DB"
    assert len(data["subjects"]) == 1
    assert data["subjects"][0]["filters"][0]["name"] == "ALLOW-HTTPS"
    assert any(p["name"] == "WEB" for p in data["providers"])
    assert any(c["name"] == "DB" for c in data["consumers"])

def test_epg_detail(auth_headers):
    dn = "uni/tn-PROD/ap-APP1/epg-WEB"
    response = client.get(f"/api/aci/epgs/detail?dn={dn}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["epg"]["name"] == "WEB"
    assert any(c["name"] == "WEB-to-DB" for c in data["provided_contracts"])

def test_list_policy_groups(auth_headers):
    response = client.get("/api/aci/access/policy-groups", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert any(p["name"] == "PG-Server-VPC" for p in data["items"])

def test_policy_group_detail(auth_headers):
    dn = "uni/infra/funcprof/accbundle-PG-Server-VPC"
    headers = {**auth_headers, "X-ACI-Fabric": "dc1"}
    response = client.get(f"/api/aci/access/policy-groups/detail?dn={dn}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["policy_group"]["name"] == "PG-Server-VPC"
    assert any(p["type"] == "LACP" and p["name"] == "LACP-ACTIVE" for p in data["bound_policies"])
    # Where used check
    used = data["where_used"]
    assert len(used) == 4
    assert any(u["node"] == "101" and u["port"] == "eth1/15" for u in used)
    assert any(u["node"] == "102" and u["port"] == "eth1/16" for u in used)

def test_list_aaeps(auth_headers):
    response = client.get("/api/aci/access/aaeps", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert any(a["name"] == "AAEP-PROD" for a in data["items"])

def test_list_domains(auth_headers):
    response = client.get("/api/aci/access/domains", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert any(d["name"] == "PHYS-DOM" and d["type"] == "Physical" for d in data["items"])
    assert any(d["name"] == "VC1" and d["type"] == "VMM" for d in data["items"])

def test_list_interface_policies(auth_headers):
    response = client.get("/api/aci/access/interface-policies?type=cdp", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert all(p["type"] == "CDP" for p in data["items"])
    assert any(p["name"] == "CDP-ON" for p in data["items"])

def test_multi_fabric_aggregation(auth_headers):
    # This requires at least 2 fabrics to be configured in the test environment or mock registry
    response = client.get("/api/aci/tenants?fabric=all", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    if len(data["items"]) > 0:
        assert "fabric_label" in data["items"][0]

def test_invalid_dn(auth_headers):
    response = client.get("/api/aci/contracts/detail?dn=invalid;dn", headers=auth_headers)
    assert response.status_code == 400
