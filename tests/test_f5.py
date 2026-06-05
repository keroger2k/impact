"""
Tests for the F5 BIG-IP integration.

All addressing here is FAKE per docs/IP_ADDRESS_POLICY.md.

The most important test is ``test_f5_client_is_read_only`` — it fails the build
if any mutating HTTP verb is ever introduced into clients/f5.py, which is the
machine-checkable backbone of the F5 read-only guarantee.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

import clients.f5 as f5

_F5_SRC = Path(__file__).resolve().parent.parent / "clients" / "f5.py"


# ── Read-only guarantee ───────────────────────────────────────────────────────

def test_f5_client_is_read_only():
    """clients/f5.py must contain no mutating HTTP call. This is the structural
    backbone of the read-only contract — not discipline, but enforcement."""
    src = _F5_SRC.read_text(encoding="utf-8")
    forbidden = [
        re.compile(r"requests\.(post|put|patch|delete)\b", re.I),
        re.compile(r"\.(post|put|patch|delete)\s*\(", re.I),
        re.compile(r"session\.(post|put|patch|delete)\b", re.I),
    ]
    hits = [p.pattern for p in forbidden if p.search(src)]
    assert not hits, f"Mutating HTTP verb found in clients/f5.py: {hits}"

    # The only network primitive should be requests.get.
    assert "requests.get(" in src


# ── Destination parsing ───────────────────────────────────────────────────────

@pytest.mark.parametrize("dest,expected", [
    ("/Common/1.2.3.4:443",     ("1.2.3.4", "443")),
    ("/Common/1.2.3.4:0",       ("1.2.3.4", "0")),       # 0 = any port
    ("/Common/1.2.3.4%2:80",    ("1.2.3.4", "80")),      # route domain stripped
    ("1.2.3.4%5:443",           ("1.2.3.4", "443")),
    ("/Common/2001:db8::1.443", ("2001:db8::1", "443")), # IPv6 port sep is '.'
    ("/Common/2001:db8::5",     ("2001:db8::5", "")),     # IPv6, no port
    ("/Common/1.2.3.0:any",     ("1.2.3.0", "any")),
    ("", ("", "")),
])
def test_parse_destination(dest, expected):
    assert f5._parse_destination(dest) == expected


def test_short_strips_partition():
    assert f5._short("/Common/pool_web") == "pool_web"
    assert f5._short("pool_web") == "pool_web"
    assert f5._short(None) == ""


def test_vs_status():
    assert f5._vs_status({"enabled": True}) == "enabled"
    assert f5._vs_status({"disabled": True}) == "disabled"
    assert f5._vs_status({}) == "unknown"


# ── collect_device parsing (no network — _get is monkeypatched) ────────────────

_CANNED = {
    "cm/device": {"items": [{
        "hostname": "f5-test-01", "managementIp": "10.20.0.50", "selfDevice": "true",
        "marketingName": "BIG-IP i5800", "version": "16.1.3", "edition": "Final",
        "failoverState": "active", "chassisId": "chs-test",
    }, {
        "hostname": "f5-test-02", "managementIp": "10.20.0.51", "selfDevice": "false",
        "failoverState": "standby",
    }]},
    "net/self": {"items": [{
        "name": "/Common/external-self", "address": "1.2.3.5/24",
        "vlan": "/Common/external", "trafficGroup": "/Common/traffic-group-local-only",
        "floating": "disabled", "allowService": "none",
    }]},
    "net/vlan": {"items": [{
        "name": "/Common/external", "tag": 1010, "mtu": 1500,
        "interfacesReference": {"items": [{"name": "1.1"}]},
    }]},
    "net/interface": {"items": [{
        "name": "1.1", "macAddress": "00:50:56:aa:01:01", "enabled": True,
        "mediaActive": "10000SR-FD", "mtu": 1500,
    }]},
    "ltm/virtual/stats": {"entries": {
        "https://localhost/mgmt/tm/ltm/virtual/~Common~vs_web/stats": {"nestedStats": {"entries": {
            "tmName": {"description": "/Common/vs_web"},
            "status.availabilityState": {"description": "available"},
        }}}
    }},
    "ltm/virtual": {"items": [{
        "name": "/Common/vs_web", "destination": "/Common/1.2.3.100:443",
        "pool": "/Common/pool_web", "ipProtocol": "tcp", "enabled": True, "partition": "Common",
    }]},
    "ltm/pool": {"items": [{
        "name": "/Common/pool_web", "partition": "Common",
        "loadBalancingMode": "round-robin", "monitor": "/Common/https",
        "membersReference": {"items": [
            {"name": "/Common/10.50.1.11:443", "address": "10.50.1.11", "state": "up", "session": "monitor-enabled"},
        ]},
    }]},
    "ltm/node": {"items": [{
        "name": "/Common/10.50.1.11", "address": "10.50.1.11", "state": "up", "session": "monitor-enabled",
    }]},
    "net/route": {"items": [{"name": "/Common/default", "network": "default", "gw": "1.2.3.1"}]},
}


def _fake_get(host, path, user, pwd, timeout=30):
    # Order matters: 'virtual/stats' must be checked before 'ltm/virtual'.
    for key in ("ltm/virtual/stats", "cm/device", "net/self", "net/vlan",
                "net/interface", "ltm/virtual", "ltm/pool", "ltm/node", "net/route"):
        if key in path:
            return _CANNED[key]
    raise AssertionError(f"unexpected path: {path}")


def test_collect_device(monkeypatch):
    monkeypatch.setattr(f5, "_get", _fake_get)
    bundle = f5.collect_device("f5.example", "10.20.0.50", "user", "pwd")

    inv = bundle["inventory"]
    assert inv["hostname"] == "f5-test-01"          # picks the selfDevice unit
    assert inv["failoverState"] == "active"
    assert inv["model"] == "BIG-IP i5800"

    assert bundle["self_ips"][0]["name"] == "external-self"
    assert bundle["self_ips"][0]["address"] == "1.2.3.5/24"
    assert bundle["vlans"][0]["interfaces"] == "1.1"

    vs = bundle["virtuals"][0]
    assert vs["ip"] == "1.2.3.100" and vs["port"] == "443"
    assert vs["pool"] == "pool_web"
    assert vs["availability"] == "available"

    assert bundle["pools"][0]["member_count"] == 1
    assert bundle["nodes"][0]["address"] == "10.50.1.11"
    assert bundle["routes"][0]["gw"] == "1.2.3.1"


def test_connectivity_check(monkeypatch):
    monkeypatch.setattr(f5, "_get", _fake_get)
    ok, detail = f5.connectivity_check("f5.example", "user", "pwd")
    assert ok is True
    assert "f5-test-01" in detail


# ── CSV parsing ───────────────────────────────────────────────────────────────

def test_csv_parsing(tmp_path, monkeypatch):
    import routers.f5 as rf5
    csv_file = tmp_path / "f5.csv"
    csv_file.write_text("hostname,management ip address\nf5-a,10.20.0.10\nf5-b,10.20.0.11\n,missing-host\n")
    monkeypatch.setattr(rf5, "F5_CSV_PATH", csv_file)
    devices = rf5.get_f5_devices_from_csv()
    assert devices == [
        {"hostname": "f5-a", "ip": "10.20.0.10"},
        {"hostname": "f5-b", "ip": "10.20.0.11"},
    ]


# ── Site filtering ────────────────────────────────────────────────────────────

def test_site_helpers():
    import routers.f5 as rf5
    assert rf5._site_of("dal1-f5-01") == "DAL1"
    assert rf5._site_of("") == ""

    rows = [
        {"hostname": "dal1-f5-01"}, {"hostname": "dal1-f5-02"},
        {"hostname": "res1-f5-01"}, {"hostname": "cos1-f5-01"},
    ]
    assert len(rf5._by_site(rows, "all")) == 4
    assert len(rf5._by_site(rows, None)) == 4
    assert [r["hostname"] for r in rf5._by_site(rows, "dal1")] == ["dal1-f5-01", "dal1-f5-02"]
    assert [r["hostname"] for r in rf5._by_site(rows, "RES1")] == ["res1-f5-01"]


def test_get_f5_sites(monkeypatch):
    import routers.f5 as rf5
    from cache import cache, TTL_F5
    cache.set("f5_inventory", [
        {"hostname": "dal1-f5-01"}, {"hostname": "res1-f5-02"}, {"hostname": "dal1-f5-02"},
    ], TTL_F5)
    assert rf5.get_f5_sites() == ["DAL1", "RES1"]


# ── IPAM discovery ────────────────────────────────────────────────────────────

def test_ipam_discover_f5():
    import asyncio
    from cache import cache, TTL_F5
    from utils.ipam_engine import IPAMEngine

    cache.set("f5_self_ips", [
        {"hostname": "f5-a", "name": "internal-self", "address": "1.2.3.0/24", "vlan": "internal"},
    ], TTL_F5)
    cache.set("f5_virtuals", [
        {"hostname": "f5-a", "name": "vs_web", "ip": "5.6.7.8", "port": "443"},
    ], TTL_F5)

    engine = IPAMEngine()
    asyncio.run(engine._discover_f5(None, None))

    by_cidr = {n.cidr: n for n in engine.subnets if n.source == "F5"}
    assert "1.2.3.0/24" in by_cidr
    assert by_cidr["1.2.3.0/24"].site == "LoadBalancer"
    assert "5.6.7.8/32" in by_cidr
    assert by_cidr["5.6.7.8/32"].role == "vip"


# ── IP lookup integration (DEV_MODE, via cache) ───────────────────────────────

def test_ip_lookup_finds_f5(monkeypatch):
    import asyncio
    import time as _t
    from cache import cache, TTL_F5
    from auth import SessionEntry
    from routers.dnac import ip_lookup_handler

    cache.set("f5_self_ips", [
        {"hostname": "f5-a", "name": "external-self", "address": "1.2.3.5/24",
         "vlan": "external", "trafficGroup": "tg"},
    ], TTL_F5)
    cache.set("f5_virtuals", [
        {"hostname": "f5-a", "name": "vs_web", "ip": "1.2.3.100", "port": "443",
         "pool": "pool_web", "status": "enabled", "availability": "available"},
    ], TTL_F5)

    sess = SessionEntry(username="dev", password="dev", expires_at=_t.monotonic() + 3600)

    vip = asyncio.run(ip_lookup_handler("1.2.3.100", sess))
    assert vip["found"] is True
    assert len(vip["f5_virtual_servers"]) == 1
    assert vip["f5_virtual_servers"][0]["pool"] == "pool_web"

    self_ip = asyncio.run(ip_lookup_handler("1.2.3.5", sess))
    assert self_ip["found"] is True
    assert len(self_ip["f5_self_ips"]) == 1
    assert self_ip["f5_self_ips"][0]["name"] == "external-self"
