"""Tests for the firewall Policy Tester: live `test security-policy-match`
command building/parsing in clients.panorama and the multi-flow
/api/firewall/policy-test endpoint.

Endpoint tests call the async handler directly (the project's pattern, see
test_ip_registry_router) with the Panorama call and cache monkeypatched, so no
network or cache access is involved. All addresses are fake per
IP_ADDRESS_POLICY.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import clients.panorama as pc
from routers import firewall as fw


# ── clients.panorama unit tests ──────────────────────────────────────────────

def test_resolve_name_falls_back_to_literal_values():
    assert pc.resolve_name("10.10.0.0/16", {}, {}) == ["10.10.0.0/16"]
    assert pc.resolve_name("1.2.3.4", {}, {}) == ["1.2.3.4"]
    assert pc.resolve_name("1.2.3.4-1.2.3.9", {}, {}) == ["1.2.3.4-1.2.3.9"]
    assert pc.resolve_name("NET-UNDEFINED", {}, {}) == []


def test_build_policy_match_cmd_full_and_minimal():
    cmd = pc.build_policy_match_cmd(
        "1.2.3.4", "5.6.7.8", "tcp", dst_port=443,
        from_zone="trust", to_zone="untrust", application="ssl")
    assert cmd == ('test security-policy-match source 1.2.3.4 destination 5.6.7.8 '
                   'protocol 6 destination-port 443 from "trust" to "untrust" application "ssl"')
    assert pc.build_policy_match_cmd("1.2.3.4", "5.6.7.8", "icmp") == \
        "test security-policy-match source 1.2.3.4 destination 5.6.7.8 protocol 1"
    assert "protocol 17" in pc.build_policy_match_cmd("1.2.3.4", "5.6.7.8", "udp")


def test_parse_policy_match_result_modern_xml():
    xml = """<response status="success"><result><rules>
      <entry name="Allow-Web"><action>allow</action><index>7</index>
        <from>trust</from><to>untrust</to></entry>
    </rules></result></response>"""
    parsed = pc.parse_policy_match_result(ET.fromstring(xml))
    assert parsed["ok"]
    assert parsed["rules"][0] == {"name": "Allow-Web", "action": "allow",
                                  "index": "7", "from": "trust", "to": "untrust"}


def test_parse_policy_match_result_legacy_text_and_default_rules():
    xml = "<result><rules><entry>interzone-default</entry></rules></result>"
    parsed = pc.parse_policy_match_result(ET.fromstring(xml))
    assert parsed["rules"][0]["name"] == "interzone-default"
    assert parsed["rules"][0]["action"] == "deny"  # inferred

    xml = '<result><rules><entry name="intrazone-default"/></rules></result>'
    parsed = pc.parse_policy_match_result(ET.fromstring(xml))
    assert parsed["rules"][0]["action"] == "allow"  # inferred


def test_parse_policy_match_result_handles_failure():
    parsed = pc.parse_policy_match_result(None)
    assert not parsed["ok"] and "no response" in parsed["error"]
    parsed = pc.parse_policy_match_result(ET.fromstring("<result/>"))
    assert parsed["ok"] and parsed["rules"] == []


# ── endpoint tests ───────────────────────────────────────────────────────────

# show-devices-all output in production often lacks device-group (→ "N/A"), so
# DG membership must come from the config-sourced serial→DG mapping instead.
DEVICES = [
    {"serial": "SN-A1", "hostname": "FW-A-01", "model": "PA-3220",
     "device_group": "N/A", "ha_enabled": True, "ha_state": "active", "connected": True},
    {"serial": "SN-A2", "hostname": "FW-A-02", "model": "PA-3220",
     "device_group": "N/A", "ha_enabled": True, "ha_state": "passive", "connected": False},
    {"serial": "SN-B1", "hostname": "FW-B-01", "model": "PA-850",
     "device_group": "N/A", "ha_enabled": False, "ha_state": "", "connected": True},
    # not in the config mapping at all → device_group field is the fallback
    {"serial": "SN-C1", "hostname": "FW-C-01", "model": "PA-850",
     "device_group": "DG-C", "ha_enabled": False, "ha_state": "", "connected": True},
]
DG_MAP = {"SN-A1": "DG-A", "SN-A2": "DG-A", "SN-B1": "DG-B"}
CACHED = {
    "pan_managed_devices": DEVICES,
    "pan_device_groups": ["DG-A", "DG-B", "DG-C"],
    "pan_dg_device_map": DG_MAP,
}


@pytest.fixture
def live(monkeypatch):
    """Route the endpoint's cache/auth/Panorama dependencies to fixtures."""
    import dev
    monkeypatch.setattr(dev, "DEV_MODE", False)
    monkeypatch.setattr(fw, "_get_key", lambda session, force_refresh=False: "test-key")
    monkeypatch.setattr(fw.cache, "get_or_set",
                        lambda key, loader, ttl, **kw: CACHED.get(key), raising=False)

    calls = []
    def fake_test(api_key, serial, **kwargs):
        calls.append((serial, kwargs))
        if kwargs["dst_ip"] == "5.6.7.9":   # canned deny
            rules = [{"name": "Deny-Bad", "action": "deny", "index": "3"}]
        elif kwargs["dst_ip"] == "5.6.7.10":  # canned op failure
            return {"ok": False, "error": "no response from firewall", "cmd": "test ..."}
        else:
            rules = [{"name": "Allow-Web", "action": "allow", "index": "7"}]
        return {"ok": True, "rules": rules, "cmd": "test security-policy-match ..."}
    monkeypatch.setattr(fw.pc, "test_security_policy_match", fake_test)
    return calls


def _req(hx: bool = False):
    m = MagicMock()
    m.headers = {"HX-Request": "true"} if hx else {}
    return m


@pytest.mark.asyncio
async def test_policy_test_runs_live_per_flow(live):
    out = await fw.policy_test(
        _req(), device_group="DG-A", firewall="SN-A1",
        src_ip=["10.10.1.1", "10.10.1.1", "10.10.1.1", ""],
        src_zone=["trust", "", "", ""],
        dst_ip=["1.2.3.4", "5.6.7.9", "5.6.7.10", ""],
        dst_zone=["untrust", "", "", ""],
        protocol=["tcp", "udp", "tcp", "tcp"],
        dst_port=["443", "53", "", ""],
        application=["ssl", "", "", ""],
        session=None,
    )
    r1, r2, r3 = out["results"]  # blank 4th row skipped
    assert out["firewall"] == {"serial": "SN-A1", "hostname": "FW-A-01"}
    assert (r1["verdict"], r1["matched_rule"]["name"]) == ("allow", "Allow-Web")
    assert (r2["verdict"], r2["matched_rule"]["name"]) == ("deny", "Deny-Bad")
    assert r3["verdict_kind"] == "error" and "no response" in r3["error"]
    # every non-error flow hit the firewall's own engine — no local matching
    assert [c[0] for c in live] == ["SN-A1"] * 3
    assert live[0][1] == {"src_ip": "10.10.1.1", "dst_ip": "1.2.3.4", "protocol": "tcp",
                          "dst_port": 443, "from_zone": "trust", "to_zone": "untrust",
                          "application": "ssl"}


@pytest.mark.asyncio
async def test_policy_test_validates_rows_without_calling_firewall(live):
    out = await fw.policy_test(
        _req(), device_group="DG-A", firewall="SN-A1",
        src_ip=["not-an-ip", "10.10.1.1", "10.10.1.1"],
        src_zone=["", "", 'bad"zone'],
        dst_ip=["1.2.3.4", "1.2.3.4", "1.2.3.4"],
        dst_zone=["", "", ""],
        protocol=["tcp", "tcp", "tcp"],
        dst_port=["", "99999", ""],
        application=["", "", ""],
        session=None,
    )
    assert [r["verdict_kind"] for r in out["results"]] == ["error"] * 3
    assert live == []  # invalid rows never reach the firewall


@pytest.mark.asyncio
async def test_policy_test_rejects_bad_targets(live):
    kw = dict(src_ip=["1.2.3.4"], src_zone=[""], dst_ip=["5.6.7.8"], dst_zone=[""],
              protocol=["tcp"], dst_port=[""], application=[""], session=None)
    with pytest.raises(HTTPException) as exc:
        await fw.policy_test(_req(), device_group="DG-A", firewall="SN-NOPE", **kw)
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        await fw.policy_test(_req(), device_group="DG-A", firewall="SN-B1", **kw)
    assert exc.value.status_code == 400  # firewall exists but in another DG


@pytest.mark.asyncio
async def test_firewall_options_prefers_connected_active(live):
    resp = await fw.list_firewall_options(_req(), device_group="DG-A", session=None)
    body = resp.body.decode()
    assert body.index("SN-A1") < body.index("SN-A2")   # active+connected first
    assert 'value="SN-A1" selected' in body
    assert 'value="SN-A2" disabled' in body            # disconnected not selectable
    assert "SN-B1" not in body and "SN-C1" not in body
    resp = await fw.list_firewall_options(_req(), device_group="DG-EMPTY", session=None)
    assert "No firewalls" in resp.body.decode()


@pytest.mark.asyncio
async def test_firewall_membership_uses_config_map_with_field_fallback(live):
    # config mapping wins even though show-devices-all said "N/A"
    fws = await fw._firewalls_in_dg(None, "DG-B")
    assert [d["serial"] for d in fws] == ["SN-B1"]
    # device absent from the mapping falls back to its device_group field
    fws = await fw._firewalls_in_dg(None, "DG-C")
    assert [d["serial"] for d in fws] == ["SN-C1"]


def test_zones_for_dg_merges_rules_and_interfaces(monkeypatch):
    def fake_stale(key):
        if key == "pan_rules":
            return {"by_dg": {
                "shared": [{"from_zones": ["corp"], "to_zones": ["any"]}],
                "DG-A": [{"from": ["trust"], "to": ["untrust"]}],
                "DG-B": [{"from_zones": ["other-dg-zone"], "to_zones": []}],
            }}
        if key == "pan_interfaces":
            return [
                {"device_group": "DG-A", "interfaces": [{"zone": "vpn"}, {"zone": ""}]},
                {"device_group": "DG-B", "interfaces": [{"zone": "nope"}]},
            ]
        return None
    monkeypatch.setattr(fw.cache, "get_stale", fake_stale, raising=False)
    zones = fw._zones_for_dg("DG-A")
    assert zones == ["corp", "trust", "untrust", "vpn"]
