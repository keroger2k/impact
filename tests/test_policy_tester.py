"""Tests for the firewall Policy Tester: zone-aware rule matching in
clients.panorama and the multi-flow /api/firewall/policy-test endpoint.

Endpoint tests call the async handler directly (the project's pattern, see
test_ip_registry_router) with _load_policy_context monkeypatched, so no cache
or Panorama access is involved. All addresses are fake per IP_ADDRESS_POLICY.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import clients.panorama as pc
from routers import firewall as fw


# ── clients.panorama unit tests ──────────────────────────────────────────────

def test_zone_matches_wildcards_and_membership():
    assert pc.zone_matches(None, ["trust"])          # no query zone → wildcard
    assert pc.zone_matches("", ["trust"])
    assert pc.zone_matches("any", ["trust"])
    assert pc.zone_matches("trust", [])              # rule with no zones
    assert pc.zone_matches("trust", ["any"])
    assert pc.zone_matches("trust", ["trust", "dmz"])
    assert not pc.zone_matches("untrust", ["trust", "dmz"])


def test_resolve_name_falls_back_to_literal_values():
    assert pc.resolve_name("10.10.0.0/16", {}, {}) == ["10.10.0.0/16"]
    assert pc.resolve_name("1.2.3.4", {}, {}) == ["1.2.3.4"]
    assert pc.resolve_name("1.2.3.4-1.2.3.9", {}, {}) == ["1.2.3.4-1.2.3.9"]
    assert pc.resolve_name("NET-UNDEFINED", {}, {}) == []


def _rule(**over):
    base = {
        "device_group": "DG-A", "rulebase": "pre", "name": "R1",
        "action": "allow", "disabled": False,
        "source": ["any"], "source_negate": False, "from_zones": ["trust"],
        "destination": ["any"], "dest_negate": False, "to_zones": ["untrust"],
        "application": ["any"], "service": ["any"],
    }
    base.update(over)
    return base


def test_find_matching_rules_filters_on_zones():
    rules = [_rule()]
    kw = dict(src_ip="1.2.3.4", dst_ip="5.6.7.8", rules=rules,
              objects={}, groups={})
    assert len(pc.find_matching_rules(**kw)) == 1                       # no zones queried
    assert len(pc.find_matching_rules(**kw, src_zone="trust", dst_zone="untrust")) == 1
    assert pc.find_matching_rules(**kw, src_zone="dmz") == []
    assert pc.find_matching_rules(**kw, dst_zone="trust") == []


def test_find_matching_rules_reads_legacy_from_to_keys():
    rule = _rule()
    rule["from"] = rule.pop("from_zones")
    rule["to"] = rule.pop("to_zones")
    matches = pc.find_matching_rules(
        src_ip="1.2.3.4", dst_ip="5.6.7.8", rules=[rule],
        objects={}, groups={}, src_zone="trust", dst_zone="untrust")
    assert len(matches) == 1


# ── endpoint tests ───────────────────────────────────────────────────────────

RULES = [
    _rule(name="Allow-Web", source=["NET-CORP"], destination=["1.2.3.0/24"],
          service=["SVC-HTTPS"]),
    _rule(name="Deny-DMZ", action="deny", from_zones=["dmz"], to_zones=["any"]),
]
CONTEXT = (
    ["DG-A"],                          # all_dgs
    {"NET-CORP": ["10.10.0.0/16"]},    # objects
    {},                                # groups
    {"SVC-HTTPS": [("tcp", "443")]},   # svc_obj
    {},                                # svc_grp
    {"dg_order": ["DG-A"], "by_dg": {"shared": [], "DG-A": RULES}},
)


@pytest.fixture
def ctx(monkeypatch):
    async def fake_context(session):
        return CONTEXT
    monkeypatch.setattr(fw, "_load_policy_context", fake_context)


def _req(hx: bool = False):
    m = MagicMock()
    m.headers = {"HX-Request": "true"} if hx else {}
    return m


@pytest.mark.asyncio
async def test_policy_test_multi_flow_verdicts(ctx):
    out = await fw.policy_test(
        _req(), device_group="DG-A",
        src_ip=["10.10.1.1", "5.6.7.8", "5.6.7.8"],
        src_zone=["trust", "", "guest"],
        dst_ip=["1.2.3.4", "1.2.3.4", "5.6.7.9"],
        dst_zone=["untrust", "", "guest"],
        protocol=["tcp", "any", "any"],
        dst_port=["443", "", ""],
        include_disabled=False, session=None,
    )
    r1, r2, r3 = out["results"]
    # flow 1: hits Allow-Web on zones + object + service
    assert r1["verdict"] == "allow"
    assert r1["matched_rule"]["name"] == "Allow-Web"
    # flow 2: zones blank are wildcards → hits Deny-DMZ (from dmz, any/any)
    assert r2["verdict"] == "deny"
    assert r2["matched_rule"]["name"] == "Deny-DMZ"
    # flow 3: same src/dst zone, no match → intrazone default allow
    assert r3["verdict"] == "allow (intrazone-default)"


@pytest.mark.asyncio
async def test_policy_test_row_errors_and_blank_rows(ctx):
    out = await fw.policy_test(
        _req(), device_group="DG-A",
        src_ip=["not-an-ip", "", "10.10.1.1"],
        src_zone=["", "", ""],
        dst_ip=["1.2.3.4", "", "1.2.3.4"],
        dst_zone=["", "", ""],
        protocol=["any", "any", "tcp"],
        dst_port=["", "", "99999"],
        include_disabled=False, session=None,
    )
    assert len(out["results"]) == 2  # blank row skipped entirely
    assert out["results"][0]["verdict_kind"] == "error"
    assert out["results"][1]["verdict_kind"] == "error"  # port out of range


@pytest.mark.asyncio
async def test_policy_test_rejects_unknown_device_group(ctx):
    with pytest.raises(HTTPException) as exc:
        await fw.policy_test(
            _req(), device_group="DG-NOPE",
            src_ip=["1.2.3.4"], src_zone=[""], dst_ip=["5.6.7.8"],
            dst_zone=[""], protocol=["any"], dst_port=[""],
            include_disabled=False, session=None,
        )
    assert exc.value.status_code == 400


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
