"""Tests for utils.ip_audit — the dual-stack reconciliation engine.

The classifier (reconcile) is tested as a pure function over synthetic rows.
The extractors are tested against fake caches matching the real shapes (fake
addressing per repo convention)."""
from __future__ import annotations

import ipaddress

import pytest

from cache import IPAM_TREE_CACHE_KEY
from utils import ip_audit
from utils.ip_audit import Observed, collect_observed, reconcile


@pytest.fixture(autouse=True)
def _fake_audit_scope(monkeypatch):
    """Point the audit's in-scope check at fake example space so these fixtures
    carry no real addressing (see docs/IP_ADDRESS_POLICY.md). Mirrors the real
    default shape — RFC1918 + a single /40 IPv6 block — using the documentation
    block 1000:2000:3000::/40 in place of the org's real allocation."""
    monkeypatch.setattr(ip_audit, "_IN_SCOPE", [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("1000:2000:3000::/40"),
    ])


class FakeCache:
    def __init__(self, data: dict):
        self.data = data

    def get(self, key, default=None):
        return self.data.get(key, default)

    def keys_for_prefix(self, prefix):
        return [k for k in self.data if k.startswith(prefix)]


def _site(id, code):
    return {"id": id, "site_code": code, "name": code}


def _prefix(id, site_id, cidr, family, role="subnet"):
    return {"id": id, "site_id": site_id, "cidr": cidr, "family": family, "role": role}


# ── reconcile: the four states ─────────────────────────────────────────────────

def test_reconcile_all_states():
    sites = [_site(1, "K001")]
    prefixes = [
        _prefix(10, 1, "10.0.0.0/16", 4, "site-aggregate"),
        _prefix(11, 1, "1000:2000:3000:1900::/56", 6, "site"),
        _prefix(12, 1, "10.20.0.0/24", 4),
    ]
    observed = [
        Observed("10.0.0.0/16", 4, "dnac", "K001"),       # exact → in-sync (p10)
        Observed("10.0.5.0/24", 4, "nexus", "K001"),      # member of p10 → covered
        Observed("10.9.9.0/24", 4, "dnac", "K001"),       # disjoint → network-only
        Observed("10.20.0.0/23", 4, "panorama", "K001"),  # supernet of p12 → mismatch
        Observed("10.50.0.0/24", 4, "nexus", "Z999"),     # unknown site → new-site cand
        Observed("10.77.0.0/24", 4, "aci"),               # no code, not contained → loose
    ]
    rep = reconcile(sites, prefixes, observed)
    s = rep["summary"]
    assert s["in_sync"] == 2          # p10 (10.0.0.0/16) and p12 (covered by /23)
    assert s["registry_only"] == 1    # the IPv6 /56
    assert s["registry_only_v6"] == 1
    assert s["network_only"] == 1     # 10.9.9.0/24
    assert s["mismatch"] == 1         # 10.20.0.0/23 broader than registered /24
    assert s["unattributed"] == 1     # 10.77.0.0/24
    assert s["new_site_candidates"] == 1

    # The drift list carries the bits needed for one-click accept.
    site_rep = rep["sites"][0]
    netonly = [d for d in site_rep["drift"] if d["kind"] == "network-only"][0]
    assert netonly["cidr"] == "10.9.9.0/24"
    assert netonly["site_id"] == 1
    assert netonly["suggested_role"] == "subnet"   # plain subnet, not a fake aggregate
    mismatch = [d for d in site_rep["drift"] if d["kind"] == "mismatch"][0]
    assert mismatch["related"] == ["10.20.0.0/24"]

    cand = rep["new_site_candidates"][0]
    assert cand["site_code"] == "Z999"
    assert cand["prefixes"][0]["cidr"] == "10.50.0.0/24"


def test_reconcile_attributes_by_containment_when_no_site_code():
    """An observation with no site code but inside a site's aggregate is
    attributed to that site (catches a site subnet seen in a DC fabric)."""
    sites = [_site(1, "K015")]
    prefixes = [_prefix(10, 1, "10.25.0.0/16", 4, "site-aggregate")]
    observed = [Observed("10.25.7.0/24", 4, "aci", site_code="")]  # member, no code
    rep = reconcile(sites, prefixes, observed)
    # Attributed → it's a covered member, so no unattributed, no drift, and the
    # aggregate is confirmed in-sync.
    assert rep["summary"]["unattributed"] == 0
    assert rep["summary"]["in_sync"] == 1
    assert rep["sites"][0]["drift"] == []


def test_reconcile_registry_only_when_nothing_observed():
    sites = [_site(1, "K001")]
    prefixes = [_prefix(10, 1, "10.0.0.0/24", 4)]
    rep = reconcile(sites, prefixes, [])
    assert rep["summary"]["registry_only"] == 1
    assert rep["summary"]["in_sync"] == 0


# ── extractors ─────────────────────────────────────────────────────────────────

def test_extract_nexus():
    cache = FakeCache({"nexus_interfaces": [
        {"hostname": "k015fwl001", "interface_name": "Vlan100",
         "ipv4_address": "10.25.24.1/24"},
        {"hostname": "k015fwl001", "interface_name": "Eth1/1",
         "ipv4_address": "N/A"},   # skipped
    ]})
    out = ip_audit._from_nexus(cache)
    assert len(out) == 1
    assert out[0].cidr == "10.25.24.0/24"
    assert out[0].site_code == "K015"
    assert out[0].source == "nexus"


def test_extract_panorama_interfaces_and_objects():
    cache = FakeCache({
        "pan_interfaces": [
            {"hostname": "k015fwl001", "interfaces": [
                {"name": "eth1/1", "ipv4": "10.25.0.1/24"},
                {"name": "eth1/2", "ipv4": ""},   # no prefix → skipped
            ]},
        ],
        "pan_address_objects": [
            {"name": "NET-X", "type": "ip-netmask", "value": "10.5.0.0/16",
             "device_group": "shared"},
            {"name": "FQDN-Y", "type": "fqdn", "value": "example.test"},  # skipped
        ],
    })
    out = ip_audit._from_panorama(cache)
    cidrs = sorted(o.cidr for o in out)
    assert cidrs == ["10.25.0.0/24", "10.5.0.0/16"]
    assert all(o.source == "panorama" for o in out)


def test_extract_ipam_tree_recurses_and_attributes():
    cache = FakeCache({IPAM_TREE_CACHE_KEY: {
        "ipv4": [{
            "cidr": "10.0.0.0/16", "source": "DNAC-Config",
            "site": "Global/CA/K015", "role": "aggregate",
            "children": [
                {"cidr": "10.0.1.0/24", "source": "DNAC-Config",
                 "site": "Global/CA/K015", "role": "subnet", "children": []},
                {"cidr": "Host Routes (K015)", "source": "Aggregate",
                 "site": "Global/CA/K015", "children": []},  # pseudo-label → skipped
            ],
        }],
        "ipv6": [],
    }})
    out = ip_audit._from_ipam_tree(cache)
    cidrs = sorted(o.cidr for o in out)
    assert cidrs == ["10.0.0.0/16", "10.0.1.0/24"]
    assert all(o.site_code == "K015" for o in out)


def test_extract_dnac_interfaces_fallback_and_aci():
    cache = FakeCache({
        "dnac_interfaces": [
            {"deviceId": "d1", "deviceName": "SW1", "portName": "Vlan100",
             "ipv4Address": "10.1.1.1", "ipv4Mask": "255.255.255.0"},
        ],
        "device_site_map": {"d1": "Global/CA/K015"},
        "aci_dc1_subnets": {"imdata": [
            {"fvSubnet": {"attributes": {"ip": "10.2.2.1/24",
                                         "dn": "uni/tn-x/BD-y/subnet-[10.2.2.1/24]"}}},
        ]},
    })
    dnac = ip_audit._from_dnac_interfaces(cache)
    assert dnac[0].cidr == "10.1.1.0/24" and dnac[0].site_code == "K015"

    aci = ip_audit._from_aci(cache)
    assert aci[0].cidr == "10.2.2.0/24" and aci[0].source == "aci"
    assert aci[0].site_code == ""   # DC subnets attribute by containment only


def test_out_of_scope_dropped_in_scope_kept():
    # In scope: RFC1918 + the org IPv6 block (1000:2000:3000::/40).
    assert ip_audit._canon("10.0.0.0/8") is not None
    assert ip_audit._canon("172.17.13.80/29") is not None     # 172.16/12
    assert ip_audit._canon("192.168.1.0/24") is not None
    assert ip_audit._canon("1000:2000:3023::/48") is not None  # S041 — inside /40
    assert ip_audit._canon("1000:2000:3059:88::/64") is not None
    # Out of scope: public, CGNAT, link-local, and IPv6 outside the org block.
    assert ip_audit._canon("98.97.64.0/21") is None           # public — not tracked
    assert ip_audit._canon("100.64.0.0/10") is None           # CGNAT object-group
    assert ip_audit._canon("169.254.1.0/24") is None
    assert ip_audit._canon("1000:2000:c0::/48") is None        # 1000:2000 but not 30xx
    assert ip_audit._canon("fe80::/64") is None


def test_default_routes_excluded():
    assert ip_audit._canon("0.0.0.0/0") is None
    assert ip_audit._canon("::/0") is None
    assert ip_audit._canon("10.0.0.0/8") is not None
    cache = FakeCache({"dnac_global_pools": [
        {"ipPoolCidr": "0.0.0.0/0", "ipPoolName": "default"},
        {"ipPoolCidr": "10.0.0.0/8", "ipPoolName": "ent"},
    ]})
    cidrs = {o.cidr for o in collect_observed(cache, sources=["dnac"])}
    assert "0.0.0.0/0" not in cidrs and "10.0.0.0/8" in cidrs


def test_vlan_from_name():
    assert ip_audit._vlan_from("Vlan100") == 100
    assert ip_audit._vlan_from("vlan 20") == 20
    assert ip_audit._vlan_from("Gi0/0") is None


def test_role_suggestion_from_iface_type():
    sites = [_site(1, "K001")]
    obs = [
        Observed("10.1.1.0/24", 4, "dnac", "K001", interface="Vlan100",
                 iface_type="svi", vlan=100),
        Observed("10.2.0.0/20", 4, "dnac", "K001", iface_type="aggregate",
                 label="EIGRP Summary"),
        Observed("10.3.3.0/24", 4, "dnac", "K001"),     # no hint → subnet
    ]
    rep = reconcile(sites, [], obs)
    drift = {d["cidr"]: d for d in rep["sites"][0]["drift"]}
    assert drift["10.1.1.0/24"]["suggested_role"] == "vlan"
    assert drift["10.1.1.0/24"]["vlan_id"] == 100
    assert drift["10.2.0.0/20"]["suggested_role"] == "site-aggregate"
    assert drift["10.3.3.0/24"]["suggested_role"] == "subnet"


def test_collect_svi_vlan_from_portname():
    cache = FakeCache({
        "dnac_interfaces": [{"deviceId": "d1", "portName": "Vlan100",
                             "ipv4Address": "10.1.1.1", "ipv4Mask": "255.255.255.0"}],
        "device_site_map": {"d1": "Global/CA/K015"},
    })
    out = collect_observed(cache, sources=["dnac"])
    assert out[0].iface_type == "svi" and out[0].vlan == 100


def test_p2p_tunnel_goes_to_infrastructure_not_dmvpn():
    # A /30 Palo tunnel.N is a point-to-point link, not a shared overlay.
    obs = [Observed("10.100.102.196/30", 4, "panorama", interface="tunnel.1",
                    iface_type="tunnel")]
    rep = reconcile([_site(1, "K001")], [], obs)
    assert rep["summary"]["dmvpn_overlays"] == 0
    assert rep["summary"]["host_routes"] == 1
    assert rep["infrastructure"]["by_type"].get("p2p") == 1   # relabeled from tunnel


def test_multi_site_supernet_is_shared_not_per_site_mismatch():
    # An org /48 that contains several airports' /56s is a shared supernet,
    # not S041's mismatch (the inverse of the single-site /48-over-/56 case).
    sites = [_site(1, "S041"), _site(2, "S689"), _site(3, "T271")]
    prefixes = [
        _prefix(11, 1, "1000:2000:3023:200::/56", 6, "site"),
        _prefix(12, 2, "1000:2000:3023:300::/56", 6, "site"),
        _prefix(13, 3, "1000:2000:3023:400::/56", 6, "site"),
    ]
    obs = [Observed("1000:2000:3023::/48", 6, "dnac",
                    label="Inferred IPv6 /48 Org Supernet")]
    rep = reconcile(sites, prefixes, obs)
    assert rep["summary"]["shared_supernets"] == 1
    assert rep["summary"]["mismatch"] == 0
    ss = rep["shared_supernets"][0]
    assert ss["cidr"] == "1000:2000:3023::/48"
    assert set(ss["sites"]) == {"S041", "S689", "T271"}
    assert ss["site_count"] == 3
    assert ss["suggested_role"] == "supernet"
    assert all(not s["drift"] for s in rep["sites"])   # no per-site drift from it


def test_bidirectional_containment_ipv6_48_over_56():
    sites = [_site(1, "K015")]
    prefixes = [_prefix(11, 1, "1000:2000:3007:700::/56", 6, "site")]
    # DNAC advertises the /48; the registry documents a /56 inside it, no code.
    obs = [Observed("1000:2000:3007::/48", 6, "dnac")]
    rep = reconcile(sites, prefixes, obs)
    assert rep["summary"]["unattributed"] == 0
    site_rep = rep["sites"][0]
    assert site_rep["counts"]["in_sync"] == 1            # the /56 is confirmed
    drift = {d["cidr"]: d for d in site_rep["drift"]}
    assert drift["1000:2000:3007::/48"]["kind"] == "mismatch"


def test_container_reconciliation_credits_stip_and_absorbs_members():
    sites = [_site(1, "K001")]
    prefixes = [{"id": 99, "site_id": None, "cidr": "1000:2000:3059::/48",
                 "family": 6, "role": "container", "label": "STIP"}]
    obs = [
        Observed("1000:2000:3059::/48", 6, "dnac"),       # the /48 itself, no code
        Observed("1000:2000:3059:5::/64", 6, "dnac"),     # a member, no code
    ]
    rep = reconcile(sites, prefixes, obs)
    assert rep["summary"]["unattributed"] == 0           # both covered by container
    assert rep["summary"]["containers_in_sync"] == 1
    conts = {c["prefix"]["cidr"]: c for c in rep["containers"]}
    assert conts["1000:2000:3059::/48"]["state"] == "in-sync"


def test_soho_tag_resolves_to_real_site_code():
    from utils.site_code import site_code_strict
    assert site_code_strict("Global/USA/SOHO/SDCZ - Office") == "SDCZ"
    assert site_code_strict("Global/SOHO") == ""          # only the tag, no real code
    # the audit's _code falls back to the device hostname when the path has none
    assert ip_audit._code("Global/SOHO", "sdczfwl001") == "SDCZ"


def test_iface_type_classifier():
    f = ip_audit._iface_type
    assert f("Tunnel200", 4, 21) == "tunnel"
    assert f("Virtual-Template1", 4, 30) == "tunnel"
    assert f("Loopback0", 4, 32) == "loopback"
    assert f("", 4, 32) == "loopback"          # length rule
    assert f("", 6, 128) == "loopback"
    assert f("Vlan100", 4, 24) == "svi"
    assert f("mgmt0", 4, 24) == "management"
    assert f("Gi0/0", 4, 30) == "p2p"
    assert f("Gi0/0", 4, 24) == ""             # ordinary subnet


def test_host_routes_are_bucketed_not_drift():
    sites = [_site(1, "K001")]
    prefixes = [_prefix(10, 1, "10.0.0.0/16", 4, "site-aggregate")]
    obs = [
        Observed("10.0.0.1/32", 4, "dnac", "K001", interface="Loopback0", iface_type="loopback"),
        Observed("10.0.0.4/30", 4, "dnac", "K001", interface="Gi0/0", iface_type="p2p"),
        Observed("10.0.5.0/24", 4, "nexus", "K001"),   # member of the /16 → covered
    ]
    rep = reconcile(sites, prefixes, obs)
    assert rep["summary"]["host_routes"] == 2
    assert rep["infrastructure"]["by_type"] == {"loopback": 1, "p2p": 1}
    # host routes never appear as per-site drift
    assert all(not sr["drift"] for sr in rep["sites"])
    # the /16 is still confirmed in-sync by the covered /24 member
    assert rep["summary"]["in_sync"] == 1


def test_dmvpn_overlay_grouped_across_sites_not_per_site():
    sites = [_site(1, "K001"), _site(2, "K002"), _site(3, "K003")]
    prefixes = [_prefix(10, 1, "10.0.0.0/16", 4)]
    # Same overlay subnet on a Tunnel iface at three sites (canonical cidr).
    obs = [Observed("10.100.216.0/21", 4, "dnac", code, interface="Tunnel200",
                    iface_type="tunnel") for code in ("K001", "K002", "K003")]
    rep = reconcile(sites, prefixes, obs)
    assert rep["summary"]["dmvpn_overlays"] == 1
    ov = rep["dmvpn_overlays"][0]
    assert ov["cidr"] == "10.100.216.0/21"
    assert ov["label"] == "Tunnel200"
    assert ov["participants"] == 3
    assert ov["in_registry"] is False
    assert ov["suggested_role"] == "dmvpn"
    # The overlay is NOT counted as per-site drift at any site.
    assert rep["summary"]["network_only"] == 0
    assert all(not sr["drift"] for sr in rep["sites"])


def test_dmvpn_overlay_flagged_in_registry_when_container_exists():
    sites = [_site(1, "K001")]
    prefixes = [{"id": 99, "site_id": None, "cidr": "10.100.216.0/21",
                 "family": 4, "role": "dmvpn"}]
    obs = [Observed("10.100.216.0/21", 4, "dnac", "K001", interface="Tunnel200",
                    iface_type="tunnel")]
    rep = reconcile(sites, prefixes, obs)
    assert rep["dmvpn_overlays"][0]["in_registry"] is True


def test_collect_observed_classifies_tunnel_from_portname():
    cache = FakeCache({
        "dnac_interfaces": [
            {"deviceId": "d1", "portName": "Tunnel200",
             "ipv4Address": "10.100.216.5", "ipv4Mask": "255.255.248.0"},
        ],
        "device_site_map": {"d1": "Global/CA/K015"},
    })
    out = collect_observed(cache, sources=["dnac"])
    assert out[0].cidr == "10.100.216.0/21"   # /21 from the netmask
    assert out[0].iface_type == "tunnel"
    assert out[0].interface == "Tunnel200"


def test_collect_observed_dedupes_and_uses_interface_fallback():
    # No IPAM tree → the dnac extractor falls back to raw interfaces, then we
    # dedupe by (cidr, source).
    cache = FakeCache({
        "dnac_interfaces": [
            {"deviceId": "d1", "ipv4Address": "10.1.1.1", "ipv4Mask": "255.255.255.0"},
            {"deviceId": "d1", "ipv4Address": "10.1.1.50", "ipv4Mask": "255.255.255.0"},
        ],
        "device_site_map": {"d1": "Global/CA/K015"},
    })
    out = collect_observed(cache, sources=["dnac"])
    assert len(out) == 1   # both interfaces normalize to 10.1.1.0/24
    assert out[0].cidr == "10.1.1.0/24"
