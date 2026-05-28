"""Tests for utils.ip_audit — the dual-stack reconciliation engine.

The classifier (reconcile) is tested as a pure function over synthetic rows.
The extractors are tested against fake caches matching the real shapes (fake
addressing per repo convention)."""
from __future__ import annotations

from cache import IPAM_TREE_CACHE_KEY
from utils import ip_audit
from utils.ip_audit import Observed, collect_observed, reconcile


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
        _prefix(11, 1, "2000:2000:3000:1900::/56", 6, "site"),
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
    assert netonly["suggested_role"] == "site-aggregate"
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
