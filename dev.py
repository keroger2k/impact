"""
dev.py — DEV_MODE support for local development without real infrastructure.

Set DEV_MODE=true in .env (or environment) to enable:
  - Login accepts any username/password (LDAP bypassed)
  - All data endpoints return mock data (no Cisco/Palo Alto connections needed)
  - Warmup completes immediately
  - Status checks report all systems healthy

The server still starts normally — just set DEV_MODE=true and run uvicorn.
"""

import os
import time
import uuid

DEV_MODE = os.getenv("DEV_MODE", "").lower() in ("1", "true", "yes")

# Fixed token used for the auto-login flow in the frontend
DEV_TOKEN = "dev-local-token-impact-ii"
DEV_USER  = "dev"


def _uid(seed: str) -> str:
    """Deterministic UUID from a seed string so IDs are stable across restarts."""
    import hashlib
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ── Mock DNAC devices ─────────────────────────────────────────────────────────

_ROLES    = ["ACCESS", "ACCESS", "ACCESS", "DISTRIBUTION", "CORE"]
_PLATFORM = ["C9300-48U", "C9300-24P", "C9500-40X", "C9600-LC-40YL4", "ISR4451-X/K9"]
_VERSION  = ["17.9.3",    "17.9.3",    "17.12.1",  "17.12.1",         "17.6.5"]
_SITES    = [
    ("TSA-DCA-HQ",   "10.10"),
    ("TSA-BOS-T1",   "10.20"),
    ("TSA-LAX-T1",   "10.30"),
    ("TSA-ORD-T1",   "10.40"),
    ("TSA-JFK-T1",   "10.50"),
]

_now_ms = int(time.time() * 1000)

MOCK_DEVICES: list[dict] = []
MOCK_DEVICE_SITE_MAP: dict[str, str] = {}

for _si, (_site, _subnet) in enumerate(_SITES):
    for _di in range(20):
        _idx   = _si * 20 + _di
        _reach = "Unreachable" if _idx % 7 == 0 else "Reachable"
        _id    = _uid(f"device-{_idx}")
        _role  = _ROLES[_di % len(_ROLES)]
        _host  = f"SW-{_site.split('-')[1]}-{_di+1:02d}" if _role == "ACCESS" else f"CORE-{_site.split('-')[1]}-{_di+1:02d}"
        _dev   = {
            "id":                    _id,
            "hostname":              _host,
            "managementIpAddress":   f"{_subnet}.{_di+1}.1",
            "platformId":            _PLATFORM[_di % len(_PLATFORM)],
            "softwareVersion":       _VERSION[_di % len(_VERSION)],
            "role":                  _role,
            "serialNumber":          f"FCW{2300+_idx:04d}A{_si:02d}",
            "vendor":                "Cisco",
            "reachabilityStatus":    _reach,
            "reachabilityFailureReason": "" if _reach == "Reachable" else "SNMP Timeout",
            "upTime":                f"{_idx * 3 + 1} days, {_di} hours, 22 minutes",
            "lastUpdateTime":        _now_ms - _idx * 3_600_000,
            "lastContactFormatted":  "2026-04-09 08:00",
            "description":           "",
        }
        MOCK_DEVICES.append(_dev)
        MOCK_DEVICE_SITE_MAP[_id] = _site

MOCK_SITES = [{"id": _uid(f"site-{s}"), "name": s} for s, _ in _SITES]

MOCK_NEXUS_DEVICES = [
    {
        "id": f"nexus_N9K-DCA-{i+1:02d}",
        "hostname": f"N9K-DCA-{i+1:02d}",
        "managementIpAddress": f"10.10.200.{i+1}",
        "platformId": "Nexus 9396PX",
        "role": "SWITCH",
        "siteName": "Nexus Inventory",
        "reachabilityStatus": "Reachable",
        "source": "Nexus",
        "softwareVersion": "9.3(10)",
        "lastUpdateTime": _now_ms
    }
    for i in range(10)
]

MOCK_NEXUS_INTERFACES = []
for dev in MOCK_NEXUS_DEVICES:
    MOCK_NEXUS_INTERFACES.append({
        "hostname": dev["hostname"],
        "device_ip": dev["managementIpAddress"],
        "platform": "nxos",
        "interface_name": "Ethernet1/1",
        "ipv4_address": f"10.60.{MOCK_NEXUS_DEVICES.index(dev)+1}.1/24",
        "vlans": [10, 20],
        "zone": "trust",
        "mac_address": f"00:50:56:00:00:{MOCK_NEXUS_DEVICES.index(dev)+1:02x}",
        "error": None
    })

MOCK_USERS = [
    {"id": _uid("user-admin"), "name": "admin", "description": "Network Administrator", "enabled": True, "passwordPolicy": "Strong"},
    {"id": _uid("user-ops"),   "name": "ops-user", "description": "NOC Operations", "enabled": True, "passwordPolicy": "Standard"},
    {"id": _uid("user-audit"), "name": "audit-svc", "description": "Audit Service Account", "enabled": False, "passwordPolicy": "None"},
]

MOCK_ISSUES = [
    {
        "priority": "P1",
        "name": "Network Device Unreachable",
        "deviceName": "SW-DCA-HQ-01",
        "siteHierarchy": "TSA-DCA-HQ",
        "lastOccurrenceTime": 1712657700000,
    },
    {
        "severity": "P2",
        "issueTitle": "Interface GigabitEthernet1/0/1 flapping",
        "deviceName": "SW-LAX-T1-03",
        "siteName": "TSA-LAX-T1",
        "timestamp": 1712662200000,
    },
    {
        "priority": "P1",
        "title": "BGP Neighbor Adjacency Down",
        "source": "CORE-ORD-T1-01",
        "siteHierarchy": "Global/TSA/ORD/T1",
        "occurredOn": "2026-04-09T09:45:00Z",
    },
    {
        "priority": "P3",
        "name": "Power Supply Failure (Redundant)",
        "host": "SW-BOS-T1-02",
        "site_name": "TSA-BOS-T1",
        "startTime": 1712664000000,
    }
]

# Add many more to test scrolling
for i in range(20):
    MOCK_ISSUES.append({
        "priority": "P2",
        "name": f"OSPF Adjacency Change {i}",
        "deviceName": f"SW-DCA-HQ-{i:02d}",
        "siteHierarchy": "TSA-DCA-HQ",
        "timestamp": 1712664000000 + (i * 60000),
    })


# ── Mock ISE data ─────────────────────────────────────────────────────────────

MOCK_NADS: list[dict] = [
    {
        "id":          _uid(f"nad-{i}"),
        "name":        dev["hostname"],
        "description": f"{dev['role']} switch",
        "ipaddress":   dev["managementIpAddress"],
        "profileName": "Cisco",
        "modelName":   dev["platformId"],
    }
    for i, dev in enumerate(MOCK_DEVICES[:10])
]

MOCK_ENDPOINT_GROUPS: list[dict] = [
    {"id": _uid("epg-workstation"), "name": "Workstation",    "description": "Corporate workstations"},
    {"id": _uid("epg-printer"),     "name": "Printer",        "description": "Network printers"},
    {"id": _uid("epg-ip-phone"),    "name": "IP_Phone",       "description": "Cisco IP phones"},
    {"id": _uid("epg-camera"),      "name": "IP_Camera",      "description": "Security cameras"},
    {"id": _uid("epg-iot"),         "name": "IoT_Device",     "description": "IoT sensors and devices"},
    {"id": _uid("epg-byod"),        "name": "BYOD",           "description": "Personal devices"},
]

MOCK_IDENTITY_GROUPS: list[dict] = [
    {"id": _uid("idg-user"),     "name": "User",        "parent": "Endpoint Identity Groups"},
    {"id": _uid("idg-guest"),    "name": "GuestEndpoints", "parent": "Endpoint Identity Groups"},
    {"id": _uid("idg-profiled"), "name": "Profiled",    "parent": "Endpoint Identity Groups"},
]

MOCK_SGTS: list[dict] = [
    {"id": _uid("sgt-unknown"),   "name": "Unknown",       "value": 0,   "description": "Unknown"},
    {"id": _uid("sgt-employees"), "name": "Employees",     "value": 4,   "description": "Corporate employees"},
    {"id": _uid("sgt-contractors"),"name": "Contractors",  "value": 5,   "description": "Contractors"},
    {"id": _uid("sgt-guests"),    "name": "Guests",        "value": 6,   "description": "Guest users"},
    {"id": _uid("sgt-printers"),  "name": "Printers",      "value": 100, "description": "Network printers"},
    {"id": _uid("sgt-cameras"),   "name": "IP_Cameras",    "value": 110, "description": "Security cameras"},
]

MOCK_POLICY_SETS: list[dict] = [
    {"id": _uid("ps-wired"),    "name": "Wired_MAB",   "description": "MAC Auth for wired devices", "isProxy": False},
    {"id": _uid("ps-wireless"), "name": "Wireless_Dot1x", "description": "802.1X for wireless",    "isProxy": False},
    {"id": _uid("ps-vpn"),      "name": "VPN_Access",  "description": "VPN user authentication",   "isProxy": False},
]

MOCK_DEPLOYMENT_NODES: list[dict] = [
    {"id": _uid("node-pan"),     "hostname": "ise-pan-01", "ipAddress": "192.168.1.10", "fqdn": "ise-pan-01.tsa.local", "nodeType": "PAN"},
    {"id": _uid("node-psn-1"),   "hostname": "ise-psn-01", "ipAddress": "192.168.1.11", "fqdn": "ise-psn-01.tsa.local", "nodeType": "PSN"},
    {"id": _uid("node-psn-2"),   "hostname": "ise-psn-02", "ipAddress": "192.168.1.12", "fqdn": "ise-psn-02.tsa.local", "nodeType": "PSN"},
]

MOCK_NAD_GROUPS: list[dict] = [
    {"id": _uid("ndg-access"),   "name": "NetworkDeviceGroup#All Device Types#Access",   "description": ""},
    {"id": _uid("ndg-core"),     "name": "NetworkDeviceGroup#All Device Types#Core",     "description": ""},
    {"id": _uid("ndg-dc"),       "name": "NetworkDeviceGroup#All Locations#Data Center", "description": ""},
]

MOCK_AUTH_RULES: list[dict] = [
    {
        "id": _uid("rule-mab"),
        "name": "MAB",
        "state": "enabled",
        "profiles": ["Cisco_Web_Auth"],
        "securityGroup": None,
    },
    {
        "id": _uid("rule-dot1x"),
        "name": "Dot1X",
        "state": "enabled",
        "profiles": ["PermitAccess"],
        "securityGroup": "Employees",
    },
    {
        "id": _uid("rule-default"),
        "name": "Default",
        "state": "enabled",
        "profiles": ["DenyAccess"],
        "securityGroup": None,
    },
]


# ── Mock Panorama / Firewall data ─────────────────────────────────────────────

_ZONES   = ["trust", "untrust", "dmz", "mgmt"]
_APPS    = ["any", "web-browsing", "ssl", "dns", "ping", "ssh", "smtp"]
_ACTIONS = ["allow", "allow", "allow", "deny"]

MOCK_FIREWALL_RULES: list[dict] = [
    {
        "name":       f"Rule-{i+1:03d}",
        "uuid":       _uid(f"pan-rule-{i}"),
        "device_group": "DG-TSA-East" if i < 8 else "DG-TSA-West",
        "rulebase":   "pre",
        "action":     _ACTIONS[i % 4],
        "disabled":   (i % 9 == 0),
        "from":       [_ZONES[i % 2]],
        "to":         [_ZONES[(i + 1) % 2]],
        "source":     ["any"] if i % 3 == 0 else [f"10.{i}.0.0/24"],
        "destination":["any"] if i % 2 == 0 else [f"172.16.{i}.0/24"],
        "application":[_APPS[i % len(_APPS)]],
        "service":    ["application-default"],
        "profile_setting": {"group": ["strict"] if i % 4 != 3 else []},
        "description": f"Auto-generated mock rule {i+1}",
        "tag": [],
    }
    for i in range(20)
]

MOCK_PAN_RULES_CACHE = {
    "dg_order": ["DG-TSA-East", "DG-TSA-West"],
    "by_dg": {
        "DG-TSA-East": [r for r in MOCK_FIREWALL_RULES if r["device_group"] == "DG-TSA-East"],
        "DG-TSA-West": [r for r in MOCK_FIREWALL_RULES if r["device_group"] == "DG-TSA-West"],
        "shared": [],
    },
}

MOCK_DEVICE_GROUPS: list[str] = ["DG-TSA-East", "DG-TSA-West"]

MOCK_ADDRESS_OBJECTS: list[dict] = [
    {"name": "NET-HQ",         "type": "ip-netmask", "value": "10.10.0.0/16", "device_group": "shared"},
    {"name": "NET-BOSTON",     "type": "ip-netmask", "value": "10.20.0.0/16", "device_group": "shared"},
    {"name": "NET-LA",         "type": "ip-netmask", "value": "10.30.0.0/16", "device_group": "shared"},
    {"name": "SERVER-WEB-01",  "type": "ip-netmask", "value": "172.16.1.10/32", "device_group": "shared"},
    {"name": "SERVER-DB-01",   "type": "ip-netmask", "value": "172.16.2.10/32", "device_group": "shared"},
]

MOCK_SERVICES: list[dict] = [
    {"name": "SVC-HTTP",   "protocol": "tcp", "port": "80",   "device_group": "shared"},
    {"name": "SVC-HTTPS",  "protocol": "tcp", "port": "443",  "device_group": "shared"},
    {"name": "SVC-SSH",    "protocol": "tcp", "port": "22",   "device_group": "shared"},
    {"name": "SVC-RDP",    "protocol": "tcp", "port": "3389", "device_group": "shared"},
    {"name": "SVC-DNS",    "protocol": "udp", "port": "53",   "device_group": "shared"},
]

# ── Mock ACI data ─────────────────────────────────────────────────────────────

MOCK_ACI_NODES = [
    {"fabricNode": {"attributes": {"id": "149", "name": "LEAF-149", "model": "N9K-C9348GC-FXP", "role": "leaf", "fabricSt": "active", "dn": "topology/pod-1/node-149"}}},
    {"fabricNode": {"attributes": {"id": "150", "name": "LEAF-150", "model": "N9K-C9348GC-FXP", "role": "leaf", "fabricSt": "active", "dn": "topology/pod-2/node-150"}}},
]

MOCK_ACI_L3OUTS = [
    {"l3extOut": {"attributes": {"name": "L3OUT-CORE", "dn": "uni/tn-COMMON/out-L3OUT-CORE", "descr": "Connection to Enterprise Core"}}},
    {"l3extOut": {"attributes": {"name": "L3OUT-FIREWALL", "dn": "uni/tn-PROD/out-L3OUT-FIREWALL", "descr": "Connection to DMZ Firewalls"}}},
    {"l3extOut": {"attributes": {"name": "HQL3Out", "dn": "uni/tn-TSA-HQ/out-HQL3Out", "descr": "Broken L3Out for testing"}}},
]

MOCK_ACI_BGP_PEERS = [
    {"bgpPeerEntry": {"attributes": {"addr": "10.255.0.1", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]"}}},
    {"bgpPeerEntry": {"attributes": {"addr": "10.255.0.2", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[10.255.0.2]/ent-[10.255.0.2]"}}},
    {"bgpPeerEntry": {"attributes": {"addr": "10.238.94.139", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[10.238.94.139/32]/ent-[10.238.94.139]"}}},
]

MOCK_ACI_BGP_PEER_CFG = [
    {"bgpPeerP": {"attributes": {"addr": "10.255.0.1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.1]", "descr": "Core Router 1"}}},
    {"bgpPeerP": {"attributes": {"addr": "10.255.0.2", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.2]", "descr": "Core Router 2"}}},
    {"bgpPeerP": {"attributes": {"addr": "10.238.94.139", "dn": "uni/tn-TSA-HQ/out-HQL3Out/lnodep-HQ-BorderLeafs/rspeerToProfile/bgpPeerP-[10.238.94.139]", "descr": "HQ Firewall"}}},
]

MOCK_ACI_SUBNETS = [
    {"l3extSubnet": {"attributes": {"ip": "10.0.0.0/8", "scope": "export-rtctrl", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-CORE/lifp-CORE/subnet-[10.0.0.0/8]"}}},
    {"l3extSubnet": {"attributes": {"ip": "172.16.0.0/12", "scope": "export-rtctrl", "dn": "uni/tn-PROD/out-L3OUT-FIREWALL/lnodep-FW/lifp-FW/subnet-[172.16.0.0/12]"}}},
    {"fvSubnet": {"attributes": {"ip": "10.10.10.1/24", "dn": "uni/tn-TSA-HQ/BD-Users/subnet-[10.10.10.1/24]", "descr": "User Access"}}},
    {"fvSubnet": {"attributes": {"ip": "fc00:10::1/64", "dn": "uni/tn-TSA-HQ/BD-Users/subnet-[fc00:10::1/64]", "descr": "User Access IPv6"}}},
    # Add a conflict: This exactly matches a DNAC pool in TSA-BOS-T1 (10.20.0.0/16) but has different site
    {"fvSubnet": {"attributes": {"ip": "10.20.0.0/16", "dn": "uni/tn-CONFLICT-TENANT/BD-Conflict/subnet-[10.20.0.0/16]", "descr": "Conflict Subnet"}}},
]

MOCK_ACI_EPGS = [
    {"fvAEPg": {"attributes": {"name": "EPG-WEB", "dn": "uni/tn-PROD/ap-APP-01/epg-EPG-WEB"}, "children": [{"healthInst": {"attributes": {"cur": "98"}}}]}},
    {"fvAEPg": {"attributes": {"name": "EPG-DB", "dn": "uni/tn-PROD/ap-APP-01/epg-EPG-DB"}, "children": [{"healthInst": {"attributes": {"cur": "45"}}}]}},
]

MOCK_ACI_BGP_DOMS = [
    {"bgpRoute": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-default/af-ipv4-ucast/rt-[10.1.1.0/24]", "prefix": "10.1.1.0/24", "nextHop": "192.168.1.1", "origin": "igp", "asPath": "65001"}}},
    {"bgpRoute": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-default/af-ipv4-ucast/rt-[172.16.10.0/24]", "prefix": "172.16.10.0/24", "nextHop": "192.168.1.2", "origin": "ebgp", "asPath": "65002 65100"}}},
    {"bgpBdpRoute": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-PRODUCTION:PROD_VRF/af-ipv4-ucast/rt-[10.200.10.0/24]", "pfx": "10.200.10.0/24", "nh": "10.200.10.1", "origin": "igp", "asPath": ""}}},
    {"bgpEvpnRoute": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-overlay-1/af-evpn/rt-[[2]:[0]:[0]:[48]:[00:50:56:00:00:01]:[32]:[10.1.1.1]]", "prefix": "10.1.1.1/32", "nextHop": "192.168.255.10", "origin": "igp", "asPath": ""}}}
]

MOCK_ACI_BGP_RIB_IN = [
    {"bgpAdjRibIn": {"attributes": {"prefix": "10.100.1.0/24", "nextHop": "10.255.0.1", "asPath": "65123", "origin": "igp", "flags": "valid,best", "localPref": "100", "med": "0", "community": "65123:100"}}},
    {"bgpAdjRibIn": {"attributes": {"prefix": "10.100.2.0/24", "nextHop": "10.255.0.1", "asPath": "65123", "origin": "igp", "flags": "valid,best", "localPref": "100", "med": "0", "community": ""}}},
]

MOCK_ACI_BGP_RIB_OUT = [
    {"bgpAdjRibOut": {"attributes": {"prefix": "10.10.0.0/16", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp", "flags": "advertised", "localPref": "100", "med": "0", "community": ""}}},
    {"bgpAdjRibOut": {"attributes": {"prefix": "172.16.0.0/12", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp", "flags": "advertised", "localPref": "100", "med": "0", "community": ""}}},
]

MOCK_ACI_BGP_ADJ_RIB_OUT = [
    {"bgpAdjRibOut": {"attributes": {
        "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]/adj-rib-out-post/rt-[10.10.0.0/16]",
        "prefix": "10.10.0.0/16", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp",
        "flags": "advertised", "localPref": "100", "med": "0", "community": ""
    }}},
    {"bgpAdjRibOut": {"attributes": {
        "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]/adj-rib-out-post/rt-[172.16.0.0/12]",
        "prefix": "172.16.0.0/12", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp",
        "flags": "advertised", "localPref": "100", "med": "0", "community": ""
    }}},
    {"bgpAdjRibOut": {"attributes": {
        "dn": "topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[10.255.0.2]/ent-[10.255.0.2]/adj-rib-out-post/rt-[10.10.0.0/16]",
        "prefix": "10.10.0.0/16", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp",
        "flags": "advertised", "localPref": "100", "med": "0", "community": ""
    }}},
    {"bgpAdjRibOut": {"attributes": {
        "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[10.238.94.139/32]/ent-[10.238.94.139]/adj-rib-out-post/rt-[192.168.10.0/24]",
        "prefix": "192.168.10.0/24", "nextHop": "0.0.0.0", "asPath": "", "origin": "igp",
        "flags": "advertised", "localPref": "100", "med": "0", "community": ""
    }}},
]

MOCK_ACI_BGP_ADJ_RIB_IN = [
    {"bgpAdjRibIn": {"attributes": {
        "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]/adj-rib-in-post/rt-[10.100.1.0/24]",
        "prefix": "10.100.1.0/24", "nextHop": "10.255.0.1", "asPath": "65123", "origin": "igp",
        "flags": "valid,best", "localPref": "100", "med": "0", "community": "65123:100"
    }}},
    {"bgpAdjRibIn": {"attributes": {
        "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]/adj-rib-in-post/rt-[10.100.2.0/24]",
        "prefix": "10.100.2.0/24", "nextHop": "10.255.0.1", "asPath": "65123", "origin": "igp",
        "flags": "valid,best", "localPref": "100", "med": "0", "community": ""
    }}},
    {"bgpAdjRibIn": {"attributes": {
        "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[10.238.94.139/32]/ent-[10.238.94.139]/adj-rib-in-post/rt-[8.8.8.0/24]",
        "prefix": "8.8.8.0/24", "nextHop": "10.238.94.139", "asPath": "65200 65300", "origin": "egp",
        "flags": "valid,best", "localPref": "100", "med": "0", "community": ""
    }}},
    {"bgpAdjRibIn": {"attributes": {
        "dn": "topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[10.255.0.2]/ent-[10.255.0.2]/adj-rib-in-post/rt-[10.100.1.0/24]",
        "prefix": "10.100.1.0/24", "nextHop": "10.255.0.2", "asPath": "65123", "origin": "igp",
        "flags": "valid", "localPref": "100", "med": "0", "community": "65123:100"
    }}},
]

MOCK_ACI_BGP_DOMS_ALL = [
    {"bgpDomAf": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-default/af-ipv4-ucast", "count": "2"}}},
    {"bgpDomAf": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-PRODUCTION:PROD_VRF/af-ipv4-ucast", "count": "1"}}},
    {"bgpDomAf": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-overlay-1/af-evpn", "count": "1"}}},
    {"bgpDomAf": {"attributes": {"dn": "topology/pod-2/node-150/sys/bgp/inst/dom-default/af-ipv4-ucast", "count": "100"}}}
]

MOCK_ACI_FAULT_INST = [
    {"faultInst": {"attributes": {"code": "F1234", "severity": "major", "descr": "BGP Peer Down", "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/fault-F1234", "created": "2024-05-20T10:00:00Z"}}},
    {"faultInst": {"attributes": {"code": "F0546", "severity": "critical", "descr": "Fabric Node Unreachable", "dn": "topology/pod-1/node-102/fault-F0546", "created": "2024-05-20T11:00:00Z"}}},
]

MOCK_ACI_HEALTH_OVERALL = [
    {"fabricHealthTotal": {"attributes": {"dn": "topology/health"}, "children": [{"healthInst": {"attributes": {"cur": "95"}}}]}}
]

MOCK_ACI_HEALTH_TENANTS = [
    {"fvTenant": {"attributes": {"name": "COMMON"}, "children": [{"healthInst": {"attributes": {"cur": "100"}}}]}},
    {"fvTenant": {"attributes": {"name": "PROD"}, "children": [{"healthInst": {"attributes": {"cur": "85"}}}]}},
]

MOCK_ACI_HEALTH_PODS = [
    {"fabricPod": {"attributes": {"id": "1"}, "children": [{"healthInst": {"attributes": {"cur": "92"}}}]}}
]

MOCK_IPAM_TREE = {
    "ipv4": [
        {
            "cidr": "10.0.0.0/8",
            "display_name": "Internal Network",
            "type": "Supernet",
            "site": "Global",
            "device": "N/A",
            "source": "Aggregated",
            "conflicts": [],
            "overlaps": [],
            "children": [
                {
                    "cidr": "10.10.0.0/16",
                    "display_name": "DCA Data Center",
                    "type": "Group",
                    "site": "TSA-DCA-HQ",
                    "device": "N/A",
                    "source": "DNAC",
                    "conflicts": [],
                    "overlaps": [],
                    "children": [
                        {
                            "cidr": "10.10.1.0/24",
                            "display_name": "User Access",
                            "type": "Subnet",
                            "site": "TSA-DCA-HQ",
                            "device": "SW-DCA-HQ-01",
                            "source": "DNAC",
                            "conflicts": [],
                            "overlaps": [],
                            "children": []
                        }
                    ]
                }
            ]
        }
    ],
    "ipv6": [
        {
            "cidr": "fc00::/7",
            "display_name": "Unique Local Address",
            "type": "Supernet",
            "site": "Global",
            "device": "N/A",
            "source": "Aggregated",
            "conflicts": [],
            "overlaps": [],
            "children": []
        }
    ]
}

# ── Cache seeding ─────────────────────────────────────────────────────────────

def seed_cache(cache) -> None:
    """Pre-populate the in-memory cache with mock data for all UI-facing endpoints."""
    from cache import TTL_DEVICES, TTL_SITES
    LONG = 86400 * 365  # 1 year — mock data never expires

    # DNAC
    cache.set("devices",         MOCK_DEVICES,          TTL_DEVICES)
    cache.set("sites",           MOCK_SITES,            TTL_SITES)
    cache.set("device_site_map", MOCK_DEVICE_SITE_MAP,  TTL_SITES)

    # DNAC status
    cache.set("status_dnac",     {"ok": True, "detail": f"{len(MOCK_DEVICES):,} devices (mock)"}, LONG)

    # ISE lists
    cache.set("ise_nads",            MOCK_NADS,             LONG)
    cache.set("ise_users",           MOCK_USERS,            LONG)
    cache.set("ise_nad_groups",      MOCK_NAD_GROUPS,       LONG)
    cache.set("ise_endpoint_groups", MOCK_ENDPOINT_GROUPS,  LONG)
    cache.set("ise_identity_groups", MOCK_IDENTITY_GROUPS,  LONG)
    cache.set("ise_sgts",            MOCK_SGTS,             LONG)
    cache.set("ise_sgacls",          [],                    LONG)
    cache.set("ise_egress_matrix",   [],                    LONG)
    cache.set("ise_policy_sets",     MOCK_POLICY_SETS,      LONG)
    cache.set("ise_authz_profiles",  [],                    LONG)
    cache.set("ise_allowed_protocols", [],                  LONG)
    cache.set("ise_profiling_policies", [],                 LONG)
    cache.set("ise_deployment_nodes", MOCK_DEPLOYMENT_NODES, LONG)

    # ISE auth rules for each mock policy set
    for ps in MOCK_POLICY_SETS:
        cache.set(f"ise_auth_rules_{ps['id']}", MOCK_AUTH_RULES, LONG)

    # ISE status
    cache.set("status_ise", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # Panorama / Firewall
    cache.set("pan_rules",           MOCK_PAN_RULES_CACHE,  LONG)
    cache.set("pan_device_groups",   MOCK_DEVICE_GROUPS,    LONG)
    cache.set("pan_address_objects", MOCK_ADDRESS_OBJECTS,  LONG)
    cache.set("pan_services",        MOCK_SERVICES,         LONG)

    # Panorama status
    cache.set("status_panorama", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # ACI
    cache.set("aci_nodes",          {"imdata": MOCK_ACI_NODES},         LONG)
    cache.set("aci_l3outs",         {"imdata": MOCK_ACI_L3OUTS},        LONG)
    cache.set("aci_bgp_peers",      {"imdata": MOCK_ACI_BGP_PEERS},     LONG)
    cache.set("aci_bgp_peer_cfg",   {"imdata": MOCK_ACI_BGP_PEER_CFG},  LONG)
    cache.set("aci_subnets",        {"imdata": MOCK_ACI_SUBNETS},       LONG)
    cache.set("aci_epgs",           {"imdata": MOCK_ACI_EPGS},          LONG)
    cache.set("aci_faults",         {"imdata": MOCK_ACI_FAULT_INST},    LONG)
    cache.set("aci_bgp_doms_all",   {"imdata": MOCK_ACI_BGP_DOMS_ALL},  LONG)
    cache.set("aci_bgp_adj_rib_out",{"imdata": MOCK_ACI_BGP_ADJ_RIB_OUT}, LONG)
    cache.set("aci_bgp_adj_rib_in", {"imdata": MOCK_ACI_BGP_ADJ_RIB_IN},  LONG)

    # ACI status
    cache.set("aci_health_overall", {"imdata": MOCK_ACI_HEALTH_OVERALL}, LONG)
    cache.set("aci_health_tenants", {"imdata": MOCK_ACI_HEALTH_TENANTS}, LONG)
    cache.set("aci_health_pods",    {"imdata": MOCK_ACI_HEALTH_PODS},    LONG)
    cache.set("status_aci", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # IPAM
    cache.set("ipam_tree", MOCK_IPAM_TREE, LONG)

    # Nexus
    cache.set("nexus_inventory", MOCK_NEXUS_DEVICES, LONG)
    cache.set("nexus_interfaces", MOCK_NEXUS_INTERFACES, LONG)

    for dev in MOCK_NEXUS_DEVICES:
        cache.set(f"config:nexus:{dev['hostname']}", MOCK_CONFIGS[dev['id']], LONG)


def create_dev_session() -> None:
    """Create the fixed dev session so the frontend can auto-login."""
    import auth as auth_module
    import time

    entry = auth_module.SessionEntry(
        username   = DEV_USER,
        password   = "dev",
        expires_at = time.monotonic() + 86400 * 365,  # never expires
    )
    with auth_module._store_lock:
        auth_module._sessions[DEV_TOKEN] = entry

MOCK_CONFIGS = {
    **{
        dev["id"]: f"""!
hostname {dev['hostname']}
!
interface Ethernet1/1
 description Primary Uplink
 ip address {dev['managementIpAddress']} 255.255.255.0
 speed 1000
 duplex full
!
snmp-server community TSA-RO RO
snmp-server community TSA-RW RW
!
end
"""
        for dev in MOCK_NEXUS_DEVICES
    },
    **{
        dev["id"]: f"""!
hostname {dev['hostname']}
!
interface GigabitEthernet0/1
 description Primary Uplink
 ip address {dev['managementIpAddress']} 255.255.255.0
 speed 1000
 duplex full
!
snmp-server community TSA-RO RO
snmp-server community TSA-RW RW
!
router eigrp 1
 network {dev['managementIpAddress'].rsplit('.', 1)[0]}.0 0.0.0.255
!
end
"""
        for dev in MOCK_DEVICES
    }
}

def get_mock_config(device_id):
    return MOCK_CONFIGS.get(device_id, "! No config found")
