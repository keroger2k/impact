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

# ── Mock DNAC interfaces ──────────────────────────────────────────────────────
# Shape matches what clients.dnac.get_all_interfaces() returns. DNAC is the
# primary source for loopbacks/tunnels/SVIs on Catalyst devices, so the mocks
# here are what exercise that path in IPAM.
MOCK_DNAC_INTERFACES: list[dict] = []

# Pick the first CORE device per site — those get a rich interface set.
_CORE_PRIMARY: dict = {}
for _d in MOCK_DEVICES:
    if _d.get("role") == "CORE":
        _site = MOCK_DEVICE_SITE_MAP.get(_d["id"])
        if _site and _site not in _CORE_PRIMARY:
            _CORE_PRIMARY[_site] = _d

_SITE_OCTET = {"TSA-DCA-HQ": 10, "TSA-BOS-T1": 20, "TSA-LAX-T1": 30, "TSA-ORD-T1": 40, "TSA-JFK-T1": 50}

def _dnac_iface(dev_id, host, port, addr, mask, vlan=None, desc=""):
    MOCK_DNAC_INTERFACES.append({
        "deviceId": dev_id, "deviceName": host,
        "portName": port, "ipv4Address": addr, "ipv4Mask": mask,
        "macAddress": "00:00:00:00:00:00", "vlanId": vlan,
        "description": desc, "adminStatus": "UP", "status": "up", "speed": "1000000",
    })

for _i, (_site, _d) in enumerate(_CORE_PRIMARY.items()):
    _n = _i + 1  # 1..5
    _id = _d["id"]
    _host = _d["hostname"]
    _octet = _SITE_OCTET.get(_site, 99)

    # Management
    _dnac_iface(_id, _host, "mgmt0", _d["managementIpAddress"], "255.255.255.0", desc="Management")
    # Transit uplink — per-site /24
    _dnac_iface(_id, _host, "GigabitEthernet1/0/1", f"10.{_octet}.100.1", "255.255.255.0", desc="Uplink")
    # Loopback0 — unique /32 per CORE device (5 hosts collapse into a host-route group)
    _dnac_iface(_id, _host, "Loopback0", f"10.99.100.{_n}", "255.255.255.255", desc="Router ID")
    # Per-site SVI
    _dnac_iface(_id, _host, "Vlan10", f"10.{_octet}.10.1", "255.255.255.0", vlan="10", desc="Users VLAN")
    # Tunnel10 — DMVPN-style hub/spoke: all CORE devices share 10.99.3.0/24 so
    # IPAM should render a single tunnel_group with 5 endpoints.
    _dnac_iface(_id, _host, "Tunnel10", f"10.99.3.{_n}", "255.255.255.0", desc=f"DMVPN endpoint {_n}")

# Point-to-point transit: Tunnel20 pairs CORE-DCA (idx 1) and CORE-BOS (idx 2) on a /30
_pair = list(_CORE_PRIMARY.values())[:2]
if len(_pair) == 2:
    _dnac_iface(_pair[0]["id"], _pair[0]["hostname"], "Tunnel20", "10.99.4.1", "255.255.255.252", desc="P2P to BOS")
    _dnac_iface(_pair[1]["id"], _pair[1]["hostname"], "Tunnel20", "10.99.4.2", "255.255.255.252", desc="P2P to DCA")

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
for _idx, _dev in enumerate(MOCK_NEXUS_DEVICES):
    _hostname = _dev["hostname"]
    _device_ip = _dev["managementIpAddress"]
    _n = _idx + 1  # 1..10
    _mac = f"00:50:56:00:00:{_n:02x}"

    # Physical uplink — per-device /24 in site transit space
    MOCK_NEXUS_INTERFACES.append({
        "hostname": _hostname, "device_ip": _device_ip, "platform": "nxos",
        "interface_name": "Ethernet1/1",
        "ipv4_address": f"10.60.{_n}.1/24",
        "vlans": [10, 20], "zone": "trust", "mac_address": _mac, "error": None,
    })

    # Loopback0 — unique /32 per device. With 10 devices this exercises the
    # "collapse 3+ loopbacks" behavior in the IPAM tree.
    MOCK_NEXUS_INTERFACES.append({
        "hostname": _hostname, "device_ip": _device_ip, "platform": "nxos",
        "interface_name": "loopback0",
        "ipv4_address": f"10.99.10.{_n}/32",
        "vlans": [], "zone": "", "mac_address": _mac, "error": None,
    })

    # SVIs on first 4 devices — per-device Vlan in the 10.70.x.0/24 space
    if _n <= 4:
        MOCK_NEXUS_INTERFACES.append({
            "hostname": _hostname, "device_ip": _device_ip, "platform": "nxos",
            "interface_name": f"Vlan{200 + _n}",
            "ipv4_address": f"10.70.{_n}.1/24",
            "vlans": [200 + _n], "zone": "trust", "mac_address": _mac, "error": None,
        })

    # Tunnel100 — DMVPN-style hub/spoke: devices 1..4 all share 10.99.0.0/24
    # so they get collapsed into one tunnel_group with 4 endpoints.
    if _n <= 4:
        MOCK_NEXUS_INTERFACES.append({
            "hostname": _hostname, "device_ip": _device_ip, "platform": "nxos",
            "interface_name": "Tunnel100",
            "ipv4_address": f"10.99.0.{_n}/24",
            "vlans": [], "zone": "vpn", "mac_address": _mac, "error": None,
        })

    # Tunnel200 — point-to-point /30 between devices 5 and 6 (2-endpoint group)
    if _n in (5, 6):
        MOCK_NEXUS_INTERFACES.append({
            "hostname": _hostname, "device_ip": _device_ip, "platform": "nxos",
            "interface_name": "Tunnel200",
            "ipv4_address": f"10.99.1.{_n - 4}/30",
            "vlans": [], "zone": "vpn", "mac_address": _mac, "error": None,
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

# Paired firewall interface inventory (matches the shape produced by
# clients.panorama.fetch_firewall_interfaces). tunnel.10 is configured on both
# firewalls in the same /24, so IPAM should render a 2-endpoint tunnel_group.
MOCK_PAN_INTERFACES: list[dict] = [
    {
        "serial":        "014101000001",
        "hostname":      "FW-DCA-01",
        "model":         "PA-3220",
        "management_ip": "10.10.250.1",
        "device_group":  "DG-TSA-East",
        "os_version":    "10.1.5",
        "ha_state":      "active",
        "ha_enabled":    True,
        "interfaces": [
            {"name": "management",  "ipv4": "10.10.250.1/24", "ipv6": [], "zone": "mgmt"},
            {"name": "ethernet1/1", "ipv4": "10.80.1.1/24",   "ipv6": [], "zone": "trust"},
            {"name": "ethernet1/2", "ipv4": "10.80.2.1/30",   "ipv6": [], "zone": "untrust"},
            {"name": "loopback.1",  "ipv4": "10.99.20.1/32",  "ipv6": [], "zone": "loopback"},
            {"name": "tunnel.10",   "ipv4": "10.99.5.1/24",   "ipv6": [], "zone": "vpn"},
        ],
    },
    {
        "serial":        "014101000002",
        "hostname":      "FW-BOS-01",
        "model":         "PA-3220",
        "management_ip": "10.20.250.1",
        "device_group":  "DG-TSA-West",
        "os_version":    "10.1.5",
        "ha_state":      "active",
        "ha_enabled":    True,
        "interfaces": [
            {"name": "management",  "ipv4": "10.20.250.1/24", "ipv6": [], "zone": "mgmt"},
            {"name": "ethernet1/1", "ipv4": "10.80.3.1/24",   "ipv6": [], "zone": "trust"},
            {"name": "loopback.1",  "ipv4": "10.99.20.2/32",  "ipv6": [], "zone": "loopback"},
            # Pairs with FW-DCA-01 tunnel.10 → should group in IPAM
            {"name": "tunnel.10",   "ipv4": "10.99.5.2/24",   "ipv6": [], "zone": "vpn"},
        ],
    },
]

# ── Mock ACI data ─────────────────────────────────────────────────────────────

MOCK_ACI_NODES = [
    {"fabricNode": {"attributes": {"id": "149", "name": "LEAF-149", "model": "N9K-C9348GC-FXP", "role": "leaf", "fabricSt": "active", "dn": "topology/pod-1/node-149"}}},
    {"fabricNode": {"attributes": {"id": "150", "name": "LEAF-150", "model": "N9K-C9348GC-FXP", "role": "leaf", "fabricSt": "active", "dn": "topology/pod-2/node-150"}}},
    {"fabricNode": {"attributes": {"id": "208", "name": "sdczwm208", "model": "N9K-C93180YC-FX", "role": "leaf", "fabricSt": "active", "dn": "topology/pod-1/node-208"}}},
]

MOCK_ACI_L3OUTS = [
    {"l3extOut": {"attributes": {"name": "L3OUT-CORE", "dn": "uni/tn-COMMON/out-L3OUT-CORE", "descr": "Connection to Enterprise Core"}}},
    {"l3extOut": {"attributes": {"name": "L3OUT-FIREWALL", "dn": "uni/tn-PROD/out-L3OUT-FIREWALL", "descr": "Connection to DMZ Firewalls"}}},
    {"l3extOut": {"attributes": {"name": "HQL3Out", "dn": "uni/tn-TSA-HQ/out-HQL3Out", "descr": "Broken L3Out for testing"}}},
]

MOCK_ACI_BGP_PEERS = [
    {"bgpPeerEntry": {"attributes": {"addr": "10.255.0.1", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1]/ent-[10.255.0.1]"}}},
    {"bgpPeerEntry": {"attributes": {"addr": "10.255.0.2", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-102/sys/bgp/inst/dom-default/peer-[10.255.0.2]/ent-[10.255.0.2]"}}},
    {"bgpPeerEntry": {"attributes": {"addr": "192.0.2.139", "operSt": "established", "type": "ebgp", "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[192.0.2.139/32]/ent-[192.0.2.139]"}}},
]

MOCK_ACI_BGP_PEER_CFG = [
    {"bgpPeerP": {"attributes": {"addr": "10.255.0.1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.1]", "descr": "Core Router 1"}}},
    {"bgpPeerP": {"attributes": {"addr": "10.255.0.2", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.2]", "descr": "Core Router 2"}}},
    {"bgpPeerP": {"attributes": {"addr": "192.0.2.139", "dn": "uni/tn-TSA-HQ/out-HQL3Out/lnodep-HQ-BorderLeafs/rspeerToProfile/bgpPeerP-[192.0.2.139]", "descr": "HQ Firewall"}}},
]

MOCK_ACI_SUBNETS = [
    {"l3extSubnet": {"attributes": {"ip": "10.0.0.0/8", "scope": "export-rtctrl", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-CORE/lifp-CORE/subnet-[10.0.0.0/8]"}}},
    {"l3extSubnet": {"attributes": {"ip": "172.16.0.0/12", "scope": "export-rtctrl", "dn": "uni/tn-PROD/out-L3OUT-FIREWALL/lnodep-FW/lifp-FW/subnet-[172.16.0.0/12]"}}},
    {"fvSubnet": {"attributes": {"ip": "192.0.2.1/24", "dn": "uni/tn-TSA-HQ/BD-Users/subnet-[192.0.2.1/24]", "descr": "User Access"}}},
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
    {"bgpRoute": {"attributes": {"dn": "topology/pod-1/node-149/sys/bgp/inst/dom-default/af-ipv4-ucast/rt-[172.16.10.0/24]", "prefix": "172.16.10.0/24", "nextHop": "192.168.1.2", "origin": "ebgp", "asPath": "65002 65100"}}}
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
        "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[192.0.2.139/32]/ent-[192.0.2.139]/adj-rib-out-post/rt-[192.168.10.0/24]",
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
        "dn": "topology/pod-1/node-134/sys/bgp/inst/dom-TSA-HQ:TSA-HQ-VRF/peer-[192.0.2.139/32]/ent-[192.0.2.139]/adj-rib-in-post/rt-[8.8.8.0/24]",
        "prefix": "8.8.8.0/24", "nextHop": "192.0.2.139", "asPath": "65200 65300", "origin": "egp",
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

MOCK_ACI_NODE_208_INTERFACES = [
    {
      "vpcIf": {
        "attributes": {
          "accBndlGrpDn": "uni/infra/funcprof/accbundle-SDCZSN903_PROD1_Policy_Group",
          "cfgdAccessVlan": "vlan-296",
          "cfgdTrunkVlans": "296",
          "cfgdVlans": "296",
          "childAction": "",
          "compatQual": "0",
          "compatQualStr": "SUCCESS",
          "compatSt": "pass",
          "descr": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-345",
          "fabEncMismatchVlans": "",
          "fabEncMismatchVlansSet": "pass",
          "fabricPathDn": "topology/pod-1/protpaths-208-209/pathep-[SDCZSN903_PROD1_Policy_Group]",
          "id": "345",
          "lcOwn": "local",
          "localOperSt": "up",
          "modTs": "2023-04-12T22:24:44.570-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "name": "SDCZSN903_PROD1_Policy_Group",
          "pcMode": "active",
          "peerCfgdVlans": "296",
          "peerUpVlans": "296",
          "remoteOperSt": "up",
          "status": "",
          "suspVlans": "",
          "upVlans": "296",
          "usage": "epg"
        }
      }
    },
    {
      "vpcIf": {
        "attributes": {
          "accBndlGrpDn": "uni/infra/funcprof/accbundle-SDCZSN903_PROD2_Policy_Group",
          "cfgdAccessVlan": "vlan-2125",
          "cfgdTrunkVlans": "2125",
          "cfgdVlans": "2125",
          "childAction": "",
          "compatQual": "0",
          "compatQualStr": "SUCCESS",
          "compatSt": "pass",
          "descr": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-346",
          "fabEncMismatchVlans": "",
          "fabEncMismatchVlansSet": "pass",
          "fabricPathDn": "topology/pod-1/protpaths-208-209/pathep-[SDCZSN903_PROD2_Policy_Group]",
          "id": "346",
          "lcOwn": "local",
          "localOperSt": "up",
          "modTs": "2023-04-12T22:25:09.863-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "name": "SDCZSN903_PROD2_Policy_Group",
          "pcMode": "active",
          "peerCfgdVlans": "2125",
          "peerUpVlans": "2125",
          "remoteOperSt": "up",
          "status": "",
          "suspVlans": "",
          "upVlans": "2125",
          "usage": "epg"
        }
      }
    },
    {
      "vpcIf": {
        "attributes": {
          "accBndlGrpDn": "uni/infra/funcprof/accbundle-sdczarc803_aggr0_policy_group",
          "cfgdAccessVlan": "unknown",
          "cfgdTrunkVlans": "1081,1223,2070,2098,2125,2180-2181",
          "cfgdVlans": "1081,1223,2070,2098,2125,2180-2181",
          "childAction": "",
          "compatQual": "0",
          "compatQualStr": "SUCCESS",
          "compatSt": "pass",
          "descr": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-685",
          "fabEncMismatchVlans": "",
          "fabEncMismatchVlansSet": "pass",
          "fabricPathDn": "topology/pod-1/protpaths-208-209/pathep-[sdczarc803_aggr0_policy_group]",
          "id": "685",
          "lcOwn": "local",
          "localOperSt": "up",
          "modTs": "2025-06-30T00:23:07.175-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "name": "sdczarc803_aggr0_policy_group",
          "pcMode": "active",
          "peerCfgdVlans": "1081,1223,2070,2098,2125,2180-2181",
          "peerUpVlans": "1081,1223,2070,2098,2125,2180-2181",
          "remoteOperSt": "up",
          "status": "",
          "suspVlans": "",
          "upVlans": "1081,1223,2070,2098,2125,2180-2181",
          "usage": "epg"
        }
      }
    },
    {
      "vpcIf": {
        "attributes": {
          "accBndlGrpDn": "uni/infra/funcprof/accbundle-sdczarc803_aggr1_policy_group",
          "cfgdAccessVlan": "unknown",
          "cfgdTrunkVlans": "1081,1223,2070,2098,2125,2180-2181",
          "cfgdVlans": "1081,1223,2070,2098,2125,2180-2181",
          "childAction": "",
          "compatQual": "0",
          "compatQualStr": "SUCCESS",
          "compatSt": "pass",
          "descr": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-686",
          "fabEncMismatchVlans": "",
          "fabEncMismatchVlansSet": "pass",
          "fabricPathDn": "topology/pod-1/protpaths-208-209/pathep-[sdczarc803_aggr1_policy_group]",
          "id": "686",
          "lcOwn": "local",
          "localOperSt": "up",
          "modTs": "2025-06-30T00:25:50.597-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "name": "sdczarc803_aggr1_policy_group",
          "pcMode": "active",
          "peerCfgdVlans": "1081,1223,2070,2098,2125,2180-2181",
          "peerUpVlans": "1081,1223,2070,2098,2125,2180-2181",
          "remoteOperSt": "up",
          "status": "",
          "suspVlans": "",
          "upVlans": "1081,1223,2070,2098,2125,2180-2181",
          "usage": "epg"
        }
      }
    },
    {
      "vpcRsVpcConf": {
        "attributes": {
          "childAction": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-686/rsvpcConf",
          "forceResolve": "yes",
          "lcOwn": "local",
          "modTs": "2025-06-30T00:25:50.597-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "parentSKey": "686",
          "rType": "mo",
          "state": "formed",
          "stateQual": "none",
          "status": "",
          "tCl": "pcAggrIf",
          "tDn": "topology/pod-1/node-208/sys/aggr-[po11]",
          "tSKey": "po11",
          "tType": "mo",
          "vpcCfgFailedBmp": "",
          "vpcCfgFailedTs": "00:00:00:00.000",
          "vpcCfgState": "0"
        }
      }
    },
    {
      "vpcRsVpcConf": {
        "attributes": {
          "childAction": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-685/rsvpcConf",
          "forceResolve": "yes",
          "lcOwn": "local",
          "modTs": "2025-06-30T00:23:07.175-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "parentSKey": "685",
          "rType": "mo",
          "state": "formed",
          "stateQual": "none",
          "status": "",
          "tCl": "pcAggrIf",
          "tDn": "topology/pod-1/node-208/sys/aggr-[po10]",
          "tSKey": "po10",
          "tType": "mo",
          "vpcCfgFailedBmp": "",
          "vpcCfgFailedTs": "00:00:00:00.000",
          "vpcCfgState": "0"
        }
      }
    },
    {
      "vpcRsVpcConf": {
        "attributes": {
          "childAction": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-346/rsvpcConf",
          "forceResolve": "yes",
          "lcOwn": "local",
          "modTs": "2023-04-12T22:25:09.863-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "parentSKey": "346",
          "rType": "mo",
          "state": "formed",
          "stateQual": "none",
          "status": "",
          "tCl": "pcAggrIf",
          "tDn": "topology/pod-1/node-208/sys/aggr-[po9]",
          "tSKey": "po9",
          "tType": "mo",
          "vpcCfgFailedBmp": "",
          "vpcCfgFailedTs": "00:00:00:00.000",
          "vpcCfgState": "0"
        }
      }
    },
    {
      "vpcRsVpcConf": {
        "attributes": {
          "childAction": "",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208/if-345/rsvpcConf",
          "forceResolve": "yes",
          "lcOwn": "local",
          "modTs": "2023-04-12T22:24:44.570-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "parentSKey": "345",
          "rType": "mo",
          "state": "formed",
          "stateQual": "none",
          "status": "",
          "tCl": "pcAggrIf",
          "tDn": "topology/pod-1/node-208/sys/aggr-[po8]",
          "tSKey": "po8",
          "tType": "mo",
          "vpcCfgFailedBmp": "",
          "vpcCfgFailedTs": "00:00:00:00.000",
          "vpcCfgState": "0"
        }
      }
    },
    {
      "vpcDom": {
        "attributes": {
          "batchedVpcInv": "",
          "childAction": "",
          "compatQual": "0",
          "compatQualStr": "SUCCESS",
          "compatSt": "pass",
          "deadIntvl": "200",
          "dn": "topology/pod-1/node-208/sys/vpc/inst/dom-208",
          "dualActiveSt": "false",
          "id": "208",
          "issuFromVer": "",
          "issuToVer": "",
          "lacpRole": "slave",
          "lcOwn": "local",
          "localMAC": "10:B3:D6:E5:58:BF",
          "localPrio": "208",
          "modTs": "2022-02-22T23:48:00.815-04:00",
          "monPolDn": "uni/fabric/monfab-default",
          "name": "",
          "oldRole": "master",
          "operRole": "master",
          "operSt": "configured-master,vpcs-reinited",
          "orphanPortList": "0",
          "peerIp": "172.18.96.73/32",
          "peerMAC": "10:B3:D6:E5:4E:FF",
          "peerPrio": "209",
          "peerSt": "up",
          "peerStQual": "success",
          "peerVersion": "25",
          "rolePrio": "208",
          "selfIniFabLinkFlapCnt": "0",
          "splitBrainTimerDuration": "0",
          "splitBrainTimerIsRun": "No",
          "splitBrainTimerStartTime": "1969-12-31T20:00:00.000-04:00",
          "status": "",
          "summOperRole": "cfg-master-oper-master",
          "sysMac": "00:00:00:00:00:00",
          "sysPrio": "32667",
          "tryRoleEstabTimerDuration": "280",
          "tryRoleEstabTimerIsRun": "No",
          "tryRoleEstabTimerStartTime": "2022-02-22T23:41:17.757-04:00",
          "type2CompatQual": "0",
          "type2CompatQualStr": "SUCCESS",
          "type2CompatSt": "pass",
          "vIpAnnounceDelay": "45",
          "virtualIp": "172.18.200.70/32",
          "vpcCfgFailedBmp": "",
          "vpcCfgFailedTs": "00:00:00:00.000",
          "vpcCfgState": "0",
          "vpcMAC": "00:23:04:EE:BE:D0",
          "vpcPrio": "32667"
        }
      }
    },
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/33]", "id": "eth1/33", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/34]", "id": "eth1/34", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/35]", "id": "eth1/35", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/36]", "id": "eth1/36", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/37]", "id": "eth1/37", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/38]", "id": "eth1/38", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/39]", "id": "eth1/39", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/40]", "id": "eth1/40", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/41]", "id": "eth1/41", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/42]", "id": "eth1/42", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/43]", "id": "eth1/43", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/44]", "id": "eth1/44", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/45]", "id": "eth1/45", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/46]", "id": "eth1/46", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/47]", "id": "eth1/47", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/48]", "id": "eth1/48", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/49]", "id": "eth1/49", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/50]", "id": "eth1/50", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/51]", "id": "eth1/51", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric,fabric-ext"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/52]", "id": "eth1/52", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric,fabric-ext"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/53]", "id": "eth1/53", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric,fabric-ext"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/54]", "id": "eth1/54", "layer": "Layer3", "mode": "trunk", "mtu": "9366", "usage": "fabric,fabric-ext"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/1]", "id": "eth1/1", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/2]", "id": "eth1/2", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/3]", "id": "eth1/3", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/4]", "id": "eth1/4", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/5]", "id": "eth1/5", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/6]", "id": "eth1/6", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/7]", "id": "eth1/7", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/8]", "id": "eth1/8", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/9]", "id": "eth1/9", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/10]", "id": "eth1/10", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/11]", "id": "eth1/11", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/12]", "id": "eth1/12", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/13]", "id": "eth1/13", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/14]", "id": "eth1/14", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/15]", "id": "eth1/15", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/16]", "id": "eth1/16", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/17]", "id": "eth1/17", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/18]", "id": "eth1/18", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/19]", "id": "eth1/19", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/20]", "id": "eth1/20", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/21]", "id": "eth1/21", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/22]", "id": "eth1/22", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/23]", "id": "eth1/23", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/24]", "id": "eth1/24", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/25]", "id": "eth1/25", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/26]", "id": "eth1/26", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/27]", "id": "eth1/27", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/28]", "id": "eth1/28", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "discovery"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/29]", "id": "eth1/29", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/30]", "id": "eth1/30", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/31]", "id": "eth1/31", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"l1PhysIf": {"attributes": {"adminSt": "up", "autoNeg": "on", "dn": "topology/pod-1/node-208/sys/phys-[eth1/32]", "id": "eth1/32", "layer": "Layer2", "mode": "trunk", "mtu": "9000", "usage": "epg"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,17,21,25,30,37,44-47,61-63", "bundleIndex": "po11", "dn": "topology/pod-1/node-208/sys/phys-[eth1/32]/phys", "lastLinkStChg": "2026-04-23T15:25:31.290-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,44", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/30]/phys", "lastLinkStChg": "2026-02-14T23:44:58.150-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/28]/phys", "lastLinkStChg": "2026-04-22T02:24:54.013-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "down", "operStQual": "link-failure"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "12,28", "bundleIndex": "po8", "dn": "topology/pod-1/node-208/sys/phys-[eth1/27]/phys", "lastLinkStChg": "2026-04-22T02:26:13.360-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/26]/phys", "lastLinkStChg": "2025-03-14T11:24:35.134-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/40]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/53]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/7]/phys", "lastLinkStChg": "2026-04-20T01:34:02.139-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/18]/phys", "lastLinkStChg": "2026-04-18T20:44:23.384-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/50]/phys", "lastLinkStChg": "2022-02-22T23:38:47.555-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,17,21,25,30,37,44-47,61-63", "bundleIndex": "po10", "dn": "topology/pod-1/node-208/sys/phys-[eth1/31]/phys", "lastLinkStChg": "2026-04-24T16:00:52.319-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/51]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/54]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "po6", "dn": "topology/pod-1/node-208/sys/phys-[eth1/22]/phys", "lastLinkStChg": "2026-03-15T23:32:58.584-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/44]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/33]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "down", "operStQual": "link-failure"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/8]/phys", "lastLinkStChg": "2026-04-20T01:34:02.680-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/48]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/43]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/39]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/34]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/35]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/17]/phys", "lastLinkStChg": "2026-03-10T13:04:57.047-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/37]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/38]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/42]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "25,37", "bundleIndex": "po9", "dn": "topology/pod-1/node-208/sys/phys-[eth1/29]/phys", "lastLinkStChg": "2026-04-22T02:26:13.147-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/9]/phys", "lastLinkStChg": "2026-04-20T01:39:31.225-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/16]/phys", "lastLinkStChg": "2026-03-10T13:04:57.547-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/1]/phys", "lastLinkStChg": "2026-04-21T21:23:07.003-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/14]/phys", "lastLinkStChg": "2026-04-21T22:09:34.489-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/3]/phys", "lastLinkStChg": "2026-04-21T21:28:25.593-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/46]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/4]/phys", "lastLinkStChg": "2026-04-18T21:16:10.692-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/5]/phys", "lastLinkStChg": "2026-04-18T21:16:11.182-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "po6", "dn": "topology/pod-1/node-208/sys/phys-[eth1/20]/phys", "lastLinkStChg": "2026-03-15T23:32:58.550-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/49]/phys", "lastLinkStChg": "2022-02-22T23:38:47.522-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/6]/phys", "lastLinkStChg": "2026-04-18T21:21:21.983-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/25]/phys", "lastLinkStChg": "2026-03-15T23:32:43.919-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/2]/phys", "lastLinkStChg": "2026-04-21T21:23:07.028-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/15]/phys", "lastLinkStChg": "2026-04-21T22:14:48.642-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/47]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/10]/phys", "lastLinkStChg": "2026-04-20T22:10:43.096-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/36]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/11]/phys", "lastLinkStChg": "2026-04-20T22:10:43.168-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/52]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "100G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "9,12,14,17,21,27,30,32,35,37,39,41,50,55,57,59,64-84,86-88", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/13]/phys", "lastLinkStChg": "2026-04-21T22:09:33.565-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/19]/phys", "lastLinkStChg": "2023-04-05T16:54:38.265-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "down", "operStQual": "link-failure"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "po6", "dn": "topology/pod-1/node-208/sys/phys-[eth1/21]/phys", "lastLinkStChg": "2026-03-15T23:32:58.588-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/41]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/12]/phys", "lastLinkStChg": "2026-04-20T22:15:58.986-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "50,53", "bundleIndex": "po6", "dn": "topology/pod-1/node-208/sys/phys-[eth1/23]/phys", "lastLinkStChg": "2026-03-15T23:32:58.628-04:00", "operDuplex": "full", "operSpeed": "1G", "operSt": "up", "operStQual": "none"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/45]/phys", "lastLinkStChg": "1969-12-31T20:00:00.000-04:00", "operDuplex": "full", "operSpeed": "25G", "operSt": "down", "operStQual": "sfp-missing"}}},
    {"ethpmPhysIf": {"attributes": {"allowedVlans": "", "bundleIndex": "unspecified", "dn": "topology/pod-1/node-208/sys/phys-[eth1/24]/phys", "lastLinkStChg": "2026-03-15T23:32:43.857-04:00", "operDuplex": "full", "operSpeed": "10G", "operSt": "up", "operStQual": "none"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po6]", "id": "po6", "name": "SDCZFPS001_plcy-grp", "operSt": "up", "pcMode": "active"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po8]", "id": "po8", "name": "SDCZSN903_PROD1_Policy_Group", "operSt": "up", "pcMode": "active"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po9]", "id": "po9", "name": "SDCZSN903_PROD2_Policy_Group", "operSt": "up", "pcMode": "active"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po10]", "id": "po10", "name": "sdczarc803_aggr0_policy_group", "operSt": "up", "pcMode": "active"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po11]", "id": "po11", "name": "sdczarc803_aggr1_policy_group", "operSt": "up", "pcMode": "active"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po10]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/31]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/31]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po8]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/27]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/27]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po11]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/32]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/32]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po9]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/29]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/29]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po6]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/21]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/21]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po6]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/23]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/23]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po6]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/22]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/22]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-208/sys/aggr-[po6]/rsmbrIfs-[topology/pod-1/node-208/sys/phys-[eth1/20]]", "tDn": "topology/pod-1/node-208/sys/phys-[eth1/20]"}}}
]


MOCK_ACI_NODE_INTERFACES = [
    # 2 access ports
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/1]", "id": "eth1/1", "adminSt": "up", "speed": "10G", "mtu": "1500", "layer": "Layer2", "mode": "trunk", "descr": "Web-Server-01"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/1]/phys", "operSt": "up", "operSpeed": "10G", "operDuplex": "full", "lastLinkStChg": "2024-05-20T08:00:00Z"}}},
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/2]", "id": "eth1/2", "adminSt": "up", "speed": "10G", "mtu": "1500", "layer": "Layer2", "mode": "trunk", "descr": "DB-Server-01"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/2]/phys", "operSt": "down", "operSpeed": "inherit", "operDuplex": "auto", "lastLinkStChg": "2024-05-19T20:00:00Z"}}},

    # 2 PC members (Po10)
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/10]", "id": "eth1/10", "adminSt": "up", "speed": "10G", "mtu": "9000", "layer": "Layer2", "mode": "trunk"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/10]/phys", "operSt": "up", "operSpeed": "10G", "operDuplex": "full"}}},
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/11]", "id": "eth1/11", "adminSt": "up", "speed": "10G", "mtu": "9000", "layer": "Layer2", "mode": "trunk"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/11]/phys", "operSt": "up", "operSpeed": "10G", "operDuplex": "full"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/aggr-[po10]", "id": "po10", "pcMode": "active", "operSt": "up"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/10]/rsmbrIfs", "tDn": "topology/pod-1/node-149/sys/aggr-[po10]"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/11]/rsmbrIfs", "tDn": "topology/pod-1/node-149/sys/aggr-[po10]"}}},

    # 1 standalone uplink
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/48]", "id": "eth1/48", "adminSt": "up", "speed": "40G", "mtu": "9216", "layer": "Layer3", "mode": "routed", "descr": "Uplink-to-Spine"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/48]/phys", "operSt": "up", "operSpeed": "40G", "operDuplex": "full"}}},

    # 1 vPC leg (vPC-100 on Po100)
    {"l1PhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/20]", "id": "eth1/20", "adminSt": "up", "speed": "10G", "mtu": "9000", "layer": "Layer2", "mode": "trunk"}}},
    {"ethpmPhysIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/20]/phys", "operSt": "up", "operSpeed": "10G", "operDuplex": "full"}}},
    {"pcAggrIf": {"attributes": {"dn": "topology/pod-1/node-149/sys/aggr-[po100]", "id": "po100", "pcMode": "active", "operSt": "up"}}},
    {"pcRsMbrIfs": {"attributes": {"dn": "topology/pod-1/node-149/sys/phys-[eth1/20]/rsmbrIfs", "tDn": "topology/pod-1/node-149/sys/aggr-[po100]"}}},
    {"vpcRsVpcConf": {"attributes": {"dn": "topology/pod-1/node-149/sys/vpc/inst/dom-1/if-[vpc-100]/rsvpcConf", "tDn": "topology/pod-1/node-149/sys/aggr-[po100]"}}},
]

MOCK_IPAM_TREE = {
    "ipv4": [
        {
            "cidr": "10.0.0.0/8",
            "display_name": "Internal Network",
            "role": "subnet",
            "interface_type": "physical",
            "site": "Global",
            "device": "N/A",
            "source": "Aggregated",
            "conflicts": [],
            "overlaps": [],
            "children": [
                {
                    "cidr": "10.10.0.0/16",
                    "display_name": "DCA Data Center",
                    "role": "subnet",
                    "interface_type": "physical",
                    "site": "TSA-DCA-HQ",
                    "device": "N/A",
                    "source": "DNAC",
                    "conflicts": [],
                    "overlaps": [],
                    "children": [
                        {
                            "cidr": "10.10.1.0/24",
                            "display_name": "User Access",
                            "role": "subnet",
                            "interface_type": "svi",
                            "vlan_id": 200,
                            "site": "TSA-DCA-HQ",
                            "device": "SW-DCA-HQ-01",
                            "source": "DNAC",
                            "conflicts": [],
                            "overlaps": [],
                            "children": []
                        },
                        {
                            "cidr": "10.10.100.0/24",
                            "display_name": "Tunnel Network (2 endpoints)",
                            "role": "tunnel_group",
                            "interface_type": "tunnel",
                            "site": "TSA-DCA-HQ",
                            "source": "Nexus",
                            "children": [
                                {
                                    "cidr": "10.10.100.0/24",
                                    "host_ip": "10.10.100.1",
                                    "display_name": "Tunnel100",
                                    "role": "endpoint",
                                    "interface_type": "tunnel",
                                    "site": "TSA-DCA-HQ",
                                    "device": "CORE-DCA-01",
                                    "source": "Nexus"
                                },
                                {
                                    "cidr": "10.10.100.0/24",
                                    "host_ip": "10.10.100.2",
                                    "display_name": "Tunnel100",
                                    "role": "endpoint",
                                    "interface_type": "tunnel",
                                    "site": "TSA-BOS-HQ",
                                    "device": "CORE-BOS-01",
                                    "source": "Nexus"
                                }
                            ]
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
            "role": "subnet",
            "interface_type": "physical",
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

def _build_ipam_tree_from_mocks() -> dict:
    """Run the live IPAM engine against the seeded mock source caches.

    DNAC discovery uses ``loop.run_in_executor`` internally so we need a real
    event loop. Session is None because the loaders are never invoked — the
    caches are already populated by seed_cache.
    """
    import asyncio
    from utils.ipam_engine import IPAMEngine

    engine = IPAMEngine()
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(engine._discover_dnac(None, loop))
        loop.run_until_complete(engine._discover_nexus(None, None))
        loop.run_until_complete(engine._discover_panorama(None, None))
    finally:
        loop.close()
    engine.build_tree()
    return engine.get_tree()


def seed_cache(cache) -> None:
    """Pre-populate the in-memory cache with mock data for all UI-facing endpoints."""
    from cache import TTL_DEVICES, TTL_SITES, IPAM_TREE_CACHE_KEY
    LONG = 86400 * 365  # 1 year — mock data never expires

    # DNAC
    cache.set("devices",         MOCK_DEVICES,          TTL_DEVICES)
    cache.set("sites",           MOCK_SITES,            TTL_SITES)
    cache.set("device_site_map", MOCK_DEVICE_SITE_MAP,  TTL_SITES)
    cache.set("dnac_interfaces", MOCK_DNAC_INTERFACES,  LONG)

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
    cache.set("pan_interfaces",      MOCK_PAN_INTERFACES,   LONG)

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

    # Nexus (seed source caches BEFORE computing the IPAM tree below)
    cache.set("nexus_inventory", MOCK_NEXUS_DEVICES, LONG)
    cache.set("nexus_interfaces", MOCK_NEXUS_INTERFACES, LONG)

    # IPAM — compute the tree from the same source caches the live engine
    # consumes, so initial render matches what Refresh Discovery would produce.
    # Falls back to the static MOCK_IPAM_TREE if the engine can't run.
    try:
        cache.set(IPAM_TREE_CACHE_KEY, _build_ipam_tree_from_mocks(), LONG)
    except Exception:
        cache.set(IPAM_TREE_CACHE_KEY, MOCK_IPAM_TREE, LONG)

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
