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
DEV_IPAM_LARGE = os.getenv("DEV_IPAM_LARGE", "").lower() in ("1", "true", "yes")

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
        _platform = _PLATFORM[_di % len(_PLATFORM)]
        _family = "Routers" if _platform.startswith("ISR") else "Switches and Hubs"
        _host  = f"SW-{_site.split('-')[1]}-{_di+1:02d}" if _role == "ACCESS" else f"CORE-{_site.split('-')[1]}-{_di+1:02d}"
        _dev   = {
            "id":                    _id,
            "hostname":              _host,
            "managementIpAddress":   f"{_subnet}.{_di+1}.1",
            "platformId":            _platform,
            "family":                _family,
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

def _dnac_iface(dev_id, host, port, addr, mask, vlan=None, desc="", ipv6_list=None):
    """ipv6_list: list of either CIDR strings ("2001::1/64") or dicts
    ({"address":"2001::1","prefix":"64"}) — exercises both shapes the
    DNAC interface API can return for ipv6AddressList."""
    MOCK_DNAC_INTERFACES.append({
        "deviceId": dev_id, "deviceName": host,
        "portName": port, "ipv4Address": addr, "ipv4Mask": mask,
        "ipv6AddressList": ipv6_list or [],
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
    # Transit uplink — per-site /24, dual-stack
    _dnac_iface(
        _id, _host, "GigabitEthernet1/0/1",
        f"10.{_octet}.100.1", "255.255.255.0",
        desc="Uplink",
        ipv6_list=[f"2001:db8:{_octet:x}:100::1/64"],
    )
    # Loopback0 — unique /32 per CORE device (5 hosts collapse into a host-route group)
    # Plus an IPv6 /128 router-id so we can verify v6 host-route handling.
    _dnac_iface(
        _id, _host, "Loopback0",
        f"10.99.100.{_n}", "255.255.255.255",
        desc="Router ID",
        ipv6_list=[{"address": f"2001:db8:99:100::{_n}", "prefix": "128"}],
    )
    # Per-site SVI — dual-stack (use dict shape here to exercise both paths)
    _dnac_iface(
        _id, _host, "Vlan10",
        f"10.{_octet}.10.1", "255.255.255.0", vlan="10", desc="Users VLAN",
        ipv6_list=[
            {"address": f"2001:db8:{_octet:x}:10::1", "prefix": "64", "addressType": "GLOBAL"},
            "fe80::1/10",  # link-local — should be filtered by is_excluded
        ],
    )
    # Tunnel10 — DMVPN-style hub/spoke: all CORE devices share 10.99.3.0/24 so
    # IPAM should render a single tunnel_group with 5 endpoints.
    _dnac_iface(_id, _host, "Tunnel10", f"10.99.3.{_n}", "255.255.255.0", desc=f"DMVPN endpoint {_n}")

# Point-to-point transit: Tunnel20 pairs CORE-DCA (idx 1) and CORE-BOS (idx 2) on a /30
_pair = list(_CORE_PRIMARY.values())[:2]
if len(_pair) == 2:
    _dnac_iface(_pair[0]["id"], _pair[0]["hostname"], "Tunnel20", "10.99.4.1", "255.255.255.252", desc="P2P to BOS")
    _dnac_iface(_pair[1]["id"], _pair[1]["hostname"], "Tunnel20", "10.99.4.2", "255.255.255.252", desc="P2P to DCA")

# ── Mock DNAC IP Pools ────────────────────────────────────────────────────────
# Mirrors what /dna/intent/api/v1/global-pool and /reserve-ip-subpool return.
# Provides authoritative dual-stack site allocations for IPAM (especially IPv6,
# which the interface inventory endpoint typically doesn't ship).
MOCK_DNAC_GLOBAL_POOLS = [
    {"id": "gp-v4", "ipPoolName": "TSA-Global-v4", "ipPoolCidr": "10.0.0.0/8", "ipv6": False},
    {"id": "gp-v6", "ipPoolName": "TSA-Global-v6", "ipPoolCidr": "2001:db8::/32", "ipv6": True},
]

MOCK_DNAC_RESERVE_SUBPOOLS = []
for _site, _prefix in _SITES:
    _site_octet = int(_prefix.split(".")[1])  # "10.10" -> 10
    MOCK_DNAC_RESERVE_SUBPOOLS.append({
        "id": f"sp-{_site}",
        "groupName": f"{_site}-Allocation",
        "siteName": _site,
        "ipPools": [
            {
                "ipPoolName": f"{_site}-v4",
                "ipPoolCidr": f"{_prefix}.0.0/16",
                "ipv6": False,
                "gateway": f"{_prefix}.0.1",
            },
            {
                "ipPoolName": f"{_site}-v6",
                "ipPoolCidr": f"2001:db8:{_site_octet:x}::/48",
                "ipv6": True,
                "gateway": f"2001:db8:{_site_octet:x}::1",
            },
        ],
    })

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

# vPC pair on the first two switches; standalone PC on switch 3 to exercise
# the "not in vPC" view. Switches 4..10 have nothing — proves the empty-state
# rendering on per-device drill-down.
_VPC_PEERS = (MOCK_NEXUS_DEVICES[0]["hostname"], MOCK_NEXUS_DEVICES[1]["hostname"])

MOCK_NEXUS_PORT_CHANNELS: list[dict] = []
for _peer in _VPC_PEERS:
    MOCK_NEXUS_PORT_CHANNELS.extend([
        {"hostname": _peer, "group": 1,  "interface": "Po1",  "state": "U", "layer": "L2", "protocol": "LACP", "members": ["Eth1/47", "Eth1/48"]},
        {"hostname": _peer, "group": 10, "interface": "Po10", "state": "U", "layer": "L2", "protocol": "LACP", "members": ["Eth1/10"]},
        {"hostname": _peer, "group": 20, "interface": "Po20", "state": "U", "layer": "L2", "protocol": "LACP", "members": ["Eth1/20"]},
        {"hostname": _peer, "group": 30, "interface": "Po30", "state": "D", "layer": "L2", "protocol": "LACP", "members": ["Eth1/30"]},
    ])
MOCK_NEXUS_PORT_CHANNELS.append({
    "hostname": MOCK_NEXUS_DEVICES[2]["hostname"],
    "group": 100, "interface": "Po100", "state": "U", "layer": "L3",
    "protocol": "NONE", "members": ["Eth1/1", "Eth1/2"],
})

MOCK_NEXUS_VPCS: list[dict] = []
for _peer, _role in zip(_VPC_PEERS, ("primary", "secondary")):
    for _vpc_id, _port, _state, _consistency, _reason in [
        (10, "Po10", "up",   "success", "success"),
        (20, "Po20", "up",   "success", "success"),
        (30, "Po30", "down", "failed",  "vPC type-1 consistency check failed"),
    ]:
        MOCK_NEXUS_VPCS.append({
            "hostname":            _peer,
            "domain_id":           "100",
            "role":                _role,
            "peer_status":         "peer-ok",
            "config_consistency":  "success",
            "vpc_id":              _vpc_id,
            "port":                _port,
            "status":              _state,
            "consistency":         _consistency,
            "reason":              _reason,
            "active_vlans":        "10,20,30" if _state == "up" else "-",
        })

MOCK_NEXUS_VLANS: list[dict] = []
_VLAN_DEFS = [
    (1,  "default",     "active",    ["Po1", "Eth1/15", "Eth1/16"]),
    (10, "USERS",       "active",    ["Po1", "Po10", "Eth1/20"]),
    (20, "SERVERS",     "active",    ["Po1", "Po20"]),
    (30, "GUEST",       "active",    ["Po1", "Po30"]),
    (99, "QUARANTINE",  "suspended", []),
]
for _peer in _VPC_PEERS:
    for _vid, _name, _state, _ports in _VLAN_DEFS:
        MOCK_NEXUS_VLANS.append({
            "hostname": _peer,
            "vlan_id":  _vid,
            "name":     _name,
            "state":    _state,
            "ports":    list(_ports),
        })

# ── F5 BIG-IP mocks (fake IPs only — see docs/IP_ADDRESS_POLICY.md) ────────────
# An HA pair: f5-dca-01 (active) / f5-dca-02 (standby). Config is synced, so
# virtuals/pools/nodes/routes/vlans are identical on both units; self-IPs differ
# per unit (last octet 1/2) with a shared floating self-IP (.4).
MOCK_F5_DEVICES = [
    {
        "id": "f5_f5-dca-01", "hostname": "f5-dca-01", "managementIpAddress": "10.20.0.10",
        "model": "BIG-IP i5800", "platformId": "F5 BIG-IP", "version": "16.1.3.1",
        "edition": "Final", "failoverState": "active", "chassisId": "chs-aaaa-0001",
        "reachabilityStatus": "Reachable", "source": "F5", "lastUpdateTime": _now_ms,
    },
    {
        "id": "f5_f5-dca-02", "hostname": "f5-dca-02", "managementIpAddress": "10.20.0.11",
        "model": "BIG-IP i5800", "platformId": "F5 BIG-IP", "version": "16.1.3.1",
        "edition": "Final", "failoverState": "standby", "chassisId": "chs-aaaa-0002",
        "reachabilityStatus": "Reachable", "source": "F5", "lastUpdateTime": _now_ms,
    },
]

_F5_HOSTS = [d["hostname"] for d in MOCK_F5_DEVICES]

MOCK_F5_SELF_IPS = []
for _i, _h in enumerate(_F5_HOSTS, start=1):
    MOCK_F5_SELF_IPS.extend([
        {"hostname": _h, "name": "external-self", "address": f"1.2.3.{_i}/24",
         "vlan": "external", "trafficGroup": "traffic-group-local-only", "floating": "disabled", "allowService": "none"},
        {"hostname": _h, "name": "internal-self", "address": f"5.6.7.{_i}/24",
         "vlan": "internal", "trafficGroup": "traffic-group-local-only", "floating": "disabled", "allowService": "default"},
        {"hostname": _h, "name": "external-float", "address": "1.2.3.4/24",
         "vlan": "external", "trafficGroup": "traffic-group-1", "floating": "enabled", "allowService": "none"},
    ])

MOCK_F5_VLANS = []
MOCK_F5_INTERFACES = []
for _h in _F5_HOSTS:
    MOCK_F5_VLANS.extend([
        {"hostname": _h, "name": "external", "tag": 1010, "mtu": 1500, "interfaces": "1.1"},
        {"hostname": _h, "name": "internal", "tag": 1020, "mtu": 1500, "interfaces": "1.2"},
        {"hostname": _h, "name": "ha",       "tag": 1030, "mtu": 1500, "interfaces": "1.3"},
    ])
    MOCK_F5_INTERFACES.extend([
        {"hostname": _h, "name": "1.1",  "mac": "00:50:56:aa:01:01", "enabled": True,  "mediaActive": "10000SR-FD", "mtu": 1500},
        {"hostname": _h, "name": "1.2",  "mac": "00:50:56:aa:01:02", "enabled": True,  "mediaActive": "10000SR-FD", "mtu": 1500},
        {"hostname": _h, "name": "1.3",  "mac": "00:50:56:aa:01:03", "enabled": True,  "mediaActive": "1000T-FD",   "mtu": 1500},
        {"hostname": _h, "name": "mgmt", "mac": "00:50:56:aa:01:00", "enabled": True,  "mediaActive": "1000T-FD",   "mtu": 1500},
    ])

# Synced objects — identical on both units.
_F5_VS_DEFS = [
    ("vs_web_https", "1.2.3.100", "443", "pool_web", "tcp", "enabled",  "available"),
    ("vs_app_https", "1.2.3.101", "443", "pool_app", "tcp", "enabled",  "offline"),
    ("vs_dns",       "1.2.3.102", "53",  "pool_dns", "udp", "enabled",  "available"),
    ("vs_legacy",    "1.2.3.103", "80",  "",         "tcp", "disabled", "unknown"),
]
MOCK_F5_VIRTUALS = []
for _h in _F5_HOSTS:
    for _name, _ip, _port, _pool, _proto, _status, _avail in _F5_VS_DEFS:
        MOCK_F5_VIRTUALS.append({
            "hostname": _h, "name": _name, "partition": "Common",
            "destination": f"/Common/{_ip}:{_port}", "ip": _ip, "port": _port,
            "pool": _pool, "ipProtocol": _proto, "status": _status,
            "availability": _avail, "description": "",
        })

_F5_POOL_DEFS = [
    ("pool_web", "round-robin",        "https", [("10.50.1.11", "443", "up"),   ("10.50.1.12", "443", "up")]),
    ("pool_app", "least-connections-member", "tcp", [("10.50.2.11", "8443", "up"), ("10.50.2.12", "8443", "down")]),
    ("pool_dns", "round-robin",        "gateway_icmp", [("10.50.3.11", "53", "up")]),
]
MOCK_F5_POOLS = []
MOCK_F5_NODES = []
_seen_nodes = set()
for _h in _F5_HOSTS:
    for _pname, _lb, _mon, _members in _F5_POOL_DEFS:
        members = [
            {"name": f"{_addr}:{_port}", "address": _addr, "state": _state,
             "session": "user-disabled" if _state == "down" else "monitor-enabled"}
            for _addr, _port, _state in _members
        ]
        MOCK_F5_POOLS.append({
            "hostname": _h, "name": _pname, "partition": "Common",
            "loadBalancingMode": _lb, "monitor": _mon,
            "member_count": len(members), "members": members,
        })
        for _addr, _port, _state in _members:
            _key = (_h, _addr)
            if _key in _seen_nodes:
                continue
            _seen_nodes.add(_key)
            MOCK_F5_NODES.append({
                "hostname": _h, "name": _addr, "address": _addr, "state": _state,
                "session": "user-disabled" if _state == "down" else "monitor-enabled",
            })

MOCK_F5_ROUTES = []
for _h in _F5_HOSTS:
    MOCK_F5_ROUTES.extend([
        {"hostname": _h, "name": "default",    "network": "default",      "gw": "1.2.3.1"},
        {"hostname": _h, "name": "to-backend", "network": "10.50.0.0/16", "gw": "5.6.7.1"},
    ])

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
        "id":              _uid(f"nad-{i}"),
        "name":            dev["hostname"],
        "description":     f"{dev['role']} switch",
        "ipaddress":       dev["managementIpAddress"],
        "profileName":     "Cisco",
        "modelName":       dev["platformId"],
        "softwareVersion": dev["softwareVersion"],
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
    {"id": _uid("ps-wired"),    "name": "Wired_MAB",      "description": "MAC Auth for wired devices", "isProxy": False, "state": "ENABLED"},
    {"id": _uid("ps-wireless"), "name": "Wireless_Dot1x", "description": "802.1X for wireless",        "isProxy": False, "state": "ENABLED"},
    {"id": _uid("ps-vpn"),      "name": "VPN_Access",     "description": "VPN user authentication",    "isProxy": False, "state": "ENABLED"},
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

# ── Extended ISE mock data ────────────────────────────────────────────────────

MOCK_ENDPOINTS: list[dict] = [
    {
        "id":               _uid("ep-laptop-dca-01"),
        "name":             "A4:C3:F0:11:22:33",
        "mac":              "A4:C3:F0:11:22:33",
        "profileId":        _uid("epg-workstation"),
        "profileName":      "Windows10-Workstation",
        "endpointGroupId":  _uid("epg-workstation"),
        "groupName":        "Workstation",
        "staticGroupAssignment": False,
        "staticProfileAssignment": False,
        "portalUser":       "",
        "ipAddress":        "10.10.5.100",
        "nas_ip_address":   "10.10.1.1",
        "identityStore":    "AD",
        "identityGroup":    "Employees",
        "connectedToDevice": "SW-DCA-01",
        "lastAuthTime":     "2026-05-05T08:15:00Z",
    },
    {
        "id":               _uid("ep-phone-dca-01"),
        "name":             "00:1B:44:11:3A:B7",
        "mac":              "00:1B:44:11:3A:B7",
        "profileName":      "Cisco-IP-Phone",
        "groupName":        "IP_Phone",
        "staticGroupAssignment": True,
        "ipAddress":        "10.10.6.50",
        "nas_ip_address":   "10.10.1.2",
        "identityStore":    "Internal Endpoints",
        "identityGroup":    "IP_Phone",
        "connectedToDevice": "SW-DCA-02",
        "lastAuthTime":     "2026-05-05T07:45:00Z",
    },
    {
        "id":               _uid("ep-camera-lax-01"),
        "name":             "DC:A6:32:55:66:77",
        "mac":              "DC:A6:32:55:66:77",
        "profileName":      "Axis-Camera",
        "groupName":        "IP_Camera",
        "staticGroupAssignment": True,
        "ipAddress":        "10.30.20.15",
        "nas_ip_address":   "10.30.1.5",
        "identityStore":    "Internal Endpoints",
        "identityGroup":    "IP_Camera",
        "connectedToDevice": "SW-LAX-05",
        "lastAuthTime":     "2026-05-05T06:00:00Z",
    },
    {
        "id":               _uid("ep-printer-ord-01"),
        "name":             "B8:27:EB:AA:BB:CC",
        "mac":              "B8:27:EB:AA:BB:CC",
        "profileName":      "HP-JetDirect",
        "groupName":        "Printer",
        "staticGroupAssignment": False,
        "ipAddress":        "10.40.30.25",
        "nas_ip_address":   "10.40.1.3",
        "identityStore":    "Internal Endpoints",
        "identityGroup":    "Printer",
        "connectedToDevice": "SW-ORD-03",
        "lastAuthTime":     "2026-05-04T22:10:00Z",
    },
    {
        "id":               _uid("ep-byod-jfk-01"),
        "name":             "F4:5C:89:DD:EE:FF",
        "mac":              "F4:5C:89:DD:EE:FF",
        "profileName":      "Apple-iPhone",
        "groupName":        "BYOD",
        "staticGroupAssignment": False,
        "ipAddress":        "10.50.100.200",
        "nas_ip_address":   "10.50.1.7",
        "identityStore":    "AD",
        "identityGroup":    "GuestEndpoints",
        "connectedToDevice": "SW-JFK-07",
        "lastAuthTime":     "2026-05-05T09:00:00Z",
    },
]

MOCK_ACTIVE_SESSIONS: list[dict] = [
    {
        "calling_station_id":  "A4:C3:F0:11:22:33",
        "user_name":           "jsmith@tsa.gov",
        "nas_ip_address":      "10.10.1.1",
        "nas_port_id":         "GigabitEthernet1/0/12",
        "framed_ip_address":   "10.10.5.100",
        "acct_session_id":     "0000001A",
        "endpoint_profile":    "Windows10-Workstation",
        "vlan":                "500",
        "auth_method":         "dot1x",
        "identity_store":      "AD",
        "identity_group":      "Employees",
        "ise_node":            "ise-psn-01.tsa.local",
        "audit_session_id":    "AC0A01010000001A",
        "network_device_name": "SW-DCA-01",
        "sgt":                 "4",
        "posture_status":      "Compliant",
        "session_timeout":     "28800",
        "acct_session_time":   "45",
    },
    {
        "calling_station_id":  "00:1B:44:11:3A:B7",
        "user_name":           "",
        "nas_ip_address":      "10.10.1.2",
        "nas_port_id":         "GigabitEthernet1/0/8",
        "framed_ip_address":   "10.10.6.50",
        "acct_session_id":     "0000001B",
        "endpoint_profile":    "Cisco-IP-Phone",
        "vlan":                "600",
        "auth_method":         "mab",
        "identity_store":      "Internal Endpoints",
        "identity_group":      "IP_Phone",
        "ise_node":            "ise-psn-01.tsa.local",
        "network_device_name": "SW-DCA-02",
        "sgt":                 "100",
        "posture_status":      "Unknown",
        "acct_session_time":   "14400",
    },
    {
        "calling_station_id":  "DC:A6:32:55:66:77",
        "user_name":           "",
        "nas_ip_address":      "10.30.1.5",
        "nas_port_id":         "GigabitEthernet2/0/3",
        "framed_ip_address":   "10.30.20.15",
        "acct_session_id":     "0000002C",
        "endpoint_profile":    "Axis-Camera",
        "vlan":                "700",
        "auth_method":         "mab",
        "identity_store":      "Internal Endpoints",
        "identity_group":      "IP_Camera",
        "ise_node":            "ise-psn-02.tsa.local",
        "network_device_name": "SW-LAX-05",
        "sgt":                 "110",
        "posture_status":      "Unknown",
        "acct_session_time":   "86400",
    },
    {
        "calling_station_id":  "F4:5C:89:DD:EE:FF",
        "user_name":           "traveler@gmail.com",
        "nas_ip_address":      "10.50.1.7",
        "nas_port_id":         "GigabitEthernet3/0/24",
        "framed_ip_address":   "10.50.100.200",
        "acct_session_id":     "0000003D",
        "endpoint_profile":    "Apple-iPhone",
        "vlan":                "900",
        "auth_method":         "dot1x",
        "identity_store":      "GuestSponsor",
        "identity_group":      "GuestEndpoints",
        "ise_node":            "ise-psn-02.tsa.local",
        "network_device_name": "SW-JFK-07",
        "sgt":                 "6",
        "posture_status":      "Pending",
        "acct_session_time":   "180",
    },
    {
        "calling_station_id":  "B8:27:EB:AA:BB:CC",
        "user_name":           "",
        "nas_ip_address":      "10.40.1.3",
        "nas_port_id":         "GigabitEthernet1/0/45",
        "framed_ip_address":   "10.40.30.25",
        "acct_session_id":     "0000004E",
        "endpoint_profile":    "HP-JetDirect",
        "vlan":                "800",
        "auth_method":         "mab",
        "identity_store":      "Internal Endpoints",
        "identity_group":      "Printer",
        "ise_node":            "ise-psn-01.tsa.local",
        "network_device_name": "SW-ORD-03",
        "sgt":                 "100",
        "posture_status":      "Unknown",
        "acct_session_time":   "259200",
    },
]

# Auth history for first MOCK_ENDPOINT MAC (used by auth-history endpoint)
MOCK_AUTH_HISTORY: list[dict] = [
    {
        "timestamp":              "2026-05-05T08:15:00Z",
        "calling_station_id":     "A4:C3:F0:11:22:33",
        "user_name":              "jsmith@tsa.gov",
        "nas_ip_address":         "10.10.1.1",
        "network_device_name":    "SW-DCA-01",
        "identity_store":         "AD",
        "auth_policy_matched_rule": "Wired_MAB/Dot1X",
        "authz_policy_matched_rule": "Employee-Full-Access",
        "authentication_method":  "dot1x",
        "authentication_protocol": "EAP-TLS",
        "failed_reason":          "",
        "passed":                 "true",
        "vlan":                   "500",
        "dacl":                   "PERMIT_ALL",
        "sgt":                    "4",
    },
    {
        "timestamp":              "2026-05-05T07:50:00Z",
        "calling_station_id":     "A4:C3:F0:11:22:33",
        "user_name":              "jsmith@tsa.gov",
        "nas_ip_address":         "10.10.1.1",
        "network_device_name":    "SW-DCA-01",
        "identity_store":         "AD",
        "auth_policy_matched_rule": "Wired_MAB/Dot1X",
        "authz_policy_matched_rule": "Employee-Full-Access",
        "authentication_method":  "dot1x",
        "authentication_protocol": "EAP-TLS",
        "failed_reason":          "12321 PEAP failed SSL/TLS handshake",
        "passed":                 "false",
        "vlan":                   "",
        "dacl":                   "",
        "sgt":                    "",
    },
    {
        "timestamp":              "2026-05-04T17:30:00Z",
        "calling_station_id":     "A4:C3:F0:11:22:33",
        "user_name":              "jsmith@tsa.gov",
        "nas_ip_address":         "10.10.1.1",
        "network_device_name":    "SW-DCA-01",
        "identity_store":         "AD",
        "auth_policy_matched_rule": "Wired_MAB/Dot1X",
        "authz_policy_matched_rule": "Employee-Full-Access",
        "authentication_method":  "dot1x",
        "authentication_protocol": "EAP-TLS",
        "failed_reason":          "",
        "passed":                 "true",
        "vlan":                   "500",
        "dacl":                   "PERMIT_ALL",
        "sgt":                    "4",
    },
]

MOCK_AUTHZ_RULES: list[dict] = [
    {
        "id":          _uid("authz-employee"),
        "name":        "Employee-Full-Access",
        "state":       "enabled",
        "priority":    1,
        "profiles":    ["PermitAccess"],
        "securityGroup": "Employees",
        "condition":   "AD-ExternalGroups EQUALS tsa.gov/Groups/TSA-Employees",
    },
    {
        "id":          _uid("authz-contractor"),
        "name":        "Contractor-Limited",
        "state":       "enabled",
        "priority":    2,
        "profiles":    ["Contractor_Access"],
        "securityGroup": "Contractors",
        "condition":   "AD-ExternalGroups EQUALS tsa.gov/Groups/Contractors",
    },
    {
        "id":          _uid("authz-iot"),
        "name":        "IoT-Devices",
        "state":       "enabled",
        "priority":    3,
        "profiles":    ["IoT_Access"],
        "securityGroup": None,
        "condition":   "EndpointIdentityGroup EQUALS IoT_Device OR EndpointIdentityGroup EQUALS IP_Camera",
    },
    {
        "id":          _uid("authz-default"),
        "name":        "Default",
        "state":       "enabled",
        "priority":    99,
        "profiles":    ["DenyAccess"],
        "securityGroup": None,
        "condition":   "",
    },
]

MOCK_AUTHZ_PROFILES: list[dict] = [
    {
        "id": _uid("ap-permit"),     "name": "PermitAccess",
        "description": "Full network access",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "vlan": {"nameID": "500", "tagID": 0},
        "reAuthTimeout": 1800,
        "daclName": "PERMIT_ALL",
        "trackMovement": False,
    },
    {
        "id": _uid("ap-deny"),       "name": "DenyAccess",
        "description": "Block all access",
        "accessType": "ACCESS_REJECT",
        "authzProfileType": "SWITCH",
        "vlan": None,
        "reAuthTimeout": 0,
        "daclName": "DENY_ALL",
        "trackMovement": False,
    },
    {
        "id": _uid("ap-contractor"), "name": "Contractor_Access",
        "description": "Limited internet-only contractor access",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "vlan": {"nameID": "510", "tagID": 0},
        "reAuthTimeout": 3600,
        "daclName": "CONTRACTOR_ACL",
        "trackMovement": False,
    },
    {
        "id": _uid("ap-iot"),        "name": "IoT_Access",
        "description": "IoT device segmented access",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "vlan": {"nameID": "750", "tagID": 0},
        "reAuthTimeout": 86400,
        "daclName": "IOT_RESTRICTED",
        "trackMovement": False,
    },
    {
        "id": _uid("ap-webauth"),    "name": "Cisco_Web_Auth",
        "description": "Web authentication portal redirect",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "vlan": {"nameID": "999", "tagID": 0},
        "reAuthTimeout": 300,
        "daclName": None,
        "webRedirection": {"WebRedirectionType": "CentralizedWebAuth", "url": "/portal/"},
        "trackMovement": False,
    },
]

MOCK_ALLOWED_PROTOCOLS: list[dict] = [
    {
        "id": _uid("proto-default"),  "name": "Default Network Access",
        "description": "Default allowed protocols for network access",
        "processHostLookup": True,
        "allowPapAscii": False,
        "allowChap": False,
        "allowMsChapV1": False,
        "allowMsChapV2": True,
        "allowEapMd5": False,
        "allowLeap": False,
        "allowEapTls": True,
        "allowEapFast": True,
        "allowPeap": True,
        "allowEapTtls": True,
        "allowTeap": True,
    },
    {
        "id": _uid("proto-dot1x"),    "name": "Dot1X Protocols",
        "description": "802.1X EAP methods only",
        "processHostLookup": False,
        "allowEapTls": True,
        "allowEapFast": True,
        "allowPeap": True,
        "allowEapTtls": False,
        "allowTeap": True,
    },
]

MOCK_PROFILING_POLICIES: list[dict] = [
    {"id": _uid("pp-win10"),    "name": "Windows10-Workstation",  "description": "Windows 10 laptop",    "minCertaintyFactor": 20},
    {"id": _uid("pp-ios"),      "name": "Apple-iPhone",           "description": "Apple iPhone",         "minCertaintyFactor": 30},
    {"id": _uid("pp-ipad"),     "name": "Apple-iPad",             "description": "Apple iPad",           "minCertaintyFactor": 30},
    {"id": _uid("pp-phone"),    "name": "Cisco-IP-Phone",         "description": "Cisco IP Phone",       "minCertaintyFactor": 10},
    {"id": _uid("pp-camera"),   "name": "Axis-Camera",            "description": "Axis IP Camera",       "minCertaintyFactor": 20},
    {"id": _uid("pp-hp"),       "name": "HP-JetDirect",           "description": "HP network printer",   "minCertaintyFactor": 15},
    {"id": _uid("pp-android"),  "name": "Android-Device",         "description": "Android device",       "minCertaintyFactor": 25},
    {"id": _uid("pp-linux"),    "name": "Linux-Workstation",      "description": "Linux endpoint",       "minCertaintyFactor": 20},
    {"id": _uid("pp-macos"),    "name": "MacBook",                "description": "Apple macOS laptop",   "minCertaintyFactor": 25},
    {"id": _uid("pp-iot"),      "name": "Generic-IoT",            "description": "IoT/OT device",        "minCertaintyFactor": 10},
]

MOCK_SGACLS: list[dict] = [
    {
        "id": _uid("sgacl-emp-guest"),
        "name": "DENY_IP_LOG",
        "description": "Deny all IP and log",
        "aclcontent": "deny ip log",
        "ipVersion": "IP_AGNOSTIC",
        "modelledContent": None,
    },
    {
        "id": _uid("sgacl-permit"),
        "name": "PERMIT_IP",
        "description": "Permit all IP",
        "aclcontent": "permit ip",
        "ipVersion": "IP_AGNOSTIC",
        "modelledContent": None,
    },
    {
        "id": _uid("sgacl-web"),
        "name": "ALLOW_WEB",
        "description": "Allow HTTP/HTTPS only",
        "aclcontent": "permit tcp dst eq 80\npermit tcp dst eq 443\ndeny ip log",
        "ipVersion": "IP_AGNOSTIC",
        "modelledContent": None,
    },
    {
        "id": _uid("sgacl-printer"),
        "name": "ALLOW_PRINT",
        "description": "Allow printer access protocols",
        "aclcontent": "permit tcp dst eq 515\npermit tcp dst eq 9100\ndeny ip",
        "ipVersion": "IP_AGNOSTIC",
        "modelledContent": None,
    },
]

MOCK_EGRESS_MATRIX: list[dict] = [
    {
        "id": _uid("em-emp-guest"),
        "name": "Employees_to_Guests",
        "description": "Employees to Guests — deny",
        "sourceSgtId":      _uid("sgt-employees"),
        "destinationSgtId": _uid("sgt-guests"),
        "sourceSgt":        "Employees",
        "destinationSgt":   "Guests",
        "sgaclIds":         [_uid("sgacl-emp-guest")],
        "matrixCellStatus": "FINAL",
        "monitorAll":       False,
    },
    {
        "id": _uid("em-emp-printers"),
        "name": "Employees_to_Printers",
        "description": "Employees to Printers — allow print",
        "sourceSgtId":      _uid("sgt-employees"),
        "destinationSgtId": _uid("sgt-printers"),
        "sourceSgt":        "Employees",
        "destinationSgt":   "Printers",
        "sgaclIds":         [_uid("sgacl-printer")],
        "matrixCellStatus": "FINAL",
        "monitorAll":       False,
    },
    {
        "id": _uid("em-contractors-web"),
        "name": "Contractors_to_Employees",
        "description": "Contractors to Employees — web only",
        "sourceSgtId":      _uid("sgt-contractors"),
        "destinationSgtId": _uid("sgt-employees"),
        "sourceSgt":        "Contractors",
        "destinationSgt":   "Employees",
        "sgaclIds":         [_uid("sgacl-web")],
        "matrixCellStatus": "FINAL",
        "monitorAll":       False,
    },
    {
        "id": _uid("em-guest-deny"),
        "name": "Guests_to_Employees",
        "description": "Guests to Employees — deny all",
        "sourceSgtId":      _uid("sgt-guests"),
        "destinationSgtId": _uid("sgt-employees"),
        "sourceSgt":        "Guests",
        "destinationSgt":   "Employees",
        "sgaclIds":         [_uid("sgacl-emp-guest")],
        "matrixCellStatus": "FINAL",
        "monitorAll":       False,
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

# Mock Panorama IKE/IPsec inventory for the VPN Tunnels page.
MOCK_PAN_IKE_CRYPTO_PROFILES: list[dict] = [
    {
        "scope": "shared", "name": "Strong-IKE",
        "encryption": ["aes-256-cbc", "aes-128-cbc"],
        "hash": ["sha256"],
        "dh_group": ["group14"],
        "lifetime_value": "8", "lifetime_unit": "hours",
        "authentication_multiple": "0",
    },
    {
        "scope": "shared", "name": "Legacy-IKE",
        "encryption": ["3des"],
        "hash": ["sha1"],
        "dh_group": ["group2"],
        "lifetime_value": "24", "lifetime_unit": "hours",
        "authentication_multiple": "0",
    },
]

MOCK_PAN_IPSEC_CRYPTO_PROFILES: list[dict] = [
    {
        "scope": "shared", "name": "Strong-IPsec",
        "protocol": "esp",
        "encryption": ["aes-256-gcm"], "authentication": ["none"],
        "dh_group": "group14",
        "lifetime_value": "1", "lifetime_unit": "hours",
        "lifesize_value": "", "lifesize_unit": "",
    },
    {
        "scope": "shared", "name": "Legacy-IPsec",
        "protocol": "esp",
        "encryption": ["3des"], "authentication": ["sha1"],
        "dh_group": "group2",
        "lifetime_value": "1", "lifetime_unit": "hours",
        "lifesize_value": "", "lifesize_unit": "",
    },
]

MOCK_PAN_IKE_GATEWAYS: list[dict] = [
    {
        "scope": "shared", "template": "", "name": "GW-AWS-East",
        "peer_address": "54.10.20.30", "local_interface": "ethernet1/2", "local_ip": "203.0.113.5",
        "protocol": "ikev2", "ikev1_profile": "", "ikev1_mode": "",
        "ikev2_profile": "Strong-IKE", "auth": "pre-shared-key", "disabled": False,
    },
    {
        "scope": "shared", "template": "", "name": "GW-Partner-X",
        "peer_address": "198.51.100.7", "local_interface": "ethernet1/2", "local_ip": "203.0.113.5",
        "protocol": "ikev1", "ikev1_profile": "Legacy-IKE", "ikev1_mode": "main",
        "ikev2_profile": "", "auth": "pre-shared-key", "disabled": False,
    },
    {
        "scope": "shared", "template": "", "name": "GW-Branch-Disabled",
        "peer_address": "192.0.2.100", "local_interface": "ethernet1/2", "local_ip": "203.0.113.5",
        "protocol": "ikev2", "ikev1_profile": "", "ikev1_mode": "",
        "ikev2_profile": "Strong-IKE", "auth": "pre-shared-key", "disabled": True,
    },
]

MOCK_PAN_IPSEC_TUNNELS: list[dict] = [
    {
        "scope": "shared", "template": "", "name": "VPN-AWS-East",
        "tunnel_interface": "tunnel.10",
        "ike_gateway": "GW-AWS-East",
        "ipsec_profile": "Strong-IPsec",
        "proxy_ids": [
            {"name": "any", "local": "0.0.0.0/0", "remote": "0.0.0.0/0", "protocol": "any"},
        ],
        "disabled": False, "anti_replay": "yes",
    },
    {
        "scope": "shared", "template": "", "name": "VPN-Partner-X",
        "tunnel_interface": "tunnel.11",
        "ike_gateway": "GW-Partner-X",
        "ipsec_profile": "Legacy-IPsec",
        "proxy_ids": [
            {"name": "p1", "local": "10.80.0.0/16", "remote": "192.0.2.0/24", "protocol": "any"},
        ],
        "disabled": False, "anti_replay": "yes",
    },
    {
        "scope": "shared", "template": "", "name": "VPN-Branch-Disabled",
        "tunnel_interface": "tunnel.12",
        "ike_gateway": "GW-Branch-Disabled",
        "ipsec_profile": "Strong-IPsec",
        "proxy_ids": [],
        "disabled": True, "anti_replay": "yes",
    },
]

# Managed firewalls as returned by clients.panorama.get_managed_devices.
# Derived from MOCK_PAN_INTERFACES so the two views agree.
MOCK_PAN_MANAGED_DEVICES: list[dict] = [
    {
        "serial":       fw["serial"],
        "hostname":     fw["hostname"],
        "model":        fw["model"],
        "ip_address":   fw["management_ip"],
        "device_group": fw["device_group"],
        "os_version":   fw["os_version"],
        "ha_state":     fw["ha_state"],
        "ha_enabled":   fw["ha_enabled"],
    }
    for fw in MOCK_PAN_INTERFACES
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

# ── ACI Policy Mocks ─────────────────────────────────────────────────────────

MOCK_ACI_TENANTS = [
    {"fvTenant": {"attributes": {"name": "PROD", "dn": "uni/tn-PROD", "descr": "Production Tenant"}}},
    {"fvTenant": {"attributes": {"name": "DEV", "dn": "uni/tn-DEV", "descr": "Development Tenant"}}},
    {"fvTenant": {"attributes": {"name": "common", "dn": "uni/tn-common", "descr": "Shared Services"}}},
]

MOCK_ACI_VRFS = [
    {"fvCtx": {"attributes": {"name": "VRF-1", "dn": "uni/tn-PROD/ctx-VRF-1", "pcEnfPref": "enforced", "pcEnfDir": "ingress", "bdEnforcedEnable": "no"}}},
    {"fvCtx": {"attributes": {"name": "VRF-2", "dn": "uni/tn-PROD/ctx-VRF-2", "pcEnfPref": "unenforced", "pcEnfDir": "ingress", "bdEnforcedEnable": "no"}}},
    {"fvCtx": {"attributes": {"name": "VRF-1", "dn": "uni/tn-DEV/ctx-VRF-1", "pcEnfPref": "enforced", "pcEnfDir": "ingress", "bdEnforcedEnable": "no"}}},
]

MOCK_ACI_BDS = [
    {"fvBD": {"attributes": {"name": "BD-WEB", "dn": "uni/tn-PROD/BD-BD-WEB", "unicastRoute": "yes", "arpFlood": "yes", "unkMacUcastAct": "proxy", "ipLearning": "yes", "type": "regular"}, "children": [
        {"fvSubnet": {"attributes": {"ip": "10.10.10.1/24", "scope": "public", "descr": "Web Subnet"}}},
        {"fvRsCtx": {"attributes": {"tnFvCtxName": "VRF-1"}}}
    ]}},
    {"fvBD": {"attributes": {"name": "BD-DB", "dn": "uni/tn-PROD/BD-BD-DB", "unicastRoute": "yes", "arpFlood": "no", "unkMacUcastAct": "proxy", "ipLearning": "yes", "type": "regular"}, "children": [
        {"fvSubnet": {"attributes": {"ip": "10.10.20.1/24", "scope": "public", "descr": "DB Subnet"}}},
        {"fvRsCtx": {"attributes": {"tnFvCtxName": "VRF-1"}}}
    ]}},
    {"fvBD": {"attributes": {"name": "BD-TEST", "dn": "uni/tn-DEV/BD-BD-TEST", "unicastRoute": "yes", "arpFlood": "yes", "unkMacUcastAct": "proxy", "ipLearning": "yes", "type": "regular"}, "children": [
        {"fvSubnet": {"attributes": {"ip": "10.20.10.1/24", "scope": "public", "descr": "Test Subnet"}}},
        {"fvRsCtx": {"attributes": {"tnFvCtxName": "VRF-1"}}}
    ]}},
]

MOCK_ACI_APP_PROFILES = [
    {"fvAp": {"attributes": {"name": "APP1", "dn": "uni/tn-PROD/ap-APP1"}, "children": [{"moCount": {"attributes": {"count": "2"}}}]}},
    {"fvAp": {"attributes": {"name": "APP1", "dn": "uni/tn-DEV/ap-APP1"}, "children": [{"moCount": {"attributes": {"count": "1"}}}]}},
]

MOCK_ACI_CONTRACTS = [
    {"vzBrCP": {"attributes": {"name": "WEB-to-DB", "dn": "uni/tn-PROD/brc-WEB-to-DB", "scope": "context"}, "children": [
        {"vzSubj": {"attributes": {"name": "Web-Subj", "revFltPorts": "yes", "consMatchT": "AtleastOne", "provMatchT": "AtleastOne"}, "children": [
            {"vzRsSubjFiltAtt": {"attributes": {"tnVzFilterName": "ALLOW-HTTPS"}}}
        ]}}
    ]}}
]

MOCK_ACI_FILTERS = [
    {"vzFilter": {"attributes": {"name": "ALLOW-HTTPS", "dn": "uni/tn-PROD/flt-ALLOW-HTTPS"}, "children": [
        {"vzEntry": {"attributes": {"name": "tcp443", "etherT": "ip", "prot": "tcp", "dFromPort": "443", "dToPort": "443", "sFromPort": "unspecified", "sToPort": "unspecified", "stateful": "yes", "applyToFrag": "no"}}}
    ]}}
]

MOCK_ACI_FV_RSPROV = [
    {"fvRsProv": {"attributes": {"dn": "uni/tn-PROD/ap-APP1/epg-WEB/rsprov-WEB-to-DB", "tDn": "uni/tn-PROD/brc-WEB-to-DB", "tnVzBrCPName": "WEB-to-DB"}}}
]

MOCK_ACI_FV_RSCONS = [
    {"fvRsCons": {"attributes": {"dn": "uni/tn-PROD/ap-APP1/epg-DB/rscons-WEB-to-DB", "tDn": "uni/tn-PROD/brc-WEB-to-DB", "tnVzBrCPName": "WEB-to-DB"}}}
]

MOCK_ACI_ACCESS_PG = [
    {"infraAccPortGrp": {"attributes": {"name": "PG-Server-Access", "dn": "uni/infra/funcprof/accportgrp-PG-Server-Access"}, "children": [
        {"infraRsCdpIfPol": {"attributes": {"tnCdpIfPolName": "CDP-ON"}}},
        {"infraRsLldpIfPol": {"attributes": {"tnLldpIfPolName": "LLDP-ENABLED"}}},
        {"infraRsAttEntP": {"attributes": {"tnInfraAttEntityPName": "AAEP-PROD"}}}
    ]}}
]

MOCK_ACI_BUNDLE_PG = [
    {"infraAccBndlGrp": {"attributes": {"name": "PG-Server-VPC", "dn": "uni/infra/funcprof/accbundle-PG-Server-VPC", "lagT": "node"}, "children": [
        {"infraRsLacpPol": {"attributes": {"tnLacpLagPolName": "LACP-ACTIVE"}}},
        {"infraRsHIfPol": {"attributes": {"tnFabricHIfPolName": "10G-AUTO"}}},
        {"infraRsAttEntP": {"attributes": {"tnInfraAttEntityPName": "AAEP-PROD"}}}
    ]}}
]

MOCK_ACI_AAEPS = [
    {"infraAttEntityP": {"attributes": {"name": "AAEP-PROD", "dn": "uni/infra/attentp-AAEP-PROD"}, "children": [
        {"infraRsDomP": {"attributes": {"tDn": "uni/phys-PHYS-DOM"}}},
        {"infraGeneric": {"children": [
            {"infraRsFuncToEpg": {"attributes": {"tDn": "uni/tn-PROD/ap-APP1/epg-WEB", "encap": "vlan-100", "mode": "regular"}}}
        ]}}
    ]}}
]

MOCK_ACI_PHYS_DOMAINS = [
    {"physDomP": {"attributes": {"name": "PHYS-DOM", "dn": "uni/phys-PHYS-DOM"}, "children": [
        {"infraRsVlanNs": {"attributes": {"tDn": "uni/infra/vlanns-[VLAN-POOL-PROD]-static"}}}
    ]}}
]

MOCK_ACI_L3_DOMAINS = [
    {"l3extDomP": {"attributes": {"name": "L3-DOM", "dn": "uni/l3dom-L3-DOM"}}}
]

MOCK_ACI_VMM_DOMAINS = [
    {"vmmDomP": {"attributes": {"name": "VC1", "dn": "uni/vmmp-VMware/dom-VC1"}}}
]

MOCK_ACI_VLAN_POOLS = [
    {"fvnsVlanInstP": {"attributes": {"name": "VLAN-POOL-PROD", "dn": "uni/infra/vlanns-[VLAN-POOL-PROD]-static", "allocMode": "static"}, "children": [
        {"fvnsEncapBlk": {"attributes": {"from": "vlan-100", "to": "vlan-200", "role": "external"}}}
    ]}}
]

MOCK_ACI_CDP_POLS = [{"cdpIfPol": {"attributes": {"name": "CDP-ON", "dn": "uni/infra/cdpIfP-CDP-ON", "adminSt": "enabled"}}}]
MOCK_ACI_LLDP_POLS = [{"lldpIfPol": {"attributes": {"name": "LLDP-ENABLED", "dn": "uni/infra/lldpIfP-LLDP-ENABLED", "adminRxSt": "enabled", "adminTxSt": "enabled"}}}]
MOCK_ACI_LACP_POLS = [{"lacpLagPol": {"attributes": {"name": "LACP-ACTIVE", "dn": "uni/infra/lacpLagP-LACP-ACTIVE", "mode": "active", "ctrl": "fast-sel-hot-stdby"}}}]
MOCK_ACI_LINK_POLS = [{"fabricHIfPol": {"attributes": {"name": "10G-AUTO", "dn": "uni/infra/hintfpol-10G-AUTO", "speed": "10G", "autoNeg": "on", "fecMode": "inherit"}}}]
MOCK_ACI_MCP_POLS = [{"mcpIfPol": {"attributes": {"name": "MCP-ENABLED", "dn": "uni/infra/mcpIfP-MCP-ENABLED", "adminSt": "enabled"}}}]
MOCK_ACI_STP_POLS = [{"stpIfPol": {"attributes": {"name": "BPDU-GUARD", "dn": "uni/infra/stpIfPol-BPDU-GUARD", "ctrl": "bpdu-guard"}}}]
MOCK_ACI_L2_POLS = [{"l2IfPol": {"attributes": {"name": "L2-DEFAULT", "dn": "uni/infra/l2IfP-L2-DEFAULT", "qinq": "disabled", "vlanScope": "global"}}}]
MOCK_ACI_STORMCTRL_POLS = [{"stormctrlIfPol": {"attributes": {"name": "STORM-DEFAULT", "dn": "uni/infra/stormctrlIfPol-STORM-DEFAULT", "bcRate": "10.0", "mcRate": "10.0", "uucRate": "10.0"}}}]

MOCK_ACI_ACCESS_TOPOLOGY = [
    # Node Profile
    {"infraNodeP": {"attributes": {"name": "Leaf101-102", "dn": "uni/infra/nprof-Leaf101-102"}}},
    {"infraLeafS": {"attributes": {"name": "Leaf101-102-Sel", "dn": "uni/infra/nprof-Leaf101-102/leaves-Leaf101-102-Sel-typ-range"}}},
    {"infraNodeBlk": {"attributes": {"name": "blk1", "dn": "uni/infra/nprof-Leaf101-102/leaves-Leaf101-102-Sel-typ-range/nodeblk-blk1", "from_": "101", "to_": "102"}}},
    {"infraRsAccPortP": {"attributes": {"dn": "uni/infra/nprof-Leaf101-102/rsaccPortP-[uni/infra/accportprof-IPROF-VPC]", "tDn": "uni/infra/accportprof-IPROF-VPC"}}},
    # Interface Profile
    {"infraAccPortP": {"attributes": {"name": "IPROF-VPC", "dn": "uni/infra/accportprof-IPROF-VPC"}}},
    {"infraHPortS": {"attributes": {"name": "Port15-16", "dn": "uni/infra/accportprof-IPROF-VPC/hports-Port15-16-typ-range"}}},
    {"infraPortBlk": {"attributes": {"name": "blk1", "dn": "uni/infra/accportprof-IPROF-VPC/hports-Port15-16-typ-range/portblk-blk1", "fromCard": "1", "toCard": "1", "fromPort": "15", "toPort": "16"}}},
    {"infraRsAccBaseGrp": {"attributes": {"dn": "uni/infra/accportprof-IPROF-VPC/hports-Port15-16-typ-range/rsaccBaseGrp", "tDn": "uni/infra/funcprof/accbundle-PG-Server-VPC"}}},
]

MOCK_ACI_URIBV4_ROUTES = [
    {
        "uribv4Route": {
            "attributes": {"prefix": "10.100.1.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.100.1.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "10.255.0.1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.100.1.0/24]/nh-[10.255.0.1]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "10.100.3.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.100.3.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "10.255.0.1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.100.3.0/24]/nh-[10.255.0.1]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "10.100.1.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-102/sys/uribv4/dom-default/rt-[10.100.1.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "10.255.0.2", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-102/sys/uribv4/dom-default/rt-[10.100.1.0/24]/nh-[10.255.0.2]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "192.168.50.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[192.168.50.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "10.250.0.5", "pref": "110", "routeType": "ospf-intra", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[192.168.50.0/24]/nh-[10.250.0.5]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "8.8.8.8/32", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[8.8.8.8/32]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "10.255.0.254", "pref": "1", "routeType": "static", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[8.8.8.8/32]/nh-[10.255.0.254]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "10.255.0.252/30", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.255.0.252/30]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "0.0.0.0", "pref": "0", "routeType": "direct", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[10.255.0.252/30]/nh-[0.0.0.0]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "44.44.44.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[44.44.44.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "1.1.1.1", "pref": "115", "routeType": "isis", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[44.44.44.0/24]/nh-[1.1.1.1]"}}}
            ]
        }
    },
    {
        "uribv4Route": {
            "attributes": {"prefix": "172.16.99.0/24", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[172.16.99.0/24]"},
            "children": [
                {"uribv4Nexthop": {"attributes": {"addr": "172.16.99.1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/sys/uribv4/dom-default/rt-[172.16.99.0/24]/nh-[172.16.99.1]"}}}
            ]
        }
    }
]

MOCK_ACI_URIBV6_ROUTES = [
    {
        "uribv6Route": {
            "attributes": {"prefix": "2001:db8::/32", "modTs": "2026-04-26T14:32:11.000Z", "dn": "topology/pod-1/node-101/sys/uribv6/dom-default/rt-[2001:db8::/32]"},
            "children": [
                {"uribv6Nexthop": {"attributes": {"addr": "2001:db8::1", "pref": "20", "routeType": "bgp", "dn": "topology/pod-1/node-101/sys/uribv6/dom-default/rt-[2001:db8::/32]/nh-[2001:db8::1]"}}}
            ]
        }
    }
]

MOCK_ACI_OSPF_ADJ_EP = [
    {
        "ospfAdjEp": {
            "attributes": {
                "dn": "topology/pod-1/node-101/sys/ospf/inst/dom-default/if-[eth1/49]/adj-[10.250.0.5]",
                "addr": "10.250.0.5",
                "operSt": "full"
            }
        }
    }
]

MOCK_ACI_L3EXT_RS_ECTX = [
    {"l3extRsEctx": {"attributes": {"dn": "uni/tn-COMMON/out-L3OUT-CORE/rsectx", "tDn": "uni/tn-COMMON/ctx-default"}}},
    {"l3extRsEctx": {"attributes": {"dn": "uni/tn-COMMON/out-L3OUT-SHARED/rsectx", "tDn": "uni/tn-COMMON/ctx-default"}}}
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

def generate_large_ipam_tree() -> dict:
    """Generates a synthetic IPAM tree with ~10,000 nodes for performance testing."""

    def _node(cidr, display_name, site, role="subnet", itype="physical", source="Aggregated"):
        return {
            "cidr": cidr,
            "display_name": display_name,
            "site": site,
            "device": "N/A" if role == "subnet" else f"DEV-{site}-01",
            "source": source,
            "role": role,
            "interface_type": itype,
            "conflicts": [],
            "overlaps": [],
            "children": []
        }

    ipv4_roots = []
    # 10.0.0.0/8 root
    root = _node("10.0.0.0/8", "Internal Network", "Global")
    ipv4_roots.append(root)

    for i in range(128):  # 128 x /16s
        v16_cidr = f"10.{i}.0.0/16"
        site_name = f"SITE-{i:03d}"
        v16_node = _node(v16_cidr, f"Data Center {i}", site_name)
        root["children"].append(v16_node)

        for j in range(35):  # ~40 x /24s per /16
            v24_cidr = f"10.{i}.{j}.0/24"
            v24_node = _node(v24_cidr, f"VLAN {j+100}", site_name, itype="svi")
            v16_node["children"].append(v24_node)

            # Add some endpoints and groups to every 5th /24
            if j % 5 == 0:
                # Tunnel Group
                tg = _node(v24_cidr, f"Tunnels in {site_name}", site_name, role="tunnel_group", itype="tunnel")
                v24_node["children"].append(tg)
                for k in range(3):
                    ep = _node(v24_cidr, f"Tunnel{k}", site_name, role="endpoint", itype="tunnel")
                    ep["host_ip"] = f"10.{i}.{j}.{k+1}"
                    tg["children"].append(ep)

                # Loopback Group
                lg = _node(v24_cidr, "Collapsed Loopbacks", site_name, role="loopback_group", itype="loopback")
                v24_node["children"].append(lg)
                for k in range(5):
                    lb = _node(f"10.{i}.{j}.{k+10}/32", f"Loopback{k}", site_name, role="host_route", itype="loopback")
                    lb["host_ip"] = f"10.{i}.{j}.{k+10}"
                    lg["children"].append(lb)

    # Add a few more supernets
    ipv4_roots.append(_node("172.16.0.0/12", "DMZ Space", "External", source="Panorama"))
    ipv4_roots.append(_node("192.168.0.0/16", "Legacy Branch Space", "Branch", source="Nexus"))

    return {
        "ipv4": ipv4_roots,
        "ipv6": [
            {
                "cidr": "2001:db8::/32",
                "display_name": "Documentation Prefix",
                "role": "subnet",
                "interface_type": "physical",
                "site": "Global",
                "source": "Aggregated",
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

    seed_cache is itself called from FastAPI's async lifespan, so we run the
    loop in a worker thread to avoid the "loop already running" RuntimeError.
    """
    import asyncio
    import threading
    from utils.ipam_engine import IPAMEngine

    result: dict = {}
    error: list = []

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            engine = IPAMEngine()
            loop.run_until_complete(engine._discover_dnac(None, loop))
            loop.run_until_complete(engine._discover_dnac_summaries(None, loop))
            loop.run_until_complete(engine._discover_dnac_iface_v6(None, loop))
            loop.run_until_complete(engine._discover_dnac_pools(None, loop))
            loop.run_until_complete(engine._discover_nexus(None, None))
            loop.run_until_complete(engine._discover_panorama(None, None))
            loop.run_until_complete(engine._discover_f5(None, None))
            engine.build_tree()
            result.update(engine.get_tree())
        except Exception as e:
            error.append(e)
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()

    if error:
        raise error[0]
    return result


def seed_cache(cache) -> None:
    """Pre-populate the in-memory cache with mock data for all UI-facing endpoints."""
    from cache import IPAM_TREE_CACHE_KEY
    LONG = 86400 * 365  # 1 year — mock data never expires

    # DNAC — use LONG for everything; the seed runs on every restart anyway
    # and prod TTLs (TTL_DEVICES/TTL_SITES = 4h) make the dev cache widget
    # go red while the mock data is still perfectly valid.
    cache.set("devices",         MOCK_DEVICES,          LONG)
    cache.set("sites",           MOCK_SITES,            LONG)
    cache.set("device_site_map", MOCK_DEVICE_SITE_MAP,  LONG)
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
    cache.set("ise_sgacls",          MOCK_SGACLS,             LONG)
    cache.set("ise_egress_matrix",   MOCK_EGRESS_MATRIX,      LONG)
    cache.set("ise_policy_sets",     MOCK_POLICY_SETS,      LONG)
    cache.set("ise_authz_profiles",  MOCK_AUTHZ_PROFILES,     LONG)
    cache.set("ise_allowed_protocols", MOCK_ALLOWED_PROTOCOLS,  LONG)
    cache.set("ise_profiling_policies", MOCK_PROFILING_POLICIES, LONG)
    cache.set("ise_deployment_nodes", MOCK_DEPLOYMENT_NODES, LONG)

    # MOCK_AUTHZ_RULES seeded per policy set:
    for ps in MOCK_POLICY_SETS:
        cache.set(f"ise_authz_rules_{ps['id']}", MOCK_AUTHZ_RULES, LONG)

    # ISE auth rules for each mock policy set
    for ps in MOCK_POLICY_SETS:
        cache.set(f"ise_auth_rules_{ps['id']}", MOCK_AUTH_RULES, LONG)

    # ISE status
    cache.set("status_ise", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # Panorama / Firewall
    cache.set("pan_rules",            MOCK_PAN_RULES_CACHE,     LONG)
    cache.set("pan_device_groups",    MOCK_DEVICE_GROUPS,       LONG)
    cache.set("pan_managed_devices",  MOCK_PAN_MANAGED_DEVICES, LONG)
    cache.set("pan_address_objects",  MOCK_ADDRESS_OBJECTS,     LONG)
    cache.set("pan_services",         MOCK_SERVICES,            LONG)
    cache.set("pan_interfaces",       MOCK_PAN_INTERFACES,      LONG)

    # Panorama IKE/IPsec — for the VPN Tunnels page
    cache.set("pan_ike_gateways",          MOCK_PAN_IKE_GATEWAYS,          LONG)
    cache.set("pan_ipsec_tunnels",         MOCK_PAN_IPSEC_TUNNELS,         LONG)
    cache.set("pan_ike_crypto_profiles",   MOCK_PAN_IKE_CRYPTO_PROFILES,   LONG)
    cache.set("pan_ipsec_crypto_profiles", MOCK_PAN_IPSEC_CRYPTO_PROFILES, LONG)

    # Panorama status
    cache.set("status_panorama", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # ACI — keys are namespaced per fabric (aci_{fabric_id}_{suffix}).
    # Seed every configured fabric with the same mock dataset so the cache
    # widget and per-fabric pages are green from startup.
    import clients.aci_registry as reg
    aci_fabric_data = {
        "nodes":           {"imdata": MOCK_ACI_NODES},
        "l3outs":          {"imdata": MOCK_ACI_L3OUTS},
        "bgp_peers":       {"imdata": MOCK_ACI_BGP_PEERS},
        "bgp_peer_cfg":    {"imdata": MOCK_ACI_BGP_PEER_CFG},
        "subnets":         {"imdata": MOCK_ACI_SUBNETS},
        "epgs":            {"imdata": MOCK_ACI_EPGS},
        "faults":          {"imdata": MOCK_ACI_FAULT_INST},
        "bgp_doms_all":    {"imdata": MOCK_ACI_BGP_DOMS_ALL},
        "bgp_adj_rib_out": {"imdata": MOCK_ACI_BGP_ADJ_RIB_OUT},
        "bgp_adj_rib_in":  {"imdata": MOCK_ACI_BGP_ADJ_RIB_IN},
        "health_overall":  {"imdata": MOCK_ACI_HEALTH_OVERALL},
        "health_tenants":  {"imdata": MOCK_ACI_HEALTH_TENANTS},
        "health_pods":     {"imdata": MOCK_ACI_HEALTH_PODS},
        "uribv4_routes":   {"imdata": MOCK_ACI_URIBV4_ROUTES},
        "uribv6_routes":   {"imdata": MOCK_ACI_URIBV6_ROUTES},
        "ospf_adj_ep":     {"imdata": MOCK_ACI_OSPF_ADJ_EP},
        "l3ext_rs_ectx":   {"imdata": MOCK_ACI_L3EXT_RS_ECTX},
        "tenants":         {"imdata": MOCK_ACI_TENANTS},
        "vrfs":            {"imdata": MOCK_ACI_VRFS},
        "bridge_domains":  {"imdata": MOCK_ACI_BDS},
        "app_profiles":    {"imdata": MOCK_ACI_APP_PROFILES},
        "contracts":       {"imdata": MOCK_ACI_CONTRACTS},
        "filters":         {"imdata": MOCK_ACI_FILTERS},
        "epg_relations":   {"prov": {"imdata": MOCK_ACI_FV_RSPROV},
                            "cons": {"imdata": MOCK_ACI_FV_RSCONS}},
        "access_pgs":      {"access": {"imdata": MOCK_ACI_ACCESS_PG},
                            "bundle": {"imdata": MOCK_ACI_BUNDLE_PG}},
        "aaeps":           {"imdata": MOCK_ACI_AAEPS},
        "domains":         {"physical": {"imdata": MOCK_ACI_PHYS_DOMAINS},
                            "l3": {"imdata": MOCK_ACI_L3_DOMAINS},
                            "vmm": {"imdata": MOCK_ACI_VMM_DOMAINS}},
        "vlan_pools":      {"imdata": MOCK_ACI_VLAN_POOLS},
        "if_pol_cdp":       {"imdata": MOCK_ACI_CDP_POLS},
        "if_pol_lldp":      {"imdata": MOCK_ACI_LLDP_POLS},
        "if_pol_lacp":      {"imdata": MOCK_ACI_LACP_POLS},
        "if_pol_link":      {"imdata": MOCK_ACI_LINK_POLS},
        "if_pol_mcp":       {"imdata": MOCK_ACI_MCP_POLS},
        "if_pol_stp":       {"imdata": MOCK_ACI_STP_POLS},
        "if_pol_l2":        {"imdata": MOCK_ACI_L2_POLS},
        "if_pol_stormctrl": {"imdata": MOCK_ACI_STORMCTRL_POLS},
        "access_topology":  {"imdata": MOCK_ACI_ACCESS_TOPOLOGY},
    }
    for f in reg.list_fabrics():
        for suffix, value in aci_fabric_data.items():
            cache.set(f"aci_{f.id}_{suffix}", value, LONG)

    cache.set("status_aci", {"ok": True, "detail": "Connected (mock)"}, LONG)

    # Nexus (seed source caches BEFORE computing the IPAM tree below)
    cache.set("nexus_inventory",     MOCK_NEXUS_DEVICES,        LONG)
    cache.set("nexus_interfaces",    MOCK_NEXUS_INTERFACES,     LONG)
    cache.set("nexus_port_channels", MOCK_NEXUS_PORT_CHANNELS,  LONG)
    cache.set("nexus_vpcs",          MOCK_NEXUS_VPCS,           LONG)
    cache.set("nexus_vlans",         MOCK_NEXUS_VLANS,          LONG)

    # F5 (seed source caches BEFORE computing the IPAM tree below)
    cache.set("f5_inventory",  MOCK_F5_DEVICES,    LONG)
    cache.set("f5_self_ips",   MOCK_F5_SELF_IPS,   LONG)
    cache.set("f5_vlans",      MOCK_F5_VLANS,      LONG)
    cache.set("f5_interfaces", MOCK_F5_INTERFACES, LONG)
    cache.set("f5_virtuals",   MOCK_F5_VIRTUALS,   LONG)
    cache.set("f5_pools",      MOCK_F5_POOLS,      LONG)
    cache.set("f5_nodes",      MOCK_F5_NODES,      LONG)
    cache.set("f5_routes",     MOCK_F5_ROUTES,     LONG)

    # DNAC device configs — keyed by device id, consumed by both the EIGRP
    # summary discovery and the IPv6-from-configs discovery. Includes routers
    # AND switches (must be seeded before _build_ipam_tree_from_mocks runs).
    cache.set(
        "dnac_device_configs",
        {dev["id"]: MOCK_CONFIGS[dev["id"]]
         for dev in MOCK_DEVICES
         if dev.get("family") in ("Routers", "Switches and Hubs")},
        LONG,
    )

    # DNAC IP pools — global and per-site reserved subpools. Where the
    # authoritative IPv6 allocations actually live.
    cache.set("dnac_global_pools",     MOCK_DNAC_GLOBAL_POOLS,     LONG)
    cache.set("dnac_reserve_subpools", MOCK_DNAC_RESERVE_SUBPOOLS, LONG)

    # IPAM — compute the tree from the same source caches the live engine
    # consumes, so initial render matches what Refresh Discovery would produce.
    # Falls back to the static MOCK_IPAM_TREE if the engine can't run.
    if DEV_IPAM_LARGE:
        cache.set(IPAM_TREE_CACHE_KEY, generate_large_ipam_tree(), LONG)
    else:
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

def _mock_dnac_config(dev: dict) -> str:
    """Build a mock IOS-XE running-config for a DNAC device.
    Routers (family='Routers') get a named-mode EIGRP block with a per-site
    summary-address advertised on Tunnel5000, so the IPAM summary discovery
    has something to chew on in DEV_MODE. Both routers and switches get an
    ipv6 address on the uplink interface so the IPv6-from-configs source
    has data too.
    """
    site = MOCK_DEVICE_SITE_MAP.get(dev["id"], "")
    site_octet = next((int(p.split(".")[1]) for s, p in _SITES if s == site), 99)
    last_octet = int(dev["managementIpAddress"].rsplit(".", 1)[1])
    base = f"""!
hostname {dev['hostname']}
!
interface GigabitEthernet0/1
 description Primary Uplink
 ip address {dev['managementIpAddress']} 255.255.255.0
 ipv6 address 2001:db8:{site_octet:x}:ce0::{last_octet:x}/64
 speed 1000
 duplex full
!
interface Loopback0
 ipv6 address 2001:db8:99:ce0::{last_octet:x}/128
!
snmp-server community TSA-RO RO
snmp-server community TSA-RW RW
!
router eigrp 1
 network {dev['managementIpAddress'].rsplit('.', 1)[0]}.0 0.0.0.255
!
"""
    if dev.get("family") == "Routers":
        site = MOCK_DEVICE_SITE_MAP.get(dev["id"], "")
        # _SITES maps site -> "10.NN" prefix; advertise that as a /16 summary.
        site_prefix = next((p for s, p in _SITES if s == site), None)
        if site_prefix:
            base += f"""!
router eigrp TSA-EIGRP
 !
 address-family ipv4 unicast autonomous-system 22
  !
  af-interface Tunnel5000
   summary-address {site_prefix}.0.0 255.255.0.0
   authentication mode md5
   authentication key-chain RoutePW
  exit-af-interface
  !
  topology base
  exit-af-topology
 exit-address-family
!
"""
        base += _mock_ipsec_block(dev)
    return base + "end\n"


_DMVPN_HUB_MGMT_IP = "10.10.5.1"   # first router in DCA-HQ — the DMVPN hub
_DMVPN_HUB_OVERLAY = "172.16.0.1"  # hub's tunnel100 IP
_SVTI_PEER         = "203.0.113.42"  # mock partner WAN endpoint
_LEGACY_PEER       = "198.51.100.7"  # mock legacy IKEv1 partner


def _mock_ipsec_block(dev: dict) -> str:
    """Inject IPsec config into router mock configs so the tunnel inventory
    page has realistic data in DEV_MODE.

    All routers share the same crypto material. The router at 10.10.5.1
    plays hub (DMVPN hub-template, sVTI to partner, crypto-map example);
    every other router is a DMVPN spoke pointing to that hub.
    """
    mgmt_ip = dev.get("managementIpAddress", "")
    is_hub = mgmt_ip == _DMVPN_HUB_MGMT_IP
    last_octet = int(mgmt_ip.rsplit(".", 1)[1]) if "." in mgmt_ip else 1
    site = MOCK_DEVICE_SITE_MAP.get(dev["id"], "")
    site_octet = next((int(p.split(".")[1]) for s, p in _SITES if s == site), 99)

    # Spoke overlay IP — give each spoke a unique /24 slot in 172.16.0.0/16
    overlay_octet3 = (site_octet // 10) % 256
    overlay_octet4 = last_octet
    spoke_overlay = f"172.16.{overlay_octet3}.{overlay_octet4}"

    common = """!
crypto ikev2 proposal STRONG-IKE2
 encryption aes-cbc-256 aes-cbc-192 aes-cbc-128
 integrity sha384 sha256
 group 19 14
!
crypto ikev2 policy WAN-POL
 proposal STRONG-IKE2
!
crypto ikev2 keyring TSA-KR
 peer ANY
  address 0.0.0.0 0.0.0.0
  pre-shared-key local SECRET
  pre-shared-key remote SECRET
 !
!
crypto ikev2 profile WAN-PROFILE
 match identity remote address 0.0.0.0
 authentication local pre-share
 authentication remote pre-share
 keyring local TSA-KR
!
crypto ipsec transform-set TSA-TS esp-aes 256 esp-sha256-hmac
 mode tunnel
!
crypto ipsec profile DMVPN-PROFILE
 set transform-set TSA-TS
 set pfs group14
 set ikev2-profile WAN-PROFILE
 set security-association lifetime seconds 3600
!
crypto ipsec profile SVTI-PROFILE
 set transform-set TSA-TS
 set ikev2-profile WAN-PROFILE
!
"""

    if is_hub:
        return common + f"""!
interface Tunnel100
 description DMVPN Hub overlay
 ip address {_DMVPN_HUB_OVERLAY} 255.255.0.0
 no ip redirects
 ip nhrp authentication TSA-NHRP
 ip nhrp network-id 100
 ip nhrp map multicast dynamic
 ip nhrp redirect
 tunnel source GigabitEthernet0/1
 tunnel mode gre multipoint
 tunnel key 100
 tunnel protection ipsec profile DMVPN-PROFILE
!
interface Tunnel200
 description sVTI to TSA Partner
 ip address 10.255.255.{last_octet} 255.255.255.252
 tunnel source GigabitEthernet0/1
 tunnel destination {_SVTI_PEER}
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile SVTI-PROFILE
!
ip access-list extended LEGACY-IPSEC-ACL
 permit ip 10.10.0.0 0.0.255.255 192.0.2.0 0.0.0.255
!
crypto isakmp policy 10
 encryption aes 256
 hash sha
 authentication pre-share
 group 14
 lifetime 28800
!
crypto isakmp key LEGACYSECRET address {_LEGACY_PEER}
!
crypto ipsec transform-set LEGACY-TS esp-aes 256 esp-sha-hmac
!
crypto map LEGACY-MAP 10 ipsec-isakmp
 description Partner VPN (IKEv1)
 set peer {_LEGACY_PEER}
 set transform-set LEGACY-TS
 set pfs group2
 match address LEGACY-IPSEC-ACL
!
interface GigabitEthernet0/2
 description WAN to legacy partner
 ip address 198.51.100.{last_octet} 255.255.255.0
 crypto map LEGACY-MAP
!
"""

    # Spoke
    return common + f"""!
interface Tunnel100
 description DMVPN Spoke overlay
 ip address {spoke_overlay} 255.255.0.0
 no ip redirects
 ip nhrp authentication TSA-NHRP
 ip nhrp network-id 100
 ip nhrp nhs {_DMVPN_HUB_OVERLAY}
 ip nhrp map {_DMVPN_HUB_OVERLAY} {_DMVPN_HUB_MGMT_IP}
 ip nhrp shortcut
 tunnel source GigabitEthernet0/1
 tunnel mode gre multipoint
 tunnel key 100
 tunnel protection ipsec profile DMVPN-PROFILE
!
"""


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
        dev["id"]: _mock_dnac_config(dev)
        for dev in MOCK_DEVICES
    }
}

def get_mock_config(device_id):
    return MOCK_CONFIGS.get(device_id, "! No config found")
