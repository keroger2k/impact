import logging
import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set, Tuple
import netaddr
from cache import cache, IPAM_TREE_CACHE_KEY
import auth as auth_module
import clients.aci as aci_client_mod

logger = logging.getLogger(__name__)

# Well-known non-allocation ranges to exclude from IPAM tree.
# 192.168.0.0/16 is NOT excluded — it's legitimate RFC1918 space in active use
# across this network (tunnels, loopbacks, SVIs, physical links).
EXCLUDED_RANGES = [
    netaddr.IPNetwork("169.254.0.0/16"),     # APIPA
    netaddr.IPNetwork("127.0.0.0/8"),        # v4 Loopback
    netaddr.IPNetwork("0.0.0.0/8"),          # This-network
    netaddr.IPNetwork("224.0.0.0/4"),        # v4 Multicast
    netaddr.IPNetwork("255.255.255.255/32"), # Broadcast
    netaddr.IPNetwork("::1/128"),            # v6 Loopback
    netaddr.IPNetwork("fe80::/10"),          # v6 Link-local
    netaddr.IPNetwork("ff00::/8"),           # v6 Multicast
]

# RFC1918 aggregate supernets synthesized as tree roots when descendants exist
# but the supernet itself isn't reported by any source — keeps e.g. 172.17.x.x
# nested under 172.16.0.0/12 instead of dangling at top level.
RFC1918_SUPERNETS = [
    netaddr.IPNetwork("10.0.0.0/8"),
    netaddr.IPNetwork("172.16.0.0/12"),
    netaddr.IPNetwork("192.168.0.0/16"),
]

# Regex patterns for interfaces/links to exclude (HA, keepalives, etc.)
HA_PATTERNS = re.compile(r"KEEPALIVE|FAILOVER|HA-LINK|HEARTBEAT", re.IGNORECASE)

def classify_interface(name: str | None, cidr: netaddr.IPNetwork) -> Tuple[str, Optional[int]]:
    """
    Classifies an interface and extracts VLAN ID if applicable.
    Returns (interface_type, vlan_id).
    Types: physical, tunnel, loopback, svi, vip, p2p, management, unknown.
    """
    name_str = (name or "").strip()

    # 1. Tunnel match
    if re.match(r"^(Tu|Tunnel)[\d/\.]+", name_str, re.IGNORECASE):
        return "tunnel", None

    # 2. Loopback match (including /32 or /128 override)
    if re.match(r"^(Lo|Loopback)\d+", name_str, re.IGNORECASE):
        return "loopback", None

    if cidr.prefixlen == (32 if cidr.version == 4 else 128):
        return "loopback", None

    # 3. SVI match
    svi_match = re.match(r"^(Vl|Vlan)(\d+)", name_str, re.IGNORECASE)
    if svi_match:
        return "svi", int(svi_match.group(2))

    # 4. Management match
    if "mgmt" in name_str.lower() or "management" in name_str.lower() or re.match(r"^Ma\d", name_str, re.IGNORECASE):
        return "management", None

    # 5. P2P transit match
    if (cidr.version == 4 and cidr.prefixlen in [30, 31]) or (cidr.version == 6 and cidr.prefixlen == 127):
        return "p2p", None

    # 6. Default
    if name_str:
        return "physical", None

    return "unknown", None

class IPAMNode:
    def __init__(self, cidr: str, source: str = "Unknown"):
        self.cidr = cidr
        self.source = source
        self.network = netaddr.IPNetwork(cidr)
        self.version = self.network.version
        self.prefixlen = self.network.prefixlen
        self.ip_int = int(self.network.network)
        self.display_name = ""
        self.site = "Unknown"
        self.device = ""
        self.logical_container = ""
        self.children_nodes: List['IPAMNode'] = []
        self.conflicts: List[str] = []
        self.overlaps: List[str] = []

        # New fields
        self.interface_type = "unknown"
        self.interface_name: Optional[str] = None
        self.host_ip: Optional[str] = None
        self.vlan_id: Optional[int] = None
        self.role = "subnet" # subnet, endpoint, tunnel_group, host_route, vip

    def to_dict(self) -> Dict:
        return {
            "cidr": self.cidr or "",
            "source": self.source or "Unknown",
            "display_name": self.display_name or "",
            "site": self.site or "Unknown",
            "device": self.device or "",
            "logical_container": self.logical_container or "",
            "conflicts": self.conflicts or [],
            "overlaps": self.overlaps or [],
            "interface_type": self.interface_type,
            "interface_name": self.interface_name,
            "host_ip": self.host_ip,
            "vlan_id": self.vlan_id,
            "role": self.role,
            "children": []
        }

class IPAMEngine:
    def __init__(self):
        self.subnets: List[IPAMNode] = []
        self.tree: Dict[str, List[Dict]] = {"ipv4": [], "ipv6": []}
        self.source_map = {
            "aci":       self._discover_aci,
            "dnac":      self._discover_dnac,
            "nexus":     self._discover_nexus,
            "panorama":  self._discover_panorama,
        }

    def is_excluded(self, net: netaddr.IPNetwork, name: str = "", desc: str = "") -> bool:
        """Return True if the network or interface matches exclusion criteria."""
        # Check excluded ranges
        for ex in EXCLUDED_RANGES:
            if net in ex:
                return True

        # Check HA patterns
        if HA_PATTERNS.search(name) or HA_PATTERNS.search(desc):
            return True
        return False

    async def discover_all(self, session, loop, sources: Optional[List[str]] = None, yield_progress=None):
        """Aggregate data from sources. If sources is None, discover all."""
        self.subnets = []

        active_sources = sources if sources else list(self.source_map.keys())

        async def emit(msg):
            if yield_progress:
                await yield_progress(msg)

        for source in active_sources:
            if source in self.source_map:
                await emit(f"Discovering {source.upper()} subnets...")
                try:
                    await self.source_map[source](session, loop)
                except Exception as e:
                    logger.error(f"Discovery failed for {source}: {e}")
                    await emit(f"Error discovering {source}: {str(e)[:50]}")

    async def _discover_aci(self, session, loop):
        import clients.aci_registry as reg
        fabrics = reg.list_fabrics()
        for f in fabrics:
            try:
                aci_client = auth_module.get_aci_for_session(session, f.id)
                # Fetch both BD and L3Out subnets
                subnets = await loop.run_in_executor(None, aci_client.get_all_subnets)
                for s in subnets:
                    ip_cidr = s.get('ip')
                    if not ip_cidr: continue

                    try:
                        net = netaddr.IPNetwork(ip_cidr)
                        if self.is_excluded(net): continue

                        node = IPAMNode(str(net.cidr), source="ACI")
                        node.display_name = s.get('name') or s.get('dn').split('/')[-1]
                        node.site = f.label
                        node.logical_container = s.get('dn').split('/')[1] # Tenant

                        node.interface_name = s.get('name')
                        node.host_ip = str(net.ip)
                        node.interface_type, node.vlan_id = classify_interface(node.interface_name, net)
                        if node.interface_type == "loopback":
                            node.role = "host_route"

                        self.subnets.append(node)
                    except Exception:
                        continue
            except Exception as e:
                logger.error(f"ACI discovery failed for fabric {f.id}: {e}")

    async def _discover_dnac(self, session, loop):
        """DNAC primary source: full interface inventory (loopbacks, tunnels,
        SVIs, physical, mgmt) with real prefix lengths from ipv4Address/ipv4Mask.
        Falls back to a management /24 approximation for devices that have no
        interface entries."""
        try:
            dnac = auth_module.get_dnac_for_session(session) if session else None
            import clients.dnac as dc

            from cache import cache, TTL_DEVICES, TTL_SITES, TTL_DNAC_INTERFACES

            def _loader_or_empty(loader):
                return (lambda: loader()) if dnac else (lambda: None)

            devices = await loop.run_in_executor(
                None, run_with_context(cache.get_or_set),
                "devices", _loader_or_empty(lambda: dc.get_all_devices(dnac)), TTL_DEVICES
            ) or []
            sites = await loop.run_in_executor(
                None, run_with_context(cache.get_or_set),
                "sites", _loader_or_empty(lambda: dc.get_site_cache(dnac)), TTL_SITES
            ) or []
            dev_site_map = await loop.run_in_executor(
                None, run_with_context(cache.get_or_set),
                "device_site_map", _loader_or_empty(lambda: dc.build_device_site_map(dnac, sites)), TTL_SITES
            ) or {}
            interfaces = await loop.run_in_executor(
                None, run_with_context(cache.get_or_set),
                "dnac_interfaces", _loader_or_empty(lambda: dc.get_all_interfaces(dnac)), TTL_DNAC_INTERFACES
            ) or []

            id_to_dev = {d.get('id'): d for d in devices if d.get('id')}
            devices_with_iface: Set[str] = set()

            for iface in interfaces:
                addr = iface.get('ipv4Address')
                mask = iface.get('ipv4Mask')
                if not addr or not mask:
                    continue
                port_name = iface.get('portName') or ''
                desc = iface.get('description') or ''
                try:
                    net = netaddr.IPNetwork(f"{addr}/{mask}")
                except Exception:
                    continue
                if self.is_excluded(net, port_name, desc):
                    continue

                dev_id = iface.get('deviceId')
                dev = id_to_dev.get(dev_id) or {}
                devices_with_iface.add(dev_id)
                hostname = dev.get('hostname') or iface.get('deviceName') or 'Unknown'

                node = IPAMNode(str(net.cidr), source="DNAC")
                node.display_name = port_name or hostname
                node.site = dev_site_map.get(dev_id, "Unknown")
                node.device = hostname
                node.host_ip = str(net.ip)
                node.interface_name = port_name
                node.interface_type, node.vlan_id = classify_interface(port_name, net)
                if node.interface_type == "loopback":
                    node.role = "host_route"

                self.subnets.append(node)

            # Fallback: device has a management IP but no interface entry came
            # back for it — keep the /24 management approximation so the device
            # still appears in IPAM.
            for dev in devices:
                dev_id = dev.get('id')
                if dev_id in devices_with_iface:
                    continue
                ip = dev.get('managementIpAddress')
                if not ip:
                    continue
                try:
                    net = netaddr.IPNetwork(f"{ip}/24")
                    if self.is_excluded(net):
                        continue
                    node = IPAMNode(str(net.cidr), source="DNAC")
                    node.display_name = dev.get('hostname', 'Unknown')
                    node.site = dev_site_map.get(dev_id, "Unknown")
                    node.device = dev.get('hostname')
                    node.host_ip = ip
                    node.interface_type = "management"
                    node.role = "host_route"
                    self.subnets.append(node)
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"DNAC discovery failed: {e}")

    async def _discover_panorama(self, session, loop):
        try:
            from cache import cache
            devices = cache.get("pan_interfaces") or []
            for dev in devices:
                site = "Firewall"
                for iface in dev.get('interfaces', []):
                    # IPv4
                    v4 = iface.get('ipv4')
                    if v4 and '/' in v4:
                        try:
                            net = netaddr.IPNetwork(v4)
                            if not self.is_excluded(net, iface.get('name', '')):
                                node = IPAMNode(str(net.cidr), source="Panorama")
                                node.display_name = iface.get('name', 'Unknown')
                                node.site = site
                                node.device = dev.get('hostname', 'Firewall')
                                node.logical_container = f"{dev['hostname']}-{iface['name']}"

                                node.interface_name = iface.get('name')
                                node.host_ip = str(net.ip)
                                node.interface_type, node.vlan_id = classify_interface(node.interface_name, net)
                                if node.interface_type == "loopback":
                                    node.role = "host_route"

                                self.subnets.append(node)
                        except Exception: pass

                    # IPv6
                    for v6 in iface.get('ipv6', []):
                        if '/' in v6:
                            try:
                                net = netaddr.IPNetwork(v6)
                                if not self.is_excluded(net, iface.get('name', '')):
                                    node = IPAMNode(str(net.cidr), source="Panorama")
                                    node.display_name = iface.get('name', 'Unknown')
                                    node.site = site
                                    node.device = dev.get('hostname', 'Firewall')
                                    node.logical_container = f"{dev['hostname']}-{iface['name']}"

                                    node.interface_name = iface.get('name')
                                    node.host_ip = str(net.ip)
                                    node.interface_type, node.vlan_id = classify_interface(node.interface_name, net)
                                    if node.interface_type == "loopback":
                                        node.role = "host_route"

                                    self.subnets.append(node)
                            except Exception: pass
        except Exception as e:
            logger.error(f"Panorama discovery failed: {e}")

    async def _discover_nexus(self, session, loop):
        try:
            from routers.nexus import get_cached_nexus_interfaces
            interfaces = get_cached_nexus_interfaces()
            for iface in interfaces:
                ip_cidr = iface.get('ipv4_address')
                if ip_cidr and ip_cidr != "N/A":
                    try:
                        net = netaddr.IPNetwork(ip_cidr)
                        if self.is_excluded(net, iface.get('interface_name', '')): continue
                        node = IPAMNode(str(net.cidr), source="Nexus")
                        node.display_name = iface.get('interface_name', 'Unknown')
                        node.site = "DataCenter"
                        node.device = iface.get('hostname')

                        node.interface_name = iface.get('interface_name')
                        node.host_ip = str(net.ip)
                        node.interface_type, node.vlan_id = classify_interface(node.interface_name, net)
                        if node.interface_type == "loopback":
                            node.role = "host_route"

                        self.subnets.append(node)
                    except Exception: pass
        except Exception as e:
            logger.error(f"Nexus discovery failed: {e}")

    def build_tree(self):
        """Construct a recursive hierarchy from the flat subnets list."""
        priority = ["ACI", "DNAC", "Nexus", "Panorama"]
        unique_nets: Dict[str, IPAMNode] = {}
        tunnel_endpoints: Dict[str, List[IPAMNode]] = {}

        # Track host IPs for VIP detection (cidr -> host_ip -> list of nodes)
        host_ips_in_subnet: Dict[str, Dict[str, List[IPAMNode]]] = {}

        # 1. Split Tunnel vs Non-Tunnel and collect for VIP detection
        for s in self.subnets:
            if s.interface_type == "tunnel":
                if s.cidr not in tunnel_endpoints:
                    tunnel_endpoints[s.cidr] = []
                tunnel_endpoints[s.cidr].append(s)
            else:
                if s.cidr not in host_ips_in_subnet:
                    host_ips_in_subnet[s.cidr] = {}
                if s.host_ip:
                    if s.host_ip not in host_ips_in_subnet[s.cidr]:
                        host_ips_in_subnet[s.cidr][s.host_ip] = []
                    host_ips_in_subnet[s.cidr][s.host_ip].append(s)

        # 2. Priority-based dedup for non-tunnels
        for source in priority:
            for s in [n for n in self.subnets if n.source == source and n.interface_type != "tunnel"]:
                if s.cidr not in unique_nets:
                    unique_nets[s.cidr] = s
                else:
                    existing = unique_nets[s.cidr]
                    if existing.site != s.site and s.site != "Unknown" and s.site != "Fabric":
                        existing.conflicts.append(
                            f"Site Conflict: {s.source} reports site '{s.site}'"
                        )

        # 3. VIP Detection
        for cidr, host_map in host_ips_in_subnet.items():
            if cidr in unique_nets:
                parent_node = unique_nets[cidr]
                for host_ip, nodes in host_map.items():
                    # Same host IP on 2+ distinct devices?
                    devices = {n.device for n in nodes if n.device}
                    if len(devices) >= 2:
                        vip_node = IPAMNode(f"{host_ip}/{32 if nodes[0].version == 4 else 128}", source="multi")
                        vip_node.role = "vip"
                        vip_node.interface_type = "vip"
                        vip_node.host_ip = host_ip
                        vip_node.display_name = "VIP (inferred)"
                        dev_list = ", ".join(sorted(list(devices)))
                        vip_node.conflicts.append(f"Shared IP inferred as VIP on: {dev_list} — verify if unexpected.")
                        parent_node.children_nodes.append(vip_node)

        # 4. Tunnel Group Synthesis
        # When a tunnel CIDR collides with a non-tunnel subnet recorded in
        # step 2 (common case: DNAC hardcodes every device's mgmt IP to /24,
        # which may overlap a tunnel /24), preserve BOTH by nesting the tunnel
        # view under the existing subnet rather than dropping or overwriting.
        for cidr, endpoints in tunnel_endpoints.items():
            existing = unique_nets.get(cidr)

            if len(endpoints) >= 2:
                source = "multi" if len({e.source for e in endpoints}) > 1 else endpoints[0].source
                group = IPAMNode(cidr, source=source)
                group.role = "tunnel_group"
                group.interface_type = "tunnel"
                group.display_name = f"Tunnel Network ({len(endpoints)} endpoints)"
                for e in endpoints:
                    e.role = "endpoint"
                    group.children_nodes.append(e)
                if existing is None:
                    unique_nets[cidr] = group
                else:
                    existing.children_nodes.append(group)
            elif len(endpoints) == 1:
                e = endpoints[0]
                if existing is None:
                    unique_nets[cidr] = e
                else:
                    e.role = "endpoint"
                    existing.children_nodes.append(e)

        # 5. Synthesize RFC1918 supernet roots so children group cleanly
        # (e.g. 172.17.0.0/16 nests under 172.16.0.0/12 instead of being a top-level root).
        for supernet in RFC1918_SUPERNETS:
            cidr = str(supernet)
            if cidr in unique_nets:
                continue
            has_descendants = any(
                n.version == 4 and n.network in supernet
                for n in unique_nets.values()
            )
            if has_descendants:
                synth = IPAMNode(cidr, source="Aggregate")
                synth.role = "supernet"
                synth.interface_type = "Supernet"
                synth.display_name = "RFC1918 Aggregate"
                unique_nets[cidr] = synth

        # 6. Sort by IP first (then prefixlen) and build tree.
        # IP-first sort gives users true numeric ordering at every depth (10.2 before
        # 10.100), while the prefixlen tiebreaker keeps parent supernets ahead of
        # children with the same start address (10.0.0.0/8 before 10.0.0.0/16).
        v4_nets = sorted([n for n in unique_nets.values() if n.version == 4],
                         key=lambda x: (x.ip_int, x.prefixlen))
        v6_nets = sorted([n for n in unique_nets.values() if n.version == 6],
                         key=lambda x: (x.ip_int, x.prefixlen))

        self.tree["ipv4"] = self._recursive_build(v4_nets)
        self.tree["ipv6"] = self._recursive_build(v6_nets)

    def _recursive_build(self, nets: List[IPAMNode]) -> List[Dict]:
        if not nets: return []

        roots: List[IPAMNode] = []
        for n in nets:
            is_child = False
            for parent in roots:
                if n.network in parent.network and n.cidr != parent.cidr:
                    parent.children_nodes.append(n)
                    is_child = True
                    break
            if not is_child:
                roots.append(n)

        result = []

        # Group orphans by site for "Host Routes" section if they are /32 or /128
        site_host_routes: Dict[str, List[IPAMNode]] = {}

        for r in roots:
            # Special case: if this is a /32 or /128 and it's a root, it might belong in "Host Routes"
            if r.prefixlen == (32 if r.version == 4 else 128) and r.role in ["host_route", "subnet"]:
                if r.site not in site_host_routes:
                    site_host_routes[r.site] = []
                site_host_routes[r.site].append(r)
                continue

            result.append(self._node_to_dict_recursive(r))

        # Add per-site Host Routes sections
        for site, host_nodes in site_host_routes.items():
            pseudo = {
                "cidr": f"Host Routes ({site})",
                "display_name": f"Orphan Host Routes - {len(host_nodes)} entries",
                "site": site,
                "role": "host_route_group",
                "interface_type": "loopback",
                "children": [self._node_to_dict_recursive(n) for n in host_nodes]
            }
            result.append(pseudo)

        return result

    def _node_to_dict_recursive(self, node: IPAMNode) -> Dict:
        d = node.to_dict()
        if node.children_nodes:
            # Sort by IP first so VIPs / tunnel groups / late-appended siblings
            # all land in numeric order rather than insertion order.
            node.children_nodes.sort(key=lambda x: (x.ip_int, x.prefixlen))

            # Check for loopback collapsing
            loopbacks = [n for n in node.children_nodes if n.interface_type == "loopback" and n.prefixlen == (32 if n.version == 4 else 128)]
            others = [n for n in node.children_nodes if n not in loopbacks]

            children_dicts = []
            if len(loopbacks) >= 3: # Collapse if 3 or more
                pseudo = {
                    "cidr": f"Loopbacks ({len(loopbacks)})",
                    "display_name": f"Collapsed Loopbacks",
                    "role": "loopback_group",
                    "interface_type": "loopback",
                    "children": [self._node_to_dict_recursive(n) for n in loopbacks]
                }
                children_dicts.append(pseudo)
            else:
                for lb in loopbacks:
                    children_dicts.append(self._node_to_dict_recursive(lb))

            # Recurse for non-loopback children or if not collapsed
            # Actually we need to maintain hierarchy, so we call _recursive_build on 'others'
            # Wait, others might have their own children.
            children_dicts.extend(self._recursive_build(others))
            d["children"] = children_dicts

        return d

    def get_tree(self):
        return self.tree

from logger_config import run_with_context
