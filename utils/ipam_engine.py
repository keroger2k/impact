import logging
import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set, Tuple
import netaddr
from cache import cache
import auth as auth_module
import clients.aci as aci_client_mod
import clients.dnac as dnac_client_mod
import clients.ise as ise_client_mod
import clients.panorama as pan_client_mod
from collectors.nxos import NXOSCollector
from routers.nexus import get_cached_nexus_inventory

logger = logging.getLogger(__name__)

# Constants for IP space
PRIVATE_RANGES = [
    netaddr.IPNetwork("10.0.0.0/8"),
    netaddr.IPNetwork("172.16.0.0/12"),
    netaddr.IPNetwork("100.64.0.0/10"), # CGNAT
    netaddr.IPNetwork("fc00::/7"),      # IPv6 ULA
]
EXCLUDED_RANGES = [
    netaddr.IPNetwork("192.168.0.0/16"),
    netaddr.IPNetwork("169.254.0.0/16"), # Link-Local
]

HA_PATTERNS = re.compile(r"HA|KEEPALIVE|VPC_PEER|FAILOVER", re.IGNORECASE)

PRIORITY_SOURCES = ["ACI", "DNAC", "Nexus", "Panorama", "ISE"]

class IPAMNode:
    def __init__(self, cidr: str, node_type: str = "Subnet", source: str = "Unknown"):
        self.network = netaddr.IPNetwork(cidr)
        self.cidr = str(self.network.cidr)
        self.type = node_type  # Group, Supernet, Subnet
        self.source = source
        self.display_name = ""
        self.description = ""
        self.site = "Unknown"
        self.vlan = ""
        self.device = ""
        self.children: List['IPAMNode'] = []
        self.conflicts = []
        self.overlaps = []
        self.logical_container = "" # For dual-stack linking (BD, VLAN, Pool Name)

    def to_dict(self):
        return {
            "cidr": self.cidr,
            "address": str(self.network.network),
            "prefix": self.network.prefixlen,
            "type": self.type,
            "source": self.source,
            "display_name": self.display_name,
            "description": self.description,
            "site": self.site,
            "vlan": self.vlan,
            "device": self.device,
            "conflicts": self.conflicts,
            "overlaps": self.overlaps,
            "children": [c.to_dict() for c in self.children]
        }

class IPAMEngine:
    def __init__(self):
        self.subnets: List[IPAMNode] = []
        self.v4_tree: List[IPAMNode] = []
        self.v6_tree: List[IPAMNode] = []

    def is_excluded(self, network: netaddr.IPNetwork, name: str = "", desc: str = "") -> bool:
        # Skip host addresses (/32 or /128)
        if (network.version == 4 and network.prefixlen == 32) or \
           (network.version == 6 and network.prefixlen == 128):
            return True

        # Check explicit exclusions
        for ex in EXCLUDED_RANGES:
            if network in ex or ex in network:
                return True
        # Check HA patterns
        if HA_PATTERNS.search(name) or HA_PATTERNS.search(desc):
            return True
        return False

    async def discover_all(self, session, loop, sources: Optional[List[str]] = None, yield_progress=None):
        """Aggregate data from sources. If sources is None, discover all."""
        self.subnets = []

        # Mapping of source names to their discover methods
        source_map = {
            "aci": self._discover_aci,
            "dnac": self._discover_dnac,
            "panorama": self._discover_panorama,
            "ise": self._discover_ise,
            "nexus": self._discover_nexus
        }

        if not sources:
            sources = list(source_map.keys())

        # Filter to valid sources
        sources = [s for s in sources if s.lower() in source_map]

        for s_name in sources:
            if yield_progress:
                await yield_progress(f"Starting {s_name.upper()} discovery...")

            method = source_map[s_name.lower()]
            start_count = len(self.subnets)
            try:
                await method(session, loop)
                count = len(self.subnets) - start_count
                if yield_progress:
                    await yield_progress(f"Finished {s_name.upper()} discovery: Found {count} subnets.")
            except Exception as e:
                logger.error(f"Discovery source {s_name} failed: {e}")
                if yield_progress:
                    await yield_progress(f"Error in {s_name.upper()} discovery: {str(e)}")

        return self.subnets

    async def _discover_aci(self, session, loop):
        try:
            client = auth_module.get_aci_for_session(session)
            # Query fvSubnet for bridge domain subnets
            data = await loop.run_in_executor(None, client.get, "api/node/class/fvSubnet.json")
            # Also query l3extSubnet for L3Out subnets
            l3_data = await loop.run_in_executor(None, client.get, "api/node/class/l3extSubnet.json")

            all_imdata = []
            if data and 'imdata' in data: all_imdata.extend(data['imdata'])
            if l3_data and 'imdata' in l3_data: all_imdata.extend(l3_data['imdata'])

            for item in all_imdata:
                cls_name = list(item.keys())[0]
                attr = item[cls_name]['attributes']
                cidr = attr.get('ip')
                if not cidr: continue

                net = netaddr.IPNetwork(cidr)
                name = ""
                # Try to get BD name from DN: uni/tn-common/BD-myBD/subnet-[10.1.1.1/24]
                dn = attr.get('dn', '')
                bd_match = re.search(r'/BD-([^/]+)/', dn)
                if bd_match:
                    name = bd_match.group(1)

                desc = attr.get('descr', '')
                if self.is_excluded(net, name, desc): continue

                node = IPAMNode(cidr, source="ACI")
                node.display_name = name
                if desc:
                    node.description = f"{name} ({desc})"
                else:
                    node.description = name

                # Site from Tenant
                tenant_match = re.search(r'uni/tn-([^/]+)/', dn)
                if tenant_match:
                    t_name = tenant_match.group(1)
                    # Simple heuristic: Chicago_Prod -> Chicago
                    node.site = t_name.split('_')[0]

                # Device for ACI subnets
                if "BD-" in dn:
                    node.device = "ACI Fabric"
                else:
                    # For L3Outs, try to find node profile in DN
                    node_prof = re.search(r'/nodeP-([^/]+)/', dn)
                    if node_prof:
                        node.device = f"ACI {node_prof.group(1)}"
                    else:
                        node.device = "ACI Fabric"

                node.logical_container = name # BD is the container
                self.subnets.append(node)
        except Exception as e:
            logger.error(f"ACI discovery failed: {e}")

    async def _discover_dnac(self, session, loop):
        from dev import DEV_MODE
        try:
            device_map = {} # deviceId -> {hostname, site}
            if DEV_MODE:
                # Mock data
                pools = [
                    {"ipPoolCidr": "10.20.0.0/16", "ipPoolName": "BOS-Pool", "groupName": "Global/TSA-BOS-T1"},
                    {"ipPoolCidr": "10.30.0.0/16", "ipPoolName": "LAX-Pool", "groupName": "Global/TSA-LAX-T1"}
                ]
                interfaces = [
                    {"ipv4Address": "10.50.1.1", "ipv4Mask": "255.255.255.0", "portName": "GigabitEthernet1/0/1", "description": "User VLAN", "deviceId": "dev1"}
                ]
                device_map = {"dev1": {"hostname": "BOS-SW-01", "site": "BOS"}}
            else:
                dnac = auth_module.get_dnac_for_session(session)
                # Build device map for metadata
                import clients.dnac as dnac_client
                devices = await loop.run_in_executor(None, dnac_client.get_all_devices, dnac)
                site_cache = await loop.run_in_executor(None, dnac_client.get_site_cache, dnac)
                site_map = await loop.run_in_executor(None, dnac_client.build_device_site_map, dnac, site_cache)

                for d in devices:
                    d_id = d.get('instanceUuid')
                    if d_id:
                        device_map[d_id] = {
                            "hostname": d.get('hostname', 'Unknown'),
                            "site": site_map.get(d_id, 'Unknown').split('/')[-1]
                        }

                # 1. Discover via IP Pools
                pools = []
                for endpoint in ["/dna/intent/api/v1/global-pool", "/dna/intent/api/v1/network-design/ip-pool"]:
                    try:
                        resp = await loop.run_in_executor(None, dnac.custom_caller.call_api, "GET", endpoint)
                        data = getattr(resp, "response", [])
                        if isinstance(data, list) and data:
                            pools.extend(data)
                    except Exception: pass

                if not pools:
                    try:
                        resp = await loop.run_in_executor(None, dnac.network_design.get_reserve_ip_subpool)
                        pools = getattr(resp, "response", [])
                    except: pass

                # 2. Discover via Interfaces (for SVIs/Routed ports not in pools)
                try:
                    import clients.dnac as dnac_client
                    interfaces = await loop.run_in_executor(None, dnac_client.get_all_interfaces, dnac)
                except:
                    interfaces = []

            # Process Pools
            for p in pools:
                name = p.get('ipPoolName', p.get('poolName', ''))
                site = p.get('groupName', 'Unknown').split('/')[-1]

                # Check for both v4 and v6 CIDRs in pools
                for cidr_key in ['ipPoolCidr', 'ipv6PoolCidr', 'cidr']:
                    cidr = p.get(cidr_key)
                    if not cidr: continue

                    try:
                        net = netaddr.IPNetwork(cidr)
                        if self.is_excluded(net, name): continue
                        node = IPAMNode(str(net.cidr), source="DNAC")
                        node.display_name = name
                        node.description = f"Pool: {name}"
                        node.logical_container = name
                        node.site = site
                        self.subnets.append(node)
                        logger.debug(f"Discovered DNAC Pool {net.version}: {net.cidr}")
                    except Exception as e:
                        logger.debug(f"Failed to parse DNAC pool CIDR '{cidr}': {e}")

            # Process Interfaces
            for iface in interfaces:
                # Common metadata
                port_name = iface.get('portName', 'Unknown')
                vlan_id = iface.get('vlanId', '')
                description = iface.get('description', '')
                d_info = device_map.get(iface.get('deviceId'), {})
                hostname = d_info.get('hostname', iface.get('hostname', 'DNAC-Managed'))
                site = d_info.get('site', 'Unknown')
                logical_container = vlan_id if vlan_id else port_name

                # IPv4
                ip = iface.get('ipv4Address')
                mask = iface.get('ipv4Mask')
                if ip and mask and ip != "N/A" and mask != "N/A":
                    try:
                        net = netaddr.IPNetwork(f"{ip}/{mask}")
                        if not self.is_excluded(net, port_name):
                            node = IPAMNode(str(net.cidr), source="DNAC")
                            node.display_name = port_name
                            node.description = description or port_name
                            node.vlan = vlan_id
                            node.device = hostname
                            node.site = site
                            node.logical_container = logical_container
                            self.subnets.append(node)
                    except Exception as e:
                        logger.debug(f"Failed to parse DNAC IPv4 for {port_name}: {e}")

                # IPv6 - Handle multiple possible field names and formats
                v6_candidates = []

                # 1. ipv6AddressList (could be list of strings or list of objects)
                v6_list = iface.get('ipv6AddressList', [])
                if isinstance(v6_list, list):
                    for item in v6_list:
                        if isinstance(item, str):
                            v6_candidates.append(item)
                        elif isinstance(item, dict):
                            # Some versions use {"address": "...", "prefixLength": "..."}
                            addr = item.get('address') or item.get('ipv6Address')
                            prefix = item.get('prefixLength') or item.get('ipv6PrefixLength')
                            if addr and prefix:
                                v6_candidates.append(f"{addr}/{prefix}")
                            elif addr and "/" in addr:
                                v6_candidates.append(addr)

                # 2. Singular fields
                v6_addr = iface.get('ipv6Address')
                v6_prefix = iface.get('ipv6PrefixLength')
                if v6_addr and v6_prefix:
                    v6_candidates.append(f"{v6_addr}/{v6_prefix}")
                elif v6_addr and "/" in v6_addr:
                    v6_candidates.append(v6_addr)

                # Process all unique candidates
                for v6_cidr in set(v6_candidates):
                    try:
                        net = netaddr.IPNetwork(v6_cidr)
                        if not self.is_excluded(net, port_name):
                            node = IPAMNode(str(net.cidr), source="DNAC")
                            node.display_name = port_name
                            node.description = description or port_name
                            node.vlan = vlan_id
                            node.device = hostname
                            node.site = site
                            node.logical_container = logical_container
                            self.subnets.append(node)
                            logger.debug(f"Discovered DNAC IPv6: {net.cidr} on {hostname} {port_name}")
                    except Exception as e:
                        logger.debug(f"Failed to parse DNAC IPv6 candidate '{v6_cidr}' for {port_name}: {e}")

        except Exception as e:
            logger.error(f"DNAC discovery failed: {e}")

    async def _discover_panorama(self, session, loop):
        try:
            key = auth_module.get_panorama_key_for_session(session)
            if not key: return

            devices = await loop.run_in_executor(None, pan_client_mod.fetch_firewall_interfaces, key)
            for dev in devices:
                dg = dev.get('device_group', 'Unknown')
                # Panorama Site = Device Group split by / (SiteHierarchy)
                site = dg.split('/')[-1] if '/' in dg else dg

                # Further site extraction from hostname (e.g. SDCZFWL100 -> SDCZ)
                hostname = dev.get('hostname', '')
                if site == 'Unknown' or site == 'Global' or site == 'Firewall':
                    match = re.match(r'^([A-Z]{3,4})', hostname)
                    if match:
                        site = match.group(1)

                for iface in dev.get('interfaces', []):
                    # IPv4
                    v4 = iface.get('ipv4')
                    if v4 and '/' in v4:
                        net = netaddr.IPNetwork(v4)
                        if not self.is_excluded(net, iface.get('name', '')):
                            node = IPAMNode(str(net.cidr), source="Panorama")
                            node.display_name = iface.get('name', 'Unknown')
                            node.site = site
                            node.device = dev.get('hostname', 'Firewall')
                            node.logical_container = f"{dev['hostname']}-{iface['name']}"
                            self.subnets.append(node)

                    # IPv6
                    for v6 in iface.get('ipv6', []):
                        if '/' in v6:
                            net = netaddr.IPNetwork(v6)
                            if not self.is_excluded(net, iface.get('name', '')):
                                node = IPAMNode(str(net.cidr), source="Panorama")
                                node.display_name = iface.get('name', 'Unknown')
                                node.site = site
                                node.device = dev.get('hostname', 'Firewall')
                                node.logical_container = f"{dev['hostname']}-{iface['name']}"
                                self.subnets.append(node)
        except Exception as e:
            logger.error(f"Panorama discovery failed: {e}")

    async def _discover_ise(self, session, loop):
        from dev import DEV_MODE
        try:
            if DEV_MODE:
                # Mock ISE Guest/VPN pools
                mock_pools = [
                    {"cidr": "192.168.100.0/24", "name": "ISE-Guest-Wifi", "site": "Global"},
                    {"cidr": "10.254.0.0/16", "name": "AnyConnect-VPN", "site": "Remote"}
                ]
                for p in mock_pools:
                    net = netaddr.IPNetwork(p['cidr'])
                    if self.is_excluded(net, p['name']): continue
                    node = IPAMNode(p['cidr'], source="ISE")
                    node.display_name = p['name']
                    node.site = p['site']
                    node.description = f"ISE Managed Pool: {p['name']}"
                    self.subnets.append(node)
                return

            # Note: ISE IP pools for Guest/VPN are often defined on the NAD (Network Access Device)
            # and referenced by name in ISE Authorization Profiles.
            # Direct API access to pool subnets in ISE ERS/OpenAPI is version-specific.
            # Future enhancement: Query Authorization Profiles and extract pool metadata if available.
            pass
        except Exception as e:
            logger.error(f"ISE discovery failed: {e}")

    async def _discover_nexus(self, session, loop):
        try:
            # 1. Use cached interfaces (faster, covers what we've already collected)
            from routers.nexus import get_cached_nexus_interfaces, get_nexus_devices_from_csv

            interfaces = get_cached_nexus_interfaces()
            for iface in interfaces:
                ip_cidr = iface.get('ipv4_address')
                if ip_cidr and ip_cidr != "N/A":
                    try:
                        net = netaddr.IPNetwork(ip_cidr)
                        if self.is_excluded(net, iface.get('interface_name', '')): continue
                        node = IPAMNode(str(net.cidr), source="Nexus")
                        node.display_name = iface.get('interface_name', 'Unknown')

                        hostname = iface.get('hostname', 'Unknown')
                        # Use heuristic for site extraction
                        match = re.match(r'^([A-Z]{3,4})', hostname)
                        node.site = match.group(1) if match else hostname.split('-')[0]

                        node.device = hostname
                        node.logical_container = iface.get('interface_name', '')
                        self.subnets.append(node)
                    except: continue

            # 2. Parse cached configs for anything missed or more metadata
            # Fallback to CSV for device list if inventory cache is empty
            nexus_inventory = get_cached_nexus_inventory()
            if not nexus_inventory:
                nexus_inventory = get_nexus_devices_from_csv()

            for n in nexus_inventory:
                hostname = n.get('hostname', 'Unknown')
                match = re.match(r'^([A-Z]{3,4})', hostname)
                site = match.group(1) if match else hostname.split('-')[0]

                config = cache.get(f"config:nexus:{hostname}")
                if config:
                    self._parse_nexus_config(config, hostname, site)
        except Exception as e:
            logger.error(f"Nexus discovery failed: {e}")

    def _parse_nexus_config(self, config: str, hostname: str, site: str):
        # Very basic parser for demonstration
        current_iface = None
        vlan_id = ""
        for line in config.splitlines():
            line = line.strip()
            if line.startswith("interface "):
                current_iface = line.split()[-1]
                vlan_id = ""
                if "Vlan" in current_iface:
                    vlan_id = current_iface.replace("Vlan", "")
            elif current_iface and (line.startswith("ip address ") or line.startswith("ipv6 address ")):
                parts = line.split()
                if len(parts) < 3: continue
                cidr = parts[2]
                if "/" not in cidr:
                    # Handle "ip address 10.1.1.1 255.255.255.0"
                    if len(parts) >= 4:
                        try:
                            net = netaddr.IPNetwork(f"{parts[2]}/{parts[3]}")
                            cidr = str(net.cidr)
                        except: continue

                try:
                    net = netaddr.IPNetwork(cidr)
                    if self.is_excluded(net, current_iface): continue

                    node = IPAMNode(str(net.cidr), source="Nexus")
                    node.display_name = current_iface
                    node.site = site
                    node.vlan = vlan_id
                    node.device = hostname
                    node.logical_container = vlan_id if vlan_id else current_iface
                    self.subnets.append(node)
                except: continue

    def build_tree(self):
        """Organize flat subnets into hierarchical v4 and v6 trees"""
        self.v4_tree = []
        self.v6_tree = []

        # 1. Deduplicate & Handle Priority
        unique_subnets: Dict[str, IPAMNode] = {}
        for s in self.subnets:
            if s.cidr not in unique_subnets:
                unique_subnets[s.cidr] = s
            else:
                current = unique_subnets[s.cidr]
                logger.debug(f"Merging/Deduplicating subnet {s.cidr}: {s.source} ({s.site}) vs {current.source} ({current.site})")

                # Merge metadata/conflicts
                if s.site != current.site and s.site != "Unknown" and current.site != "Unknown":
                    conflict_msg = f"Site Conflict: {s.source} ({s.site}) vs {current.source} ({current.site})"
                    if conflict_msg not in current.conflicts:
                        current.conflicts.append(conflict_msg)
                        logger.info(f"Conflict detected on {s.cidr}: {conflict_msg}")

                # Priority: ACI > DNAC > Nexus > Panorama > ISE
                try:
                    s_idx = PRIORITY_SOURCES.index(s.source)
                    c_idx = PRIORITY_SOURCES.index(current.source)
                    if s_idx < c_idx:
                        # Transfer conflicts to the new winner
                        s.conflicts = list(set(s.conflicts + current.conflicts))
                        unique_subnets[s.cidr] = s
                except ValueError:
                    # One of the sources is not in priority list (e.g. System-Generated)
                    # Keep existing unless new one is a known source
                    if s.source in PRIORITY_SOURCES:
                        s.conflicts = list(set(s.conflicts + current.conflicts))
                        unique_subnets[s.cidr] = s

        # 2. Separate v4 and v6
        v4_nodes = [n for n in unique_subnets.values() if n.network.version == 4]
        v6_nodes = [n for n in unique_subnets.values() if n.network.version == 6]

        # 3. Build Trees
        self.v4_tree = self._build_recursive_tree(v4_nodes, version=4)
        self.v6_tree = self._build_recursive_tree(v6_nodes, version=6)

        # 4. Process Dual-Stack Linking
        self._link_dual_stack()

    def _build_recursive_tree(self, nodes: List[IPAMNode], version: int) -> List[IPAMNode]:
        if not nodes: return []

        # Sort by prefix length (largest first)
        nodes.sort(key=lambda x: x.network.prefixlen)

        # Ensure root nodes exist (10.0.0.0/8, etc)
        roots = []
        if version == 4:
            roots = [IPAMNode("10.0.0.0/8", "Group", "System-Generated"),
                     IPAMNode("172.16.0.0/12", "Group", "System-Generated"),
                     IPAMNode("100.64.0.0/10", "Group", "System-Generated")]
        else:
            roots = [IPAMNode("fc00::/7", "Group", "System-Generated")]

        # Add nodes to tree
        for node in nodes:
            # Check if it fits in existing root
            placed = False
            for root in roots:
                if node.network == root.network:
                    # Merge discovered node into system root
                    root.source = node.source
                    root.display_name = node.display_name
                    root.description = node.description
                    root.site = node.site
                    root.vlan = node.vlan
                    root.conflicts = node.conflicts
                    root.logical_container = node.logical_container
                    placed = True
                    break
                elif node.network in root.network:
                    self._insert_into_tree(root, node)
                    placed = True
                    break

            if not placed:
                # If public IP, create a root if needed
                is_private = False
                for pr in PRIVATE_RANGES:
                    if node.network in pr:
                        is_private = True
                        break

                if not is_private:
                    # Create /8 or similar root for public space
                    prefix = 8 if version == 4 else 32
                    # Use canonical CIDR (e.g. 11.0.0.0/8)
                    temp_net = netaddr.IPNetwork(f"{node.network.network}/{prefix}")
                    root_cidr = str(temp_net.cidr)
                    new_root = IPAMNode(root_cidr, "Group", "System-Generated")
                    roots.append(new_root)
                    self._insert_into_tree(new_root, node)
                else:
                    # It's private but outside our predefined roots? (shouldn't happen with RFC1918)
                    roots.append(node)

        # Filter empty roots and clean up
        final_roots = []
        for r in roots:
            if r.children or r.source != "System-Generated":
                final_roots.append(r)

        # Sort roots numerically by IP address
        final_roots.sort(key=lambda x: x.network.value)
        return final_roots

    def _insert_into_tree(self, parent: IPAMNode, node: IPAMNode):
        # Find if it fits in any existing child
        # Use a copy of children for safe removal while iterating
        for child in list(parent.children):
            if node.network in child.network:
                self._insert_into_tree(child, node)
                return
            elif child.network in node.network:
                # Node is a new parent for this child
                parent.children.remove(child)
                node.children.append(child)
                node.type = "Supernet"
                # Flag overlap
                node.overlaps.append(f"Nesting Overlap: {child.cidr} ({child.source}) is inside {node.cidr}")

        # Doesn't fit in children, or became a parent for some. Add to children.
        parent.children.append(node)
        # Sort children numerically by IP address, then by prefix length
        parent.children.sort(key=lambda x: (x.network.value, x.network.prefixlen))
        if parent.source != "System-Generated":
            parent.type = "Supernet"

    def _link_dual_stack(self):
        # Link based on logical_container
        v4_map = {}
        for n in self._flatten(self.v4_tree):
            if n.logical_container:
                v4_map[n.logical_container] = n

        for n in self._flatten(self.v6_tree):
            if n.logical_container and n.logical_container in v4_map:
                v4_node = v4_map[n.logical_container]
                # In UI they will be linked. For model, we can just store reference or flag
                n.display_name = f"[Dual-Stack] {n.display_name}"
                v4_node.display_name = f"[Dual-Stack] {v4_node.display_name}"

    def _flatten(self, nodes: List[IPAMNode]) -> List[IPAMNode]:
        flat = []
        for n in nodes:
            flat.append(n)
            flat.extend(self._flatten(n.children))
        return flat

    def get_tree(self):
        return {
            "ipv4": [n.to_dict() for n in self.v4_tree],
            "ipv6": [n.to_dict() for n in self.v6_tree]
        }
