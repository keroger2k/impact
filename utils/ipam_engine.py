import logging
import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set, Tuple
import netaddr
from cache import cache
import auth as auth_module
import clients.aci as aci_client_mod

logger = logging.getLogger(__name__)

# RFC 1918 ranges to exclude from IPAM tree (management networks)
EXCLUDED_RANGES = [
    netaddr.IPNetwork("192.168.0.0/16"),
]

# Regex patterns for interfaces/links to exclude (HA, keepalives, etc.)
HA_PATTERNS = re.compile(r"KEEPALIVE|FAILOVER|HA-LINK|HEARTBEAT", re.IGNORECASE)

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
        self.conflicts = []

    def to_dict(self) -> Dict:
        return {
            "cidr": self.cidr,
            "source": self.source,
            "display_name": self.display_name,
            "site": self.site,
            "device": self.device,
            "logical_container": self.logical_container,
            "conflicts": self.conflicts,
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
        # Check RFC 1918 range
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
        try:
            aci_client = auth_module.get_aci_for_session(session)
            # Fetch BD subnets
            subnets = await loop.run_in_executor(None, aci_client.get_all_subnets)
            for s in subnets:
                ip_cidr = s.get('ip')
                if not ip_cidr: continue

                try:
                    net = netaddr.IPNetwork(ip_cidr)
                    if self.is_excluded(net): continue

                    node = IPAMNode(str(net.cidr), source="ACI")
                    node.display_name = s.get('name') or s.get('dn').split('/')[-1]
                    node.site = "Fabric"
                    node.logical_container = s.get('dn').split('/')[1] # Tenant
                    self.subnets.append(node)
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"ACI discovery failed: {e}")

    async def _discover_dnac(self, session, loop):
        try:
            dnac = auth_module.get_dnac_for_session(session)
            import clients.dnac as dc

            # Use cached devices/sites if available
            from cache import cache, TTL_DEVICES, TTL_SITES
            devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "devices", lambda: dc.get_all_devices(dnac), TTL_DEVICES)
            sites = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "sites", lambda: dc.get_site_cache(dnac), TTL_SITES)
            dev_site_map = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "device_site_map", lambda: dc.build_device_site_map(dnac, sites), TTL_SITES)

            for dev in devices:
                ip = dev.get('managementIpAddress')
                if not ip: continue

                site = dev_site_map.get(dev.get('id'), "Unknown")
                try:
                    # Assume management is /24 if not specified for tree building
                    net = netaddr.IPNetwork(f"{ip}/24")
                    if self.is_excluded(net): continue

                    node = IPAMNode(str(net.cidr), source="DNAC")
                    node.display_name = dev.get('hostname', 'Unknown')
                    node.site = site
                    node.device = dev.get('hostname')
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
                        self.subnets.append(node)
                    except Exception: pass
        except Exception as e:
            logger.error(f"Nexus discovery failed: {e}")

    def build_tree(self):
        """Construct a recursive hierarchy from the flat subnets list."""
        # 1. Deduplicate subnets (ACI > DNAC > Nexus > Panorama)
        priority = ["ACI", "DNAC", "Nexus", "Panorama"]
        unique_nets: Dict[str, IPAMNode] = {}

        for source in priority:
            for s in [n for n in self.subnets if n.source == source]:
                if s.cidr not in unique_nets:
                    unique_nets[s.cidr] = s
                else:
                    # Check for conflicts
                    existing = unique_nets[s.cidr]
                    if existing.site != s.site and s.site != "Unknown":
                        existing.conflicts.append({
                            "type": "Site Conflict",
                            "source": s.source,
                            "val": s.site
                        })

        # 2. Sort by prefix length (broadest first)
        v4_nets = sorted([n for n in unique_nets.values() if n.version == 4],
                         key=lambda x: (x.prefixlen, x.ip_int))
        v6_nets = sorted([n for n in unique_nets.values() if n.version == 6],
                         key=lambda x: (x.prefixlen, x.ip_int))

        # 3. Build recursive tree
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
        for r in roots:
            d = r.to_dict()
            if r.children_nodes:
                # Recurse for children
                d["children"] = self._recursive_build(r.children_nodes)
            result.append(d)
        return result

    def get_tree(self):
        return self.tree

from logger_config import run_with_context
