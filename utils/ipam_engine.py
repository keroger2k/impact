import logging
import time
import ipaddress
import asyncio
from typing import List, Dict, Set, Optional
from netaddr import IPAddress, IPNetwork, cidr_merge, iprange_to_cidrs as summarize_address_range
from cache import cache, TTL_DEVICES

logger = logging.getLogger(__name__)

def canonicalize_ip(ip_str: str) -> str:
    """Convert IPv6 to RFC 5952 canonical form, or return IPv4 as is."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address):
            return str(ip.compressed)
        return str(ip)
    except ValueError:
        return ip_str

class IPAMDiscoveryEngine:
    def __init__(self, session=None):
        self.session = session
        self.configured_subnets: List[IPNetwork] = []
        self.active_endpoints: Dict[str, Dict] = {} # Key: Canonical IP
        self.master_ip_map: Dict[str, Dict] = {} # Key: Canonical IP
        self.orphaned_ips: List[str] = []
        self.dual_stack_gaps: List[Dict] = []
        self.stats = {
            "aci": 0,
            "ise": 0,
            "dnac": 0,
            "nexus": 0,
            "panorama": 0,
            "total_active": 0,
            "orphaned": 0,
            "gaps": 0
        }

    async def run(self):
        start_time = time.time()
        logger.info("Starting IPAM Discovery Engine...")

        # 1. Fetch data from all sources
        await self._fetch_all_data()

        # 2. Build Master IP Map & Reconciliation
        self._reconcile()

        # 3. Save snapshot to cache
        self._save_snapshot()

        duration = time.time() - start_time
        logger.info(f"IPAM Discovery completed in {duration:.2f} seconds.")

    async def _fetch_all_data(self):
        import auth as auth_module
        import clients.aci as aci_module
        import clients.ise as ise_module
        import clients.dnac as dnac_module
        import clients.panorama as pan_module
        from routers.nexus import get_cached_nexus_interfaces

        loop = asyncio.get_event_loop()

        from logger_config import run_with_context
        # ACI
        aci_client = auth_module.get_aci_for_session(self.session)
        bd_subnets_raw = await loop.run_in_executor(None, run_with_context(aci_client.get_bd_subnets))
        endpoints_raw = await loop.run_in_executor(None, run_with_context(aci_client.get_active_endpoints))

        for item in bd_subnets_raw.get('imdata', []):
            ip_str = item.get('fvSubnet', {}).get('attributes', {}).get('ip')
            if ip_str:
                try:
                    self.configured_subnets.append(IPNetwork(ip_str))
                except Exception: pass

        for item in endpoints_raw.get('imdata', []):
            attr = item.get('fvCEp', {}).get('attributes', {})
            # A fvCEp has a primary 'ip' attribute, but may also have child fvIp objects for multiple IPs
            ips_to_process = set()
            primary_ip = attr.get('ip')
            if primary_ip and primary_ip != "0.0.0.0":
                ips_to_process.add(canonicalize_ip(primary_ip))

            # Check for child fvIp objects
            children = item.get('fvCEp', {}).get('children', [])
            for child in children:
                fvip_attr = child.get('fvIp', {}).get('attributes', {})
                child_ip = fvip_attr.get('addr')
                if child_ip and child_ip != "0.0.0.0":
                    ips_to_process.add(canonicalize_ip(child_ip))

            for ip in ips_to_process:
                self.stats["aci"] += 1
                self._add_active_endpoint(ip, {
                    "source": "ACI",
                    "mac": attr.get('mac'),
                    "dn": attr.get('dn'),
                    "location": f"EPG: {attr.get('dn').split('/epg-')[-1] if '/epg-' in attr.get('dn') else 'Unknown'}",
                    "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                })

        # ISE
        ise_client = auth_module.get_ise_for_session(self.session)
        sessions_raw = await loop.run_in_executor(None, run_with_context(ise_module.get_active_sessions, ise_client))
        for s in sessions_raw:
            ip = canonicalize_ip(s.get('framed_ip_address'))
            if ip and ip != "0.0.0.0":
                self.stats["ise"] += 1
                self._add_active_endpoint(ip, {
                    "source": "ISE",
                    "mac": s.get('calling_station_id'),
                    "user": s.get('user_name'),
                    "sgt": s.get('sgt'),
                    "location": f"SGT: {s.get('sgt') or 'N/A'}",
                    "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                }, priority=False)

        # DNAC
        dnac_client = auth_module.get_dnac_for_session(self.session)
        devices = cache.get("devices")
        if not devices:
             devices = await loop.run_in_executor(None, run_with_context(dnac_module.get_all_devices, dnac_client))

        for d in devices:
            ip = canonicalize_ip(d.get('managementIpAddress'))
            if ip:
                self.stats["dnac"] += 1
                self._add_active_endpoint(ip, {
                    "source": "DNAC",
                    "mac": d.get('macAddress'), # Might be None
                    "location": f"Device: {d.get('hostname')}",
                    "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                })

        # Nexus
        nexus_ifaces = get_cached_nexus_interfaces()
        for i in nexus_ifaces:
            ip_with_prefix = i.get('ipv4_address')
            if ip_with_prefix and ip_with_prefix != "N/A":
                ip = canonicalize_ip(ip_with_prefix.split('/')[0])
                self.stats["nexus"] += 1
                self._add_active_endpoint(ip, {
                    "source": "Nexus",
                    "mac": i.get('mac_address'),
                    "location": f"Switch: {i.get('hostname')} ({i.get('interface_name')})",
                    "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                })

        # Panorama
        pan_key = auth_module.get_panorama_key_for_session(self.session)
        if pan_key:
            pan_devices = await loop.run_in_executor(None, run_with_context(pan_module.fetch_firewall_interfaces, pan_key))
            for dev in pan_devices:
                for iface in dev.get('interfaces', []):
                    # IPv4
                    v4 = iface.get('ipv4')
                    if v4:
                        ip = canonicalize_ip(v4.split('/')[0])
                        self.stats["panorama"] += 1
                        self._add_active_endpoint(ip, {
                            "source": "Panorama",
                            "location": f"Firewall: {dev.get('hostname')} ({iface.get('name')})",
                            "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                        })
                    # IPv6
                    for v6 in iface.get('ipv6', []):
                        ip = canonicalize_ip(v6.split('/')[0])
                        self.stats["panorama"] += 1
                        self._add_active_endpoint(ip, {
                            "source": "Panorama",
                            "location": f"Firewall: {dev.get('hostname')} ({iface.get('name')})",
                            "last_discovered": time.strftime("%m/%d/%Y %H:%M:%S")
                        })

    def _add_active_endpoint(self, ip: str, data: Dict, priority: bool = True):
        if ip not in self.active_endpoints:
            # Create a copy of data to avoid mutating the same dict object multiple times if shared
            self.active_endpoints[ip] = data.copy()
            self.active_endpoints[ip]['all_sources'] = [data.copy()]
        else:
            self.active_endpoints[ip]['all_sources'].append(data.copy())

            # Weighted Authority Implementation:
            # 1. If existing source is ACI, never overwrite it (ACI is top authority)
            # 2. If new data is from ACI, always overwrite current info
            # 3. Otherwise, use priority flag (default True for non-ACI sources to fill gaps)

            current_source = self.active_endpoints[ip].get('source')
            new_source = data.get('source')

            should_update = False
            if current_source == "ACI":
                should_update = False # ACI is already the source, don't downgrade
            elif new_source == "ACI":
                should_update = True # New data is ACI, upgrade to it
            elif priority:
                should_update = True # Standard priority update for others

            if should_update:
                # Update primary info but keep metadata
                for k, v in data.items():
                    if k != 'all_sources':
                        self.active_endpoints[ip][k] = v

    def _reconcile(self):
        self.stats["total_active"] = len(self.active_endpoints)

        # Build MAC to IPs map for Dual-Stack Gaps
        mac_to_ips: Dict[str, Set[str]] = {}

        for ip, data in self.active_endpoints.items():
            # Check if Orphaned
            is_orphaned = True
            try:
                ip_obj = IPAddress(ip)
                for subnet in self.configured_subnets:
                    if ip_obj in subnet:
                        is_orphaned = False
                        data['subnet'] = str(subnet)
                        break
            except Exception: pass

            if is_orphaned:
                self.orphaned_ips.append(ip)
                data['status'] = "Orphaned"
                self.stats["orphaned"] += 1
            else:
                data['status'] = "Configured"

            # Prepare for Dual-Stack analysis
            mac = data.get('mac')
            if mac and mac != "N/A":
                if mac not in mac_to_ips: mac_to_ips[mac] = set()
                mac_to_ips[mac].add(ip)

        # Dual-Stack Gaps
        for mac, ips in mac_to_ips.items():
            has_v4 = any(':' not in ip for ip in ips)
            has_v6 = any(':' in ip for ip in ips)
            if has_v4 != has_v6:
                self.stats["gaps"] += 1
                self.dual_stack_gaps.append({
                    "mac": mac,
                    "ips": list(ips),
                    "missing": "IPv6" if has_v4 else "IPv4"
                })

        self.master_ip_map = self.active_endpoints

    def _save_snapshot(self):
        snapshot = {
            "stats": self.stats,
            "master_ip_map": self.master_ip_map,
            "orphaned_ips": self.orphaned_ips,
            "dual_stack_gaps": self.dual_stack_gaps,
            "last_run": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        cache.set("ipam_snapshot", snapshot, ttl=86400) # 24h

def get_ipam_snapshot():
    return cache.get("ipam_snapshot")
