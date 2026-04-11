import logging
from typing import List, Dict
from cache import cache

logger = logging.getLogger(__name__)

def correlate_next_hops(ips: List[str]) -> List[Dict]:
    """
    Given a list of IP addresses (potential next hops),
    attempt to correlate them to known devices in our inventory.
    """
    if not ips:
        return []

    # Get inventory from cache
    devices = cache.get("devices") or []
    pan_interfaces = cache.get("pan_interfaces") or []

    # Fast lookup maps
    dnac_map = {d.get("managementIpAddress"): d for d in devices if d.get("managementIpAddress")}

    # Panorama map: IP -> Firewall hostname
    pan_map = {}
    for entry in pan_interfaces:
        iface = entry.get("interface", {})
        dev = entry.get("device", {})
        ipv4 = iface.get("ipv4")
        if isinstance(ipv4, list):
            for ip_val in ipv4:
                # Clean CIDR notation if present
                ip_clean = ip_val.split('/')[0]
                pan_map[ip_clean] = dev.get("hostname", "Unknown Firewall")
        elif ipv4:
            ip_clean = ipv4.split('/')[0]
            pan_map[ip_clean] = dev.get("hostname", "Unknown Firewall")

    results = []
    # Deduplicate input IPs
    unique_ips = sorted(list(set(ips)))

    for ip in unique_ips:
        if not ip: continue

        # Clean IP (remove masks if passed)
        ip_clean = ip.split('/')[0]

        match = {
            "ip": ip,
            "hostname": None,
            "type": None,
            "id": None
        }

        # Check DNAC
        if ip_clean in dnac_map:
            d = dnac_map[ip_clean]
            match["hostname"] = d.get("hostname")
            match["type"] = "Cisco Device"
            match["id"] = d.get("id")
        # Check Panorama
        elif ip_clean in pan_map:
            match["hostname"] = pan_map[ip_clean]
            match["type"] = "Firewall Interface"

        if match["hostname"]:
            results.append(match)

    return results
