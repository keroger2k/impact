import csv
import io
from typing import Dict, List
from netaddr import IPNetwork

def generate_solarwinds_csv(master_ip_map: Dict[str, Dict]) -> str:
    """
    Generate a SolarWinds IPAM compatible CSV.
    Columns: IP Address, CIDR, Status, MAC Address, Description, Last_Discovered
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow(["IP Address", "CIDR", "Status", "MAC Address", "Description", "Last_Discovered"])

    for ip, data in master_ip_map.items():
        # SolarWinds CIDR often refers to the subnet prefix length
        subnet = data.get('subnet', '')
        cidr = subnet.split('/')[-1] if '/' in subnet else ""

        status = data.get('status', 'Active')
        mac = data.get('mac', '')
        if mac == "N/A": mac = ""

        # Build description/comments
        sources = []
        for s in data.get('all_sources', []):
            src_str = f"Found in {s['source']}"
            if s.get('location'): src_str += f" ({s['location']})"
            if s.get('user'): src_str += f" | User: {s['user']}"
            if s.get('sgt'): src_str += f" | SGT: {s['sgt']}"
            sources.append(src_str)

        description = " | ".join(sources)
        last_discovered = data.get('last_discovered', '')

        writer.writerow([ip, cidr, status, mac, description, last_discovered])

    return output.getvalue()
