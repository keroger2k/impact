import csv
import io
from typing import List

def generate_solarwinds_csv(nodes: List[dict]) -> str:
    """
    Generates a SolarWinds-compatible CSV for Subnet Import with extended fields.
    """
    output = io.StringIO()
    # Fields: cidr, host_ip, interface_type, interface_name, vlan_id, role, site, device, source, conflicts, notes
    # We also keep some SolarWinds compatible names for backward compatibility if needed,
    # but the prompt specifically asked for this list.
    fieldnames = [
        "cidr", "host_ip", "interface_type", "interface_name",
        "vlan_id", "role", "site", "device", "source", "conflicts", "notes"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    def flatten(node_list):
        for node in node_list:
            # Skip container rows for tunnel_group; we only want the endpoints
            if node.get("role") == "tunnel_group":
                if node.get("children"):
                    flatten(node["children"])
                continue

            # Skip loopback_group and host_route_group as they are synthetic
            if node.get("role") in ["loopback_group", "host_route_group"]:
                if node.get("children"):
                    flatten(node["children"])
                continue

            writer.writerow({
                "cidr": node.get("cidr", ""),
                "host_ip": node.get("host_ip", ""),
                "interface_type": node.get("interface_type", ""),
                "interface_name": node.get("interface_name", ""),
                "vlan_id": node.get("vlan_id", ""),
                "role": node.get("role", ""),
                "site": node.get("site", ""),
                "device": node.get("device", ""),
                "source": node.get("source", ""),
                "conflicts": "; ".join(node.get("conflicts", [])) if isinstance(node.get("conflicts"), list) else "",
                "notes": "; ".join(node.get("overlaps", [])) if isinstance(node.get("overlaps"), list) else ""
            })
            if node.get("children"):
                flatten(node["children"])

    flatten(nodes)
    return output.getvalue()
