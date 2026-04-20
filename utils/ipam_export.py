import csv
import io
from typing import List

def generate_solarwinds_csv(nodes: List[dict]) -> str:
    """
    Generates a SolarWinds-compatible CSV for Subnet Import.
    Required Columns: Type, Address, CIDR, Display Name, Description, Location, VLAN
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "Type", "Address", "CIDR", "Display Name", "Description", "Location", "VLAN"
    ])
    writer.writeheader()

    def flatten(node_list):
        for node in node_list:
            writer.writerow({
                "Type": node["type"],
                "Address": node["address"],
                "CIDR": node["prefix"],
                "Display Name": node["display_name"],
                "Description": node["description"],
                "Location": node["site"],
                "VLAN": node["vlan"]
            })
            if node["children"]:
                flatten(node["children"])

    flatten(nodes)
    return output.getvalue()
