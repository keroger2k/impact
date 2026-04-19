import sys
import os
import asyncio
import netaddr
from utils.ipam_engine import IPAMEngine, IPAMNode

async def test_tree_building():
    engine = IPAMEngine()

    # Mock some subnets
    s1 = IPAMNode("10.0.0.0/24", source="ACI")
    s1.site = "Chicago"
    s1.display_name = "ACI-Subnet-1"

    s2 = IPAMNode("10.0.1.0/24", source="ACI")
    s2.site = "Chicago"
    s2.display_name = "ACI-Subnet-2"

    s3 = IPAMNode("10.1.0.0/16", source="Panorama")
    s3.site = "Global"
    s3.display_name = "Pan-Supernet"

    s4 = IPAMNode("10.1.1.0/24", source="Nexus")
    s4.site = "Chicago"
    s4.display_name = "Nexus-Vlan10"

    s5 = IPAMNode("10.1.1.0/24", source="ACI") # Conflict with s4 (priority should win)
    s5.site = "NewYork"
    s5.display_name = "ACI-Vlan10"

    s6 = IPAMNode("8.8.8.0/24", source="Public")
    s6.site = "Internet"

    s7 = IPAMNode("fc00:1::/64", source="ACI")
    s7.logical_container = "BD-1"

    s8 = IPAMNode("10.0.0.0/24", source="ACI") # Duplicate IP, same site - should dedupe
    s8.site = "Chicago"

    engine.subnets = [s1, s2, s3, s4, s5, s6, s7, s8]

    print("Building tree...")
    engine.build_tree()

    tree = engine.get_tree()

    print("\nIPv4 Tree Structure:")
    def print_node(node, indent=0):
        print("  " * indent + f"- {node['cidr']} ({node['type']}) [Source: {node['source']}] [Site: {node['site']}]")
        if node['conflicts']:
            print("  " * (indent+1) + f"Conflicts: {node['conflicts']}")
        if node['overlaps']:
            print("  " * (indent+1) + f"Overlaps: {node['overlaps']}")
        for child in node['children']:
            print_node(child, indent + 1)

    for node in tree['ipv4']:
        print_node(node)

    print("\nIPv6 Tree Structure:")
    for node in tree['ipv6']:
        print_node(node)

if __name__ == "__main__":
    asyncio.run(test_tree_building())
