import csv
import io
import netaddr
from typing import List, Dict, Any, Optional

from utils.vlan_purposes import describe_vlan

def generate_solarwinds_csv(tree_data: Dict[str, List[Dict]]) -> str:
    """
    Generates a SolarWinds-compatible CSV for Subnet Import matching Phase 2 requirements.

    Required CSV column order:
    1. Id (sequential int starting at 1)
    2. Address (IP only, no /prefix; blank for Group rows)
    3. CIDR (just the prefix length number; blank for Group rows)
    4. Type (one of: Group, Supernet, Subnet, GlobalPrefix, PrefixAggregate, IPv6Subnet)
    5. Display Name
    6. ParentId (Id of parent row, 0 for top-level)
    7. Group Description
    8. Node Expunge Interval
    9. Retain User Data (False)
    10. Transient Period
    11. Disable Auto Scanning (False)
    12. Disable Neighbor Scanning (True for Group/Supernet/GlobalPrefix/PrefixAggregate; False for Subnet/IPv6Subnet)
    13. VLAN
    14. Location
    15. Scan Interval
    16. Neighbor Scan Address
    17. Neighbor Scan Interval
    """
    # 1. Pre-scan for all "real" CIDRs (source != "Aggregate") to support host-route rollup dedupe
    real_cidrs = set()
    def scan_real(nodes):
        for n in nodes:
            if n.get("source") != "Aggregate":
                real_cidrs.add(n.get("cidr"))
            scan_real(n.get("children", []))

    scan_real(tree_data.get("ipv4", []))
    scan_real(tree_data.get("ipv6", []))

    emitted_rows = []
    next_id = 1

    # Define Roots
    # Id=1: IPv4 Group, Id=2: IPv6 Group
    emitted_rows.append({
        "Id": 1, "ParentId": 0, "Type": "Group", "Display Name": "IPv4 Group",
        "Address": "", "CIDR": "", "node": {}, "is_synthesized": False, "is_v6": False, "network": None
    })
    emitted_rows.append({
        "Id": 2, "ParentId": 0, "Type": "Group", "Display Name": "IPv6 Group",
        "Address": "", "CIDR": "", "node": {}, "is_synthesized": False, "is_v6": True, "network": None
    })
    next_id = 3

    ipv4_group_id = 1
    ipv6_group_id = 2

    synthesized_rollups = {} # (parent_id, rollup_cidr) -> row_id
    absorbed_nodes = {} # row_id -> list of node dicts
    # Host routes whose rollup /24 or /64 already exists somewhere in the tree
    # as a real emitted row. Resolved after both walks complete, since the real
    # row may not have been emitted yet when the host route is encountered.
    deferred_host_absorptions = [] # list of (rollup_cidr, host_node)

    def process_tree(nodes, current_parent_id, is_v6):
        nonlocal next_id
        for n in nodes:
            cidr = n.get("cidr", "")
            source = n.get("source", "Unknown")
            role = n.get("role", "subnet")

            try:
                # 8. Skip nodes with unparseable CIDR (but recurse children)
                network = netaddr.IPNetwork(cidr)
            except netaddr.AddrFormatError:
                process_tree(n.get("children", []), current_parent_id, is_v6)
                continue

            # 5. Skip Aggregate source (but recurse children)
            if source == "Aggregate":
                process_tree(n.get("children", []), current_parent_id, is_v6)
                continue

            # 6. Skip synthetic groups (loopback_group, host_route_group)
            if role in ("loopback_group", "host_route_group"):
                process_tree(n.get("children", []), current_parent_id, is_v6)
                continue

            # 6. Skip absorbed roles (endpoint, vip) - they don't get their own row
            if role in ("endpoint", "vip"):
                absorbed_nodes.setdefault(current_parent_id, []).append(n)
                continue

            # 3. Host-route rollup logic
            is_host_route = network.prefixlen == (128 if is_v6 else 32)
            if is_host_route:
                rollup_prefixlen = 64 if is_v6 else 24
                rollup_net = network.supernet(rollup_prefixlen)[0]
                rollup_cidr = str(rollup_net.cidr)

                # If a real node with this rollup CIDR exists anywhere in the tree,
                # defer absorption until after the walk so we can attach to the
                # correct row_id rather than the (possibly root) current parent.
                if rollup_cidr in real_cidrs:
                    deferred_host_absorptions.append((rollup_cidr, n))
                    continue

                # If we've already synthesized this rollup for this parent, skip (absorbed)
                key = (current_parent_id, rollup_cidr)
                if key in synthesized_rollups:
                    row_id = synthesized_rollups[key]
                    absorbed_nodes.setdefault(row_id, []).append(n)
                    continue

                # Synthesize a new rollup row at /24 or /64.
                # The seed node `n` is stored as the row template (`node`); the
                # writer pass includes it via `[n] + absorbed_nodes[row_id]`, so
                # do NOT also add it to absorbed_nodes here.
                row_id = next_id
                next_id += 1
                synthesized_rollups[key] = row_id

                emitted_rows.append({
                    "Id": row_id,
                    "ParentId": current_parent_id,
                    "Address": str(rollup_net.ip),
                    "CIDR": str(rollup_net.prefixlen),
                    "node": n, # Use this host node as template for metadata
                    "is_synthesized": True,
                    "is_v6": is_v6,
                    "network": rollup_net
                })
                continue

            # Regular emitted node (Subnet/Supernet/etc.)
            row_id = next_id
            next_id += 1

            emitted_rows.append({
                "Id": row_id,
                "ParentId": current_parent_id,
                "Address": str(network.ip),
                "CIDR": str(network.prefixlen),
                "node": n,
                "is_synthesized": False,
                "is_v6": is_v6,
                "network": network
            })

            # 7. Tunnel groups: one row, don't recurse into children (absorbed instead)
            if role == "tunnel_group":
                for c in n.get("children", []):
                    absorbed_nodes.setdefault(row_id, []).append(c)
            else:
                process_tree(n.get("children", []), row_id, is_v6)

    # Walk both trees starting from respective roots
    process_tree(tree_data.get("ipv4", []), ipv4_group_id, False)
    process_tree(tree_data.get("ipv6", []), ipv6_group_id, True)

    # Resolve deferred host absorptions: attach each host /32 (or /128) whose
    # rollup CIDR matched an existing real row to that row's absorbed_nodes,
    # so device/interface metadata is preserved instead of dropped at root.
    cidr_to_row_id = {}
    for row in emitted_rows:
        if row.get("Type") == "Group":
            continue
        canonical = f"{row['Address']}/{row['CIDR']}"
        cidr_to_row_id.setdefault(canonical, row["Id"])

    for rollup_cidr, host_node in deferred_host_absorptions:
        target_id = cidr_to_row_id.get(rollup_cidr)
        if target_id is not None:
            absorbed_nodes.setdefault(target_id, []).append(host_node)

    # Secondary pass to determine Types and build final field values
    has_children_ids = {row["ParentId"] for row in emitted_rows}

    output = io.StringIO()
    fieldnames = [
        "Id", "Address", "CIDR", "Type", "Display Name", "ParentId",
        "Group Description", "Node Expunge Interval", "Retain User Data",
        "Transient Period", "Disable Auto Scanning", "Disable Neighbor Scanning",
        "VLAN", "Location", "Scan Interval", "Neighbor Scan Address", "Neighbor Scan Interval"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in emitted_rows:
        row_id = row["Id"]

        # Handle Root Groups
        if row.get("Type") == "Group":
            writer.writerow({
                "Id": row_id,
                "Address": "",
                "CIDR": "",
                "Type": "Group",
                "Display Name": row["Display Name"],
                "ParentId": 0,
                "Node Expunge Interval": "",
                "Retain User Data": "False",
                "Transient Period": "",
                "Disable Auto Scanning": "False",
                "Disable Neighbor Scanning": "True",
                "VLAN": "", "Location": "", "Scan Interval": "",
                "Neighbor Scan Address": "", "Neighbor Scan Interval": ""
            })
            continue

        n = row["node"]
        is_v6 = row["is_v6"]
        network = row["network"]

        # 2. Type Determination Logic
        rtype = ""
        if is_v6:
            # IPv6 threshold rules
            plen = network.prefixlen
            if plen <= 48: rtype = "GlobalPrefix"
            elif plen <= 63: rtype = "PrefixAggregate"
            else: rtype = "IPv6Subnet"
        else:
            # IPv4 children rules
            if row_id in has_children_ids: rtype = "Supernet"
            else: rtype = "Subnet"

        # 4. Display Name Composition
        source = n.get("source", "")
        disp = n.get("display_name", "")

        # For synthesized rollups, the seed node's display name is order-dependent
        # when multiple hosts roll up. Use a deterministic count-based name in that
        # case; preserve the seed's name when only one host rolled up.
        if row["is_synthesized"]:
            host_count = 1 + len(absorbed_nodes.get(row_id, []))
            if host_count > 1:
                disp = f"Rollup ({host_count} hosts)"
            else:
                try:
                    netaddr.IPAddress(disp)
                    disp = "Rollup"
                except (netaddr.AddrFormatError, ValueError):
                    pass

        if source and disp:
            dname = f"{source}: {disp}"
        elif source:
            dname = source
        elif disp:
            dname = disp
        else:
            dname = f"Imported {rtype}"

        # 8. Group Description Composition
        # Collect info from the node itself plus all absorbed nodes (endpoints, vips, hosts)
        nodes_to_describe = [n] + absorbed_nodes.get(row_id, [])
        devices, ifaces, conflicts, overlaps = [], [], [], []

        for ad in nodes_to_describe:
            d = ad.get("device")
            if d and d not in devices: devices.append(d)
            i = ad.get("interface_name")
            if i and i not in ifaces: ifaces.append(i)

            cfls = ad.get("conflicts", [])
            if isinstance(cfls, str): cfls = [cfls]
            for c in cfls:
                if c and str(c) not in conflicts: conflicts.append(str(c))

            ovls = ad.get("overlaps", [])
            if isinstance(ovls, str): ovls = [ovls]
            for o in ovls:
                if o and str(o) not in overlaps: overlaps.append(str(o))

        # 8. Field Mapping (VLAN & Location)
        vlan = n.get("vlan_id")

        # Short Group Description: prefer a VLAN purpose label when we know it,
        # then a compact "VLAN {id} - device / iface" for unmapped VLANs,
        # then fall back to the original Device/Interface format. Conflicts and
        # Overlaps are always appended when present so they remain discoverable
        # in SolarWinds.
        purpose = describe_vlan(vlan)
        if purpose:
            base = purpose
        elif vlan is not None:
            ctx_parts = []
            if devices: ctx_parts.append(", ".join(devices))
            if ifaces: ctx_parts.append(", ".join(ifaces))
            base = f"VLAN {vlan}"
            if ctx_parts:
                base += " — " + " / ".join(ctx_parts)
        else:
            legacy = []
            if devices: legacy.append(f"Device: {', '.join(devices)}")
            if ifaces: legacy.append(f"Interface: {', '.join(ifaces)}")
            base = " | ".join(legacy)

        warn_parts = []
        if conflicts: warn_parts.append(f"Conflicts: {'; '.join(conflicts)}")
        if overlaps: warn_parts.append(f"Overlaps: {'; '.join(overlaps)}")
        gdesc = " | ".join(p for p in ([base] + warn_parts) if p)
        loc = n.get("site")
        if loc == "Unknown": loc = ""

        # 12. Neighbor Scanning rules
        dns = "True" if rtype in ("Supernet", "GlobalPrefix", "PrefixAggregate") else "False"

        writer.writerow({
            "Id": row_id,
            "Address": row["Address"],
            "CIDR": row["CIDR"],
            "Type": rtype,
            "Display Name": dname,
            "ParentId": row["ParentId"],
            "Group Description": gdesc,
            "Node Expunge Interval": "",
            "Retain User Data": "False",
            "Transient Period": "",
            "Disable Auto Scanning": "False",
            "Disable Neighbor Scanning": dns,
            "VLAN": vlan if vlan is not None else "",
            "Location": loc or "",
            "Scan Interval": "",
            "Neighbor Scan Address": "",
            "Neighbor Scan Interval": ""
        })

    return output.getvalue()
