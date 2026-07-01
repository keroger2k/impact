import unittest
import csv
import io
from utils.ipam_export import generate_solarwinds_csv

class TestIPAMExport(unittest.TestCase):
    def parse_csv(self, csv_str):
        f = io.StringIO(csv_str)
        reader = csv.DictReader(f)
        return list(reader)

    def test_roots_and_types(self):
        tree = {
            "ipv4": [
                {
                    "cidr": "10.0.0.0/8", "source": "DNAC-Pool", "display_name": "Global 10",
                    "children": [
                        {"cidr": "10.1.0.0/16", "source": "DNAC-Pool", "display_name": "Site A"}
                    ]
                }
            ],
            "ipv6": [
                {"cidr": "2001:db8::/32", "source": "DNAC-Pool", "display_name": "Global v6"},
                {"cidr": "2001:db8:1::/48", "source": "DNAC-Pool", "display_name": "Site v6"},
                {"cidr": "2001:db8:1:1::/64", "source": "DNAC-Pool", "display_name": "Subnet v6"}
            ]
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # Rows:
        # 1. IPv4 Group (Id=1)
        # 2. IPv6 Group (Id=2)
        # 3. 10.0.0.0/8 (Id=3, Parent=1) - Supernet (has child 10.1.0.0/16)
        # 4. 10.1.0.0/16 (Id=4, Parent=3) - Subnet
        # 5. 2001:db8::/32 (Id=5, Parent=2) - GlobalPrefix (<=48)
        # 6. 2001:db8:1::/48 (Id=6, Parent=2) - GlobalPrefix (<=48)
        # 7. 2001:db8:1:1::/64 (Id=7, Parent=2) - IPv6Subnet (>=64)

        self.assertEqual(rows[0]["Display Name"], "IPv4 Group")
        self.assertEqual(rows[0]["Type"], "Group")
        self.assertEqual(rows[1]["Display Name"], "IPv6 Group")
        self.assertEqual(rows[1]["Type"], "Group")

        self.assertEqual(rows[2]["Address"], "10.0.0.0")
        self.assertEqual(rows[2]["Type"], "Supernet")
        self.assertEqual(rows[2]["Disable Neighbor Scanning"], "True")

        self.assertEqual(rows[3]["Address"], "10.1.0.0")
        self.assertEqual(rows[3]["Type"], "Subnet")
        self.assertEqual(rows[3]["Disable Neighbor Scanning"], "False")

        self.assertEqual(rows[4]["Type"], "GlobalPrefix")
        self.assertEqual(rows[5]["Type"], "GlobalPrefix")
        self.assertEqual(rows[6]["Type"], "IPv6Subnet")

    def test_host_route_rollup(self):
        tree = {
            "ipv4": [
                {
                    "cidr": "10.1.1.0/24", "source": "DNAC", "display_name": "VLAN 10",
                    "children": [
                        {"cidr": "10.1.1.1/32", "source": "DNAC", "display_name": "Host 1", "role": "host_route", "device": "R1"}
                    ]
                },
                {
                    # No parent /24 exists for this one
                    "cidr": "10.2.2.1/32", "source": "DNAC", "display_name": "Orphan Host", "role": "host_route", "device": "R2"
                }
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group
        # 2. IPv6 Group
        # 3. 10.1.1.0/24 (Real)
        # 4. 10.2.2.0/24 (Synthesized Rollup for 10.2.2.1/32)

        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[2]["Address"], "10.1.1.0")
        self.assertEqual(rows[3]["Address"], "10.2.2.0")
        self.assertEqual(rows[3]["CIDR"], "24")
        self.assertEqual(rows[3]["Type"], "Subnet")

        # 10.1.1.1/32 should be absorbed into 10.1.1.0/24 description
        self.assertIn("Device: R1", rows[2]["Group Description"])
        # 10.2.2.1/32 should be absorbed into its rollup row description
        self.assertIn("Device: R2", rows[3]["Group Description"])
        # Display Name is the canonical CIDR for both real and synthesized rows
        self.assertEqual(rows[2]["Display Name"], "10.1.1.0/24")
        self.assertEqual(rows[3]["Display Name"], "10.2.2.0/24")

    def test_aggregate_skip(self):
        tree = {
            "ipv4": [
                {
                    "cidr": "10.0.0.0/8", "source": "Aggregate", "display_name": "RFC1918",
                    "children": [
                        {"cidr": "10.5.0.0/16", "source": "DNAC-Pool", "display_name": "Real Subnet"}
                    ]
                }
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group
        # 2. IPv6 Group
        # 3. 10.5.0.0/16 (Parent should be 1, skipping 10.0.0.0/8)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2]["Address"], "10.5.0.0")
        self.assertEqual(rows[2]["ParentId"], "1")

    def test_tunnel_group_and_description(self):
        tree = {
            "ipv4": [
                {
                    "cidr": "172.16.1.0/24", "source": "multi", "display_name": "Tunnel Network", "role": "tunnel_group",
                    "children": [
                        {"cidr": "172.16.1.1/32", "source": "Nexus", "device": "R1", "interface_name": "Tunnel0", "role": "endpoint"},
                        {"cidr": "172.16.1.2/32", "source": "Nexus", "device": "R2", "interface_name": "Tunnel0", "role": "endpoint"}
                    ]
                }
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group
        # 2. IPv6 Group
        # 3. 172.16.1.0/24 (Id=3)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2]["Type"], "Subnet")
        desc = rows[2]["Group Description"]
        self.assertIn("Device: R1, R2", desc)
        self.assertIn("Interface: Tunnel0", desc)

    def test_display_name_is_canonical_cidr(self):
        # Display Name always echoes Address/CIDR regardless of source or
        # display_name on the node, so it lines up cleanly with the Address
        # and CIDR columns in SolarWinds.
        tree = {
            "ipv4": [
                {"cidr": "1.1.1.0/24", "source": "DNAC", "display_name": "MySubnet"},
                {"cidr": "2.2.2.0/24", "source": "ACI", "display_name": ""},
                {"cidr": "3.3.3.0/24", "source": "", "display_name": "JustName"},
                {"cidr": "4.4.4.0/24", "source": "", "display_name": ""},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        self.assertEqual(rows[2]["Display Name"], "1.1.1.0/24")
        self.assertEqual(rows[3]["Display Name"], "2.2.2.0/24")
        self.assertEqual(rows[4]["Display Name"], "3.3.3.0/24")
        self.assertEqual(rows[5]["Display Name"], "4.4.4.0/24")

    def test_orphan_host_absorbed_into_existing_real_subnet(self):
        # A real /24 sits as a peer to an orphan /32 (e.g. coming out of a
        # host_route_group). The /32's metadata must end up on the /24's row,
        # not silently lost on the IPv4 root group.
        tree = {
            "ipv4": [
                {"cidr": "10.1.1.0/24", "source": "DNAC", "display_name": "VLAN 10"},
                {"cidr": "10.1.1.5/32", "source": "DNAC", "display_name": "Orphan",
                 "role": "host_route", "device": "OrphanRouter",
                 "interface_name": "Loopback0"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group, 2. IPv6 Group, 3. 10.1.1.0/24
        # The /32 should be absorbed into the /24, no extra row emitted.
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2]["Address"], "10.1.1.0")
        # OrphanRouter and its interface should land on the /24 row.
        self.assertIn("OrphanRouter", rows[2]["Group Description"])
        self.assertIn("Loopback0", rows[2]["Group Description"])

    def test_rollup_display_name_deterministic_for_multiple_hosts(self):
        # Two host routes roll up to the same synthesized /24. Display name must
        # not be order-dependent on which host happens to be first.
        tree = {
            "ipv4": [
                {"cidr": "10.9.9.1/32", "source": "DNAC", "display_name": "HostA",
                 "role": "host_route", "device": "RouterA"},
                {"cidr": "10.9.9.2/32", "source": "DNAC", "display_name": "HostB",
                 "role": "host_route", "device": "RouterB"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group, 2. IPv6 Group, 3. synthesized 10.9.9.0/24
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2]["Address"], "10.9.9.0")
        self.assertEqual(rows[2]["CIDR"], "24")
        # Display Name = canonical CIDR — deterministic by construction,
        # not order-dependent on which host happened to be first.
        self.assertEqual(rows[2]["Display Name"], "10.9.9.0/24")
        # Both hosts' device metadata must show up
        self.assertIn("RouterA", rows[2]["Group Description"])
        self.assertIn("RouterB", rows[2]["Group Description"])

    def test_default_route_zero_slash_zero_is_skipped(self):
        # SolarWinds rejects a /0 supernet on import. The exporter must drop
        # both 0.0.0.0/0 and ::/0 while still emitting any nested descendants
        # (reparented under the IPv4/IPv6 root group).
        tree = {
            "ipv4": [
                {"cidr": "0.0.0.0/0", "source": "DNAC", "display_name": "default",
                 "children": [
                     {"cidr": "10.50.0.0/16", "source": "DNAC", "display_name": "Site"}
                 ]},
                {"cidr": "172.16.0.0/12", "source": "DNAC", "display_name": "RFC1918"}
            ],
            "ipv6": [
                {"cidr": "::/0", "source": "DNAC", "display_name": "v6 default"}
            ]
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # No row should be 0.0.0.0/0 or ::/0
        addresses = [(r["Address"], r["CIDR"]) for r in rows]
        self.assertNotIn(("0.0.0.0", "0"), addresses)
        self.assertNotIn(("::", "0"), addresses)

        # Descendants of 0.0.0.0/0 reparent to the IPv4 root group (Id=1)
        site_row = next(r for r in rows if r["Address"] == "10.50.0.0")
        self.assertEqual(site_row["ParentId"], "1")

    def test_group_description_uses_vlan_purpose_when_known(self):
        # vlan_id maps to a known purpose -> description is just the short
        # label (e.g. "Data VLAN"), no Device:/Interface: clutter.
        tree = {
            "ipv4": [
                {"cidr": "10.10.10.0/24", "source": "DNAC", "display_name": "Vlan100",
                 "vlan_id": 100, "device": "core1", "interface_name": "Vlan100"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)
        self.assertEqual(rows[2]["Group Description"], "Data VLAN")
        self.assertEqual(rows[2]["VLAN"], "100")

    def test_group_description_falls_back_to_vlan_id_for_unknown_vlan(self):
        # vlan_id present but not in the purpose mapping -> compact
        # "VLAN {id} — device / iface" line.
        tree = {
            "ipv4": [
                {"cidr": "10.20.30.0/24", "source": "DNAC", "display_name": "Vlan250",
                 "vlan_id": 250, "device": "core1", "interface_name": "Vlan250"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)
        self.assertEqual(rows[2]["Group Description"], "VLAN 250 — core1 / Vlan250")

    def test_group_description_keeps_legacy_format_without_vlan(self):
        # No vlan_id -> preserve the original Device:/Interface: format so
        # SolarWinds operators still get context for non-VLAN subnets.
        tree = {
            "ipv4": [
                {"cidr": "172.16.5.0/30", "source": "Nexus", "display_name": "p2p",
                 "device": "core1", "interface_name": "Ethernet1/1"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)
        self.assertEqual(rows[2]["Group Description"],
                         "Device: core1 | Interface: Ethernet1/1")

    def test_group_description_appends_conflicts_with_vlan_purpose(self):
        # Conflicts/Overlaps must remain discoverable even when a short VLAN
        # purpose is used as the base description.
        tree = {
            "ipv4": [
                {"cidr": "10.10.10.0/24", "source": "DNAC", "display_name": "Vlan100",
                 "vlan_id": 100, "device": "core1", "interface_name": "Vlan100",
                 "conflicts": ["dup with 10.10.10.0/24 on core2"]},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)
        desc = rows[2]["Group Description"]
        self.assertTrue(desc.startswith("Data VLAN"))
        self.assertIn("Conflicts: dup with 10.10.10.0/24 on core2", desc)

    def test_synthetic_host_route_group_container_is_traversed(self):
        # The engine emits host_route_group containers with a non-CIDR string
        # like "Host Routes (SiteX)" as their cidr field. The exporter must
        # parse-fail gracefully and recurse into the group's children.
        tree = {
            "ipv4": [
                {
                    "cidr": "Host Routes (SiteX)",
                    "display_name": "Orphan Host Routes - 1 entries",
                    "role": "host_route_group",
                    "children": [
                        {"cidr": "192.0.2.5/32", "source": "DNAC",
                         "display_name": "LonelyHost", "role": "host_route",
                         "device": "EdgeRouter"},
                    ]
                }
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # 1. IPv4 Group, 2. IPv6 Group, 3. synthesized 192.0.2.0/24 rollup
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2]["Address"], "192.0.2.0")
        self.assertEqual(rows[2]["CIDR"], "24")
        self.assertIn("EdgeRouter", rows[2]["Group Description"])

    def test_synthesized_rollup_adopts_sibling_subnets(self):
        # Engine tree has /30 and /27 hanging directly off /8 because no /24
        # exists in source data. A /32 host route triggers a synthesized /24
        # rollup. Without re-parenting, that /24 and the /30/27s end up as
        # siblings under /8, and SolarWinds rejects every one as an overlap.
        # The exporter must re-parent the /30/27s under the synthesized /24.
        tree = {
            "ipv4": [
                {
                    "cidr": "10.0.0.0/8", "source": "Aggregate", "display_name": "RFC1918",
                    "children": [
                        {"cidr": "10.29.8.4/30", "source": "DNAC", "device": "R1",
                         "interface_name": "Eth1/1"},
                        {"cidr": "10.29.8.64/27", "source": "DNAC", "device": "R2",
                         "interface_name": "Vlan20"},
                        {"cidr": "10.29.8.96/27", "source": "DNAC", "device": "R3",
                         "interface_name": "Vlan30"},
                        {"cidr": "10.29.8.128/25", "source": "DNAC", "device": "R4",
                         "interface_name": "Vlan40"},
                        # Host route — triggers a synthesized 10.29.8.0/24 row.
                        {"cidr": "10.29.8.10/32", "source": "DNAC", "device": "R5",
                         "interface_name": "Loopback0", "role": "host_route"},
                    ]
                }
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        r24 = next(r for r in rows if r["Address"] == "10.29.8.0" and r["CIDR"] == "24")
        r30 = next(r for r in rows if r["Address"] == "10.29.8.4")
        r27a = next(r for r in rows if r["Address"] == "10.29.8.64")
        r27b = next(r for r in rows if r["Address"] == "10.29.8.96")
        r25 = next(r for r in rows if r["Address"] == "10.29.8.128")

        # All four real subnets must now nest under the synthesized /24
        # instead of being its peers.
        self.assertEqual(r30["ParentId"], r24["Id"])
        self.assertEqual(r27a["ParentId"], r24["Id"])
        self.assertEqual(r27b["ParentId"], r24["Id"])
        self.assertEqual(r25["ParentId"], r24["Id"])
        # The /24 itself stays at the IPv4 root group (10/8 was Aggregate-skipped).
        self.assertEqual(r24["ParentId"], "1")
        # And the /24 row now reports Supernet (it has children).
        self.assertEqual(r24["Type"], "Supernet")

    def test_reparent_uses_most_specific_containing_row(self):
        # When several supernets contain the same leaf, the leaf's parent
        # must be the most-specific one (largest prefixlen).
        tree = {
            "ipv4": [
                {"cidr": "10.0.0.0/8", "source": "DNAC", "display_name": "10/8"},
                {"cidr": "10.1.0.0/16", "source": "DNAC", "display_name": "10.1/16"},
                {"cidr": "10.1.2.0/24", "source": "DNAC", "display_name": "10.1.2/24"},
                {"cidr": "10.1.2.4/30", "source": "DNAC", "display_name": "leaf"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        r8 = next(r for r in rows if r["Address"] == "10.0.0.0")
        r16 = next(r for r in rows if r["Address"] == "10.1.0.0")
        r24 = next(r for r in rows if r["Address"] == "10.1.2.0")
        r30 = next(r for r in rows if r["Address"] == "10.1.2.4")

        # Each layer parents to the next-most-specific containing row.
        self.assertEqual(r30["ParentId"], r24["Id"])
        self.assertEqual(r24["ParentId"], r16["Id"])
        self.assertEqual(r16["ParentId"], r8["Id"])
        self.assertEqual(r8["ParentId"], "1")

    def test_every_parent_precedes_its_children(self):
        # SolarWinds resolves ParentId against already-read rows, so no row may
        # reference a parent defined later in the file. The engine can hand us a
        # /29 nested under a /23 while a /24 that belongs between them shows up
        # elsewhere in the tree; the containment re-parent pass then makes the
        # /29's parent the /24 — which, before ordering, was emitted after it.
        tree = {
            "ipv4": [
                {"cidr": "1.1.1.0/23", "source": "DNAC", "role": "subnet",
                 "children": [
                     {"cidr": "1.1.1.0/29", "source": "DNAC", "role": "subnet"},
                 ]},
                {"cidr": "1.1.1.0/24", "source": "DNAC", "role": "subnet"},
            ],
            "ipv6": []
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        # The hierarchy must be /23 -> /24 -> /29 by containment.
        r23 = next(r for r in rows if r["CIDR"] == "23")
        r24 = next(r for r in rows if r["CIDR"] == "24")
        r29 = next(r for r in rows if r["CIDR"] == "29")
        self.assertEqual(r24["ParentId"], r23["Id"])
        self.assertEqual(r29["ParentId"], r24["Id"])

        # And crucially, every row's parent must appear earlier in the file.
        seen = set()
        for r in rows:
            parent = int(r["ParentId"])
            if parent != 0:
                self.assertIn(parent, seen,
                              f"row {r['Id']} references not-yet-seen parent {parent}")
            seen.add(int(r["Id"]))

    def test_reparent_respects_ip_version_boundary(self):
        # An IPv4 row must never get parented under an IPv6 row (and vice
        # versa), even when prefix-length math would otherwise "fit".
        tree = {
            "ipv4": [
                {"cidr": "10.0.0.0/8", "source": "DNAC"},
                {"cidr": "10.1.0.0/16", "source": "DNAC"},
            ],
            "ipv6": [
                {"cidr": "2001:db8::/32", "source": "DNAC"},
                {"cidr": "2001:db8:1::/48", "source": "DNAC"},
            ]
        }
        csv_out = generate_solarwinds_csv(tree)
        rows = self.parse_csv(csv_out)

        r8 = next(r for r in rows if r["Address"] == "10.0.0.0")
        r16 = next(r for r in rows if r["Address"] == "10.1.0.0")
        r32v6 = next(r for r in rows if r["Address"] == "2001:db8::")
        r48v6 = next(r for r in rows if r["Address"] == "2001:db8:1::")

        self.assertEqual(r8["ParentId"], "1")    # IPv4 root group
        self.assertEqual(r16["ParentId"], r8["Id"])
        self.assertEqual(r32v6["ParentId"], "2")  # IPv6 root group
        self.assertEqual(r48v6["ParentId"], r32v6["Id"])


if __name__ == "__main__":
    unittest.main()
