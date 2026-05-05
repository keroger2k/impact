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
        # Display Name for rollup should be from the host route
        self.assertEqual(rows[3]["Display Name"], "DNAC: Orphan Host")

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

    def test_display_name_composition(self):
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

        self.assertEqual(rows[2]["Display Name"], "DNAC: MySubnet")
        self.assertEqual(rows[3]["Display Name"], "ACI")
        self.assertEqual(rows[4]["Display Name"], "JustName")
        self.assertEqual(rows[5]["Display Name"], "Imported Subnet")

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
        # Deterministic name: count-based, not "DNAC: HostA" or "DNAC: HostB"
        self.assertEqual(rows[2]["Display Name"], "DNAC: Rollup (2 hosts)")
        # Both hosts' device metadata must show up
        self.assertIn("RouterA", rows[2]["Group Description"])
        self.assertIn("RouterB", rows[2]["Group Description"])

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

if __name__ == "__main__":
    unittest.main()
