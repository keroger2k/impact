import unittest
import netaddr
from utils.ipam_engine import IPAMEngine, IPAMNode, classify_interface, _normalize_ipv6_entry


class TestIPv6Normalizer(unittest.TestCase):
    def test_string_with_prefix(self):
        self.assertEqual(_normalize_ipv6_entry("2001:db8::1/64"), "2001:db8::1/64")

    def test_string_without_prefix_defaults_to_64(self):
        self.assertEqual(_normalize_ipv6_entry("2001:db8::1"), "2001:db8::1/64")

    def test_dict_with_prefix(self):
        e = {"address": "2001:db8::1", "prefix": "64", "addressType": "GLOBAL"}
        self.assertEqual(_normalize_ipv6_entry(e), "2001:db8::1/64")

    def test_dict_with_prefix_length_field(self):
        e = {"address": "2001:db8::1", "prefixLength": "48"}
        self.assertEqual(_normalize_ipv6_entry(e), "2001:db8::1/48")

    def test_dict_without_prefix_defaults_to_64(self):
        self.assertEqual(_normalize_ipv6_entry({"address": "2001:db8::1"}), "2001:db8::1/64")

    def test_dict_alternate_address_keys(self):
        self.assertEqual(_normalize_ipv6_entry({"ipAddress": "2001:db8::1", "prefix": "48"}),
                         "2001:db8::1/48")
        self.assertEqual(_normalize_ipv6_entry({"ip": "2001:db8::1", "prefix": "48"}),
                         "2001:db8::1/48")

    def test_empty_or_unrecognized(self):
        self.assertIsNone(_normalize_ipv6_entry(None))
        self.assertIsNone(_normalize_ipv6_entry(""))
        self.assertIsNone(_normalize_ipv6_entry({}))
        self.assertIsNone(_normalize_ipv6_entry(42))

class TestIPAMEngine(unittest.TestCase):
    def setUp(self):
        self.engine = IPAMEngine()

    def test_classify_interface(self):
        # Tunnel
        self.assertEqual(classify_interface("Tunnel100", netaddr.IPNetwork("10.1.1.1/24"))[0], "tunnel")
        self.assertEqual(classify_interface("Tu1", netaddr.IPNetwork("10.1.1.1/32"))[0], "tunnel")

        # Loopback
        self.assertEqual(classify_interface("Loopback0", netaddr.IPNetwork("10.1.1.1/24"))[0], "loopback")
        self.assertEqual(classify_interface("Lo5", netaddr.IPNetwork("10.1.1.1/24"))[0], "loopback")
        self.assertEqual(classify_interface("GigabitEthernet1", netaddr.IPNetwork("10.1.1.1/32"))[0], "loopback") # /32 override

        # SVI
        t, vid = classify_interface("Vlan200", netaddr.IPNetwork("10.1.1.0/24"))
        self.assertEqual(t, "svi")
        self.assertEqual(vid, 200)

        # Management
        self.assertEqual(classify_interface("mgmt0", netaddr.IPNetwork("10.1.1.1/24"))[0], "management")
        self.assertEqual(classify_interface("Management1", netaddr.IPNetwork("10.1.1.1/24"))[0], "management")
        self.assertEqual(classify_interface("Ma1", netaddr.IPNetwork("10.1.1.1/24"))[0], "management")

        # P2P
        self.assertEqual(classify_interface("Eth1/1", netaddr.IPNetwork("10.1.1.0/30"))[0], "p2p")
        self.assertEqual(classify_interface("Eth1/1", netaddr.IPNetwork("10.1.1.0/31"))[0], "p2p")

        # Physical
        self.assertEqual(classify_interface("Eth1/1", netaddr.IPNetwork("10.1.1.0/24"))[0], "physical")

    def test_tunnel_grouping_no_conflict(self):
        n1 = IPAMNode("10.1.1.0/24", source="Nexus")
        n1.interface_type = "tunnel"
        n1.interface_name = "Tunnel100"
        n1.host_ip = "10.1.1.1"
        n1.device = "RouterA"
        n1.site = "SiteA"

        n2 = IPAMNode("10.1.1.0/24", source="Nexus")
        n2.interface_type = "tunnel"
        n2.interface_name = "Tunnel100"
        n2.host_ip = "10.1.1.2"
        n2.device = "RouterB"
        n2.site = "SiteB"

        self.engine.subnets = [n1, n2]
        self.engine.build_tree()

        v4_tree = self.engine.tree["ipv4"]
        self.assertEqual(len(v4_tree), 1)
        group = v4_tree[0]
        self.assertEqual(group["role"], "tunnel_group")
        self.assertEqual(len(group["children"]), 2)
        self.assertEqual(len(group["conflicts"]), 0)

    def test_non_tunnel_same_cidr_still_conflicts(self):
        n1 = IPAMNode("10.2.0.0/24", source="ACI")
        n1.site = "SiteA"
        n1.interface_type = "physical"

        n2 = IPAMNode("10.2.0.0/24", source="Nexus")
        n2.site = "SiteB"
        n2.interface_type = "physical"

        self.engine.subnets = [n1, n2]
        self.engine.build_tree()

        v4_tree = self.engine.tree["ipv4"]
        self.assertEqual(len(v4_tree), 1)
        node = v4_tree[0]
        self.assertTrue(any("Site Conflict" in c for c in node["conflicts"]))

    def test_loopback_host_route(self):
        n = IPAMNode("10.99.0.1/32", source="Nexus")
        n.interface_name = "Loopback0"
        n.interface_type, _ = classify_interface(n.interface_name, n.network)
        n.role = "host_route"

        self.assertEqual(n.interface_type, "loopback")
        self.assertEqual(n.role, "host_route")

        self.engine.subnets = [n]
        self.engine.build_tree()
        # Should be in a "Host Routes" group because it's a root /32
        self.assertEqual(self.engine.tree["ipv4"][0]["role"], "host_route_group")

    def test_p2p_detection(self):
        n = IPAMNode("10.3.3.0/30", source="Nexus")
        n.interface_name = "Ethernet1/1"
        n.interface_type, _ = classify_interface(n.interface_name, n.network)
        self.assertEqual(n.interface_type, "p2p")

    def test_is_excluded(self):
        # 192.168/16 is NOT excluded — it's legitimate RFC1918 space in use here
        self.assertFalse(self.engine.is_excluded(netaddr.IPNetwork("192.168.1.0/24")))
        # APIPA
        self.assertTrue(self.engine.is_excluded(netaddr.IPNetwork("169.254.1.1/32")))
        # v4 Loopback
        self.assertTrue(self.engine.is_excluded(netaddr.IPNetwork("127.0.0.1/32")))
        # /32 NOT excluded if not in a special range
        self.assertFalse(self.engine.is_excluded(netaddr.IPNetwork("10.1.1.1/32")))

    def test_singleton_tunnel_preserved_when_cidr_collides_with_non_tunnel(self):
        # Regression: a lone tunnel endpoint at a CIDR already occupied by a
        # non-tunnel subnet (e.g. DNAC's hardcoded /24 mgmt subnet) used to be
        # silently dropped. It should nest under the existing subnet instead.
        mgmt = IPAMNode("10.1.1.0/24", source="DNAC")
        mgmt.interface_type = "management"
        mgmt.site = "SiteA"
        mgmt.device = "CORE-A"

        tun = IPAMNode("10.1.1.0/24", source="Nexus")
        tun.interface_type = "tunnel"
        tun.interface_name = "Tunnel10"
        tun.host_ip = "10.1.1.100"
        tun.device = "CORE-A"
        tun.site = "SiteA"

        self.engine.subnets = [mgmt, tun]
        self.engine.build_tree()

        v4 = self.engine.tree["ipv4"]
        self.assertEqual(len(v4), 1)
        self.assertEqual(v4[0]["interface_type"], "management")
        # The tunnel must still be reachable, as a child endpoint
        tunnel_children = [c for c in v4[0]["children"] if c.get("interface_type") == "tunnel"]
        self.assertEqual(len(tunnel_children), 1)
        self.assertEqual(tunnel_children[0]["role"], "endpoint")
        self.assertEqual(tunnel_children[0]["interface_name"], "Tunnel10")

    def test_tunnel_group_preserved_when_cidr_collides_with_non_tunnel(self):
        # 2+ tunnel endpoints colliding with a non-tunnel at the same CIDR
        # should nest the tunnel_group under the existing subnet, not overwrite it.
        mgmt = IPAMNode("10.2.2.0/24", source="DNAC")
        mgmt.interface_type = "management"
        mgmt.site = "SiteA"

        n1 = IPAMNode("10.2.2.0/24", source="Nexus")
        n1.interface_type = "tunnel"
        n1.interface_name = "Tunnel42"
        n1.host_ip = "10.2.2.1"
        n1.device = "RouterA"

        n2 = IPAMNode("10.2.2.0/24", source="Nexus")
        n2.interface_type = "tunnel"
        n2.interface_name = "Tunnel42"
        n2.host_ip = "10.2.2.2"
        n2.device = "RouterB"

        self.engine.subnets = [mgmt, n1, n2]
        self.engine.build_tree()

        v4 = self.engine.tree["ipv4"]
        self.assertEqual(len(v4), 1)
        self.assertEqual(v4[0]["interface_type"], "management")
        groups = [c for c in v4[0]["children"] if c.get("role") == "tunnel_group"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["children"]), 2)

    def test_vip_detection(self):
        n1 = IPAMNode("10.1.1.0/24", source="Nexus")
        n1.device = "Core1"
        n1.host_ip = "10.1.1.254"

        n2 = IPAMNode("10.1.1.0/24", source="Nexus")
        n2.device = "Core2"
        n2.host_ip = "10.1.1.254"

        self.engine.subnets = [n1, n2]
        self.engine.build_tree()

        v4_tree = self.engine.tree["ipv4"]
        subnet = v4_tree[0]
        vips = [c for c in subnet["children"] if c["role"] == "vip"]
        self.assertEqual(len(vips), 1)
        self.assertEqual(vips[0]["host_ip"], "10.1.1.254")

if __name__ == "__main__":
    unittest.main()
