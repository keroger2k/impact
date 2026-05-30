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

    def _v4_roots(self):
        # build_tree() synthesizes an RFC1918 supernet (10/8, 172.16/12, 192.168/16)
        # whenever any descendant exists. These tests pre-date that feature and
        # assert against the *logical* tree root — descend through the synthetic
        # wrapper so each test can still target the subnet it created.
        v4 = self.engine.tree["ipv4"]
        if len(v4) == 1 and v4[0].get("source") == "Aggregate" and v4[0].get("role") == "supernet":
            return v4[0]["children"]
        return v4

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

        v4_tree = self._v4_roots()
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

        v4_tree = self._v4_roots()
        self.assertEqual(len(v4_tree), 1)
        node = v4_tree[0]
        self.assertTrue(any("Site Conflict" in c for c in node["conflicts"]))

    def test_loopback_host_route(self):
        # Use a non-RFC1918 /32 so the RFC1918 supernet synthesis doesn't claim
        # it as a child — we want a true top-level orphan to exercise the
        # "Host Routes" pseudo-group, which is only created at the top level.
        n = IPAMNode("100.64.0.1/32", source="Nexus")
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

        v4 = self._v4_roots()
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

        v4 = self._v4_roots()
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

        v4_tree = self._v4_roots()
        subnet = v4_tree[0]
        vips = [c for c in subnet["children"] if c["role"] == "vip"]
        self.assertEqual(len(vips), 1)
        self.assertEqual(vips[0]["host_ip"], "10.1.1.254")

    def _mk_loopback(self, cidr: str, site: str, device: str = "rtr") -> IPAMNode:
        n = IPAMNode(cidr, source="DNAC")
        n.interface_name = "Loopback0"
        n.interface_type = "loopback"
        n.role = "host_route"
        n.site = site
        n.device = device
        n.host_ip = cidr.split("/")[0]
        return n

    def _find_node(self, tree, cidr):
        """DFS for the first node with matching cidr (skipping pseudo groups)."""
        for n in tree:
            if n.get("cidr") == cidr:
                return n
            child = self._find_node(n.get("children", []), cidr)
            if child is not None:
                return child
        return None

    def test_loopback_nests_under_most_specific_subnet(self):
        # Regression: a /32 loopback was being yanked out at the topmost level
        # and dumped into a single "Loopbacks" pseudo group, even when a
        # containing /20 (or other supernet) existed at a deeper level.
        # The /32 should nest under the most-specific containing subnet.
        summary = IPAMNode("10.4.16.0/20", source="DNAC-Config")
        summary.display_name = "EIGRP Summary (Tunnel5000)"
        summary.interface_type = "aggregate"
        summary.role = "aggregate"
        summary.site = "T489"

        loop = self._mk_loopback("10.4.30.10/32", site="T489")

        # An unrelated /32 outside the /20 — should NOT end up under it.
        far_loop = self._mk_loopback("10.99.0.1/32", site="OTHER")

        self.engine.subnets = [summary, loop, far_loop]
        self.engine.build_tree()

        # The /20 must contain the loopback, either directly or via a
        # collapsed "Loopbacks (n)" pseudo group when 3+ siblings exist.
        twenty = self._find_node(self.engine.tree["ipv4"], "10.4.16.0/20")
        self.assertIsNotNone(twenty, "expected the /20 to be present in the tree")
        nested = self._find_node(twenty.get("children", []), "10.4.30.10/32")
        self.assertIsNotNone(
            nested,
            "10.4.30.10/32 must nest under 10.4.16.0/20, not be hoisted into a "
            "top-level Loopbacks group",
        )

    def test_loopbacks_collapse_only_when_no_deeper_parent(self):
        # 3+ loopbacks under a /20 with NO matching deeper subnet → they should
        # collapse into a "Loopbacks (n)" pseudo at the /20.
        # 3+ loopbacks under a /20 WITH a matching /24 → they should nest into
        # the /24 instead, not be collapsed at the /20.
        twenty = IPAMNode("10.5.0.0/20", source="DNAC-Config")
        twenty.role = "aggregate"
        twenty.interface_type = "aggregate"
        twenty.site = "X"

        # Three /32s at IPs that don't share any /24 with each other.
        orphans = [
            self._mk_loopback("10.5.0.1/32", "X"),
            self._mk_loopback("10.5.4.1/32", "X"),
            self._mk_loopback("10.5.8.1/32", "X"),
        ]

        self.engine.subnets = [twenty, *orphans]
        self.engine.build_tree()

        twenty_dict = self._find_node(self.engine.tree["ipv4"], "10.5.0.0/20")
        self.assertIsNotNone(twenty_dict)
        groups = [c for c in twenty_dict["children"] if c.get("role") == "loopback_group"]
        self.assertEqual(len(groups), 1, "orphan loopbacks should collapse at /20")
        self.assertEqual(len(groups[0]["children"]), 3)

        # Now add a /24 that contains all 3 loopbacks — they should nest into
        # the /24 instead of being collapsed at the /20.
        self.engine = IPAMEngine()
        twenty2 = IPAMNode("10.6.0.0/20", source="DNAC-Config")
        twenty2.role = "aggregate"
        twenty2.interface_type = "aggregate"
        twenty2.site = "X"

        twenty4 = IPAMNode("10.6.0.0/24", source="DNAC")
        twenty4.interface_type = "physical"
        twenty4.site = "X"

        deep_loops = [
            self._mk_loopback("10.6.0.1/32", "X"),
            self._mk_loopback("10.6.0.2/32", "X"),
            self._mk_loopback("10.6.0.3/32", "X"),
        ]

        self.engine.subnets = [twenty2, twenty4, *deep_loops]
        self.engine.build_tree()

        twenty2_dict = self._find_node(self.engine.tree["ipv4"], "10.6.0.0/20")
        self.assertIsNotNone(twenty2_dict)
        # /20 should have a /24 child, NOT a collapsed loopback_group.
        roles = [c.get("role") for c in twenty2_dict["children"]]
        self.assertNotIn("loopback_group", roles,
                         "loopbacks that fit a deeper /24 must not be collapsed at /20")
        twenty4_dict = self._find_node(twenty2_dict["children"], "10.6.0.0/24")
        self.assertIsNotNone(twenty4_dict)
        # The /24's children include the loopback group (3 collapse) or the 3
        # /32s directly. Either way, the /32s must be reachable under the /24.
        for cidr in ("10.6.0.1/32", "10.6.0.2/32", "10.6.0.3/32"):
            self.assertIsNotNone(
                self._find_node(twenty4_dict["children"], cidr),
                f"{cidr} must be reachable under 10.6.0.0/24",
            )


    def _mk_v6(self, cidr: str, site: str = "Site1", iface: str = "Vlan10") -> IPAMNode:
        # Mirror the real discovery code path: it stores str(net.cidr), so the
        # stored cidr is masked to the prefix boundary even when an interface
        # IP has host bits set.
        net = netaddr.IPNetwork(cidr)
        n = IPAMNode(str(net.cidr), source="DNAC")
        n.site = site
        n.interface_name = iface
        n.interface_type, n.vlan_id = classify_interface(iface, net)
        n.host_ip = str(net.ip)
        return n

    def test_v6_site_supernet_synthesized_when_missing(self):
        # Two /64s in the same /56 with no existing /56 or /48 in the data —
        # the /56 should be synthesized so the /64s nest under it instead of
        # scattering as top-level roots.
        a = self._mk_v6("4000:5000:1a:ab00::1/64", iface="Vlan10")
        b = self._mk_v6("4000:5000:1a:ab40::1/64", iface="Vlan11")

        self.engine.subnets = [a, b]
        self.engine.build_tree()

        v6 = self.engine.tree["ipv6"]
        # Single root: the inferred /48 (since two /64s also share a /48).
        # Under it, the inferred /56 with the two /64 children.
        self.assertEqual(len(v6), 1, "expected a single inferred root supernet")
        site56 = self._find_node(v6, "4000:5000:1a:ab00::/56")
        self.assertIsNotNone(site56, "expected an inferred /56 site supernet")
        self.assertEqual(site56["role"], "supernet")
        self.assertIn("/56", site56["display_name"])
        # Both /64s reachable under the /56.
        self.assertIsNotNone(self._find_node([site56], "4000:5000:1a:ab00::/64"))
        self.assertIsNotNone(self._find_node([site56], "4000:5000:1a:ab40::/64"))

    def test_v6_org_supernet_synthesized_from_two_sites(self):
        # Two distinct /56s (each with one /64) in the same /48 — the /48
        # should be synthesized and contain both /56s as children.
        siteA_64 = self._mk_v6("4000:5000:1a:ab00::1/64", site="A", iface="Vlan10")
        siteA_64b = self._mk_v6("4000:5000:1a:ab01::1/64", site="A", iface="Vlan11")
        siteB_64 = self._mk_v6("4000:5000:1a:cd00::1/64", site="B", iface="Vlan10")
        siteB_64b = self._mk_v6("4000:5000:1a:cd01::1/64", site="B", iface="Vlan11")

        self.engine.subnets = [siteA_64, siteA_64b, siteB_64, siteB_64b]
        self.engine.build_tree()

        v6 = self.engine.tree["ipv6"]
        # Single inferred /48 root containing two inferred /56s.
        self.assertEqual(len(v6), 1)
        self.assertEqual(v6[0]["cidr"], "4000:5000:1a::/48")
        self.assertEqual(v6[0]["role"], "supernet")
        child_cidrs = {c["cidr"] for c in v6[0]["children"]}
        self.assertIn("4000:5000:1a:ab00::/56", child_cidrs)
        self.assertIn("4000:5000:1a:cd00::/56", child_cidrs)

    def test_v6_synthesis_skipped_when_existing_supernet_present(self):
        # If a real /56 already exists from DNAC config, don't synthesize a
        # duplicate; the existing node wins and the /64 nests under it.
        real_56 = IPAMNode("4000:5000:1a:ab00::/56", source="DNAC-Config")
        real_56.display_name = "EIGRP Summary (Tunnel100)"
        real_56.role = "aggregate"
        real_56.interface_type = "aggregate"
        leaf = self._mk_v6("4000:5000:1a:ab00::1/64")

        self.engine.subnets = [real_56, leaf]
        self.engine.build_tree()

        found = self._find_node(self.engine.tree["ipv6"], "4000:5000:1a:ab00::/56")
        self.assertIsNotNone(found)
        # The real one is preserved, not replaced with an inferred supernet.
        self.assertEqual(found["source"], "DNAC-Config")
        self.assertNotIn("Inferred", found.get("display_name", ""))

    def test_v6_synthesis_skipped_for_singleton(self):
        # A single /64 with no siblings should NOT trigger a /56 wrapper —
        # that would just add noise without grouping anything.
        only = self._mk_v6("4000:5000:1a:ab00::1/64")
        self.engine.subnets = [only]
        self.engine.build_tree()

        v6 = self.engine.tree["ipv6"]
        self.assertEqual(len(v6), 1)
        self.assertEqual(v6[0]["cidr"], "4000:5000:1a:ab00::/64")
        self.assertNotEqual(v6[0].get("role"), "supernet")

    def test_v6_supernet_inherits_single_site_metadata(self):
        # /56 with all children in S093 → synth.site == "S093" and the
        # display_name surfaces it for the user.
        a = self._mk_v6("1000:2000:3002:ab00::1/64", site="S093", iface="Vlan10")
        b = self._mk_v6("1000:2000:3002:ab40::1/64", site="S093", iface="Vlan11")
        a.device = "S093-CORE-1"
        b.device = "S093-CORE-1"

        self.engine.subnets = [a, b]
        self.engine.build_tree()

        site56 = self._find_node(self.engine.tree["ipv6"], "1000:2000:3002:ab00::/56")
        self.assertIsNotNone(site56)
        self.assertEqual(site56["site"], "S093")
        self.assertIn("S093", site56["display_name"])
        self.assertEqual(site56["device"], "S093-CORE-1")

    def test_v6_org_supernet_lists_multiple_sites(self):
        # /48 spanning two /56s in different sites → synth.site == "2 sites",
        # display_name lists them, logical_container has the full list.
        # Two /64s per site so each /56 has 2 members and itself gets synthesized.
        s93a = self._mk_v6("1000:2000:3002:ab00::1/64", site="S093", iface="Vlan10")
        s93b = self._mk_v6("1000:2000:3002:ab40::1/64", site="S093", iface="Vlan11")
        s94a = self._mk_v6("1000:2000:3002:cd00::1/64", site="S094", iface="Vlan10")
        s94b = self._mk_v6("1000:2000:3002:cd40::1/64", site="S094", iface="Vlan11")

        self.engine.subnets = [s93a, s93b, s94a, s94b]
        self.engine.build_tree()

        v6 = self.engine.tree["ipv6"]
        org48 = self._find_node(v6, "1000:2000:3002::/48")
        self.assertIsNotNone(org48)
        self.assertEqual(org48["site"], "2 sites")
        self.assertIn("S093", org48["display_name"])
        self.assertIn("S094", org48["display_name"])
        self.assertIn("S093", org48["logical_container"])
        self.assertIn("S094", org48["logical_container"])

        # The two inferred /56s under it carry their own single-site metadata.
        s93_56 = self._find_node([org48], "1000:2000:3002:ab00::/56")
        s94_56 = self._find_node([org48], "1000:2000:3002:cd00::/56")
        self.assertEqual(s93_56["site"], "S093")
        self.assertEqual(s94_56["site"], "S094")

    def test_v6_supernet_metadata_unknown_when_no_site_info(self):
        # If descendants have no site info, metadata stays unset rather than
        # surfacing a misleading value.
        a = self._mk_v6("1000:2000:3002:ab00::1/64", site="Unknown", iface="Vlan10")
        b = self._mk_v6("1000:2000:3002:ab40::1/64", site="Unknown", iface="Vlan11")

        self.engine.subnets = [a, b]
        self.engine.build_tree()

        site56 = self._find_node(self.engine.tree["ipv6"], "1000:2000:3002:ab00::/56")
        self.assertIsNotNone(site56)
        self.assertEqual(site56["site"], "Unknown")
        # Display name carries no spurious site, just the prefix-count tail.
        self.assertNotIn("·", site56["display_name"].rsplit("(", 1)[0])

    def test_v6_synthesis_groups_p2p_and_loopback_under_site(self):
        # Mixed leaf types under the same /56: /127 P2P + /128 loopback + /64.
        # All three should nest under the inferred /56.
        p2p = self._mk_v6("4000:5000:1a:ab00::/127", iface="Ethernet1/1")
        lo = self._mk_v6("4000:5000:1a:ab00:1::1/128", iface="Loopback0")
        svi = self._mk_v6("4000:5000:1a:ab01::1/64", iface="Vlan20")

        self.engine.subnets = [p2p, lo, svi]
        self.engine.build_tree()

        site56 = self._find_node(self.engine.tree["ipv6"], "4000:5000:1a:ab00::/56")
        self.assertIsNotNone(site56)
        self.assertIsNotNone(self._find_node([site56], "4000:5000:1a:ab00::/127"))
        self.assertIsNotNone(self._find_node([site56], "4000:5000:1a:ab00:1::1/128"))
        self.assertIsNotNone(self._find_node([site56], "4000:5000:1a:ab01::/64"))


if __name__ == "__main__":
    unittest.main()
