import unittest
import asyncio
import netaddr
from utils.ipam_engine import IPAMEngine, IPAMNode

class TestIPAMEngine(unittest.TestCase):
    def setUp(self):
        self.engine = IPAMEngine()

    def test_node_creation(self):
        node = IPAMNode("10.0.0.0/24", source="Test")
        self.assertEqual(node.cidr, "10.0.0.0/24")
        self.assertEqual(node.network.prefixlen, 24)

    def test_is_excluded(self):
        # /32 exclusion
        self.assertTrue(self.engine.is_excluded(netaddr.IPNetwork("10.1.1.1/32")))
        # HA pattern exclusion
        self.assertTrue(self.engine.is_excluded(netaddr.IPNetwork("10.1.1.0/24"), name="KEEPALIVE-VLAN"))
        # Standard subnet
        self.assertFalse(self.engine.is_excluded(netaddr.IPNetwork("10.1.1.0/24"), name="Users"))
        # 192.168 exclusion
        self.assertTrue(self.engine.is_excluded(netaddr.IPNetwork("192.168.1.0/24")))

    def test_tree_building_nesting(self):
        self.engine.subnets = [
            IPAMNode("10.0.0.0/16", source="ACI"),
            IPAMNode("10.0.1.0/24", source="DNAC"),
            IPAMNode("10.0.2.0/24", source="DNAC"),
        ]
        self.engine.build_tree()

        # Should be under 10.0.0.0/8 root
        self.assertEqual(len(self.engine.v4_tree), 1)
        root = self.engine.v4_tree[0]
        self.assertEqual(root.cidr, "10.0.0.0/8")

        # 10.0.0.0/16 should be child of root
        self.assertEqual(len(root.children), 1)
        supernet = root.children[0]
        self.assertEqual(supernet.cidr, "10.0.0.0/16")

        # 10.0.1.0 and 10.0.2.0 should be children of 10.0.0.0/16
        self.assertEqual(len(supernet.children), 2)
        child_cidrs = [c.cidr for c in supernet.children]
        self.assertIn("10.0.1.0/24", child_cidrs)
        self.assertIn("10.0.2.0/24", child_cidrs)

    def test_priority_and_conflict(self):
        # ACI has higher priority than DNAC
        self.engine.subnets = [
            IPAMNode("10.10.10.0/24", source="DNAC"),
        ]
        self.engine.subnets[0].site = "Site-A"

        node2 = IPAMNode("10.10.10.0/24", source="ACI")
        node2.site = "Site-B"
        self.engine.subnets.append(node2)

        self.engine.build_tree()

        # Flatten and find the node
        flat = self.engine._flatten(self.engine.v4_tree)
        target = next(n for n in flat if n.cidr == "10.10.10.0/24")

        # Source should be ACI (higher priority)
        self.assertEqual(target.source, "ACI")
        # Should have conflict message
        self.assertTrue(any("Site Conflict" in c for c in target.conflicts))
        self.assertTrue(any("Site-A" in c for c in target.conflicts))
        self.assertTrue(any("Site-B" in c for c in target.conflicts))

    def test_dual_stack_linking(self):
        v4 = IPAMNode("10.1.1.0/24", source="ACI")
        v4.logical_container = "BD-Users"
        v4.display_name = "Users"

        v6 = IPAMNode("fc00:1::/64", source="ACI")
        v6.logical_container = "BD-Users"
        v6.display_name = "Users"

        self.engine.subnets = [v4, v6]
        self.engine.build_tree()

        # Names should be updated with [Dual-Stack]
        self.assertIn("[Dual-Stack]", v4.display_name)
        self.assertIn("[Dual-Stack]", v6.display_name)

if __name__ == "__main__":
    unittest.main()
