import unittest

from utils.ipam_config_parser import parse_eigrp_summaries, parse_ipv6_addresses


IPV6_INTERFACE_CONFIG = """!
hostname rtr-test-01
!
interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.0.1 255.255.255.0
 ipv6 address 2001:db8:0:100::1/64
 ipv6 address fe80::1 link-local
!
interface GigabitEthernet0/2
 ipv6 address 2001:db8:0:200::/64 eui-64
 ipv6 address autoconfig
 ipv6 address dhcp
!
interface Loopback0
 ipv6 address 2001:db8:99::1/128
!
interface Vlan100
 ipv6 address 2001:db8:1:100::1/64
!
end
"""


class TestIPv6AddressParser(unittest.TestCase):
    def test_extracts_static_addresses(self):
        results = parse_ipv6_addresses(IPV6_INTERFACE_CONFIG)
        cidrs = [r["cidr"] for r in results]
        # Four static addresses with explicit prefix; link-local/autoconfig/dhcp are excluded.
        self.assertEqual(len(results), 4)
        self.assertIn("2001:db8:0:100::1/64", cidrs)
        self.assertIn("2001:db8:0:200::/64", cidrs)  # eui-64 form keeps the prefix
        self.assertIn("2001:db8:99::1/128", cidrs)
        self.assertIn("2001:db8:1:100::1/64", cidrs)

    def test_attributes_to_correct_interface(self):
        results = parse_ipv6_addresses(IPV6_INTERFACE_CONFIG)
        by_iface = {r["interface"]: r for r in results}
        self.assertEqual(by_iface["GigabitEthernet0/1"]["address"], "2001:db8:0:100::1")
        self.assertEqual(by_iface["GigabitEthernet0/1"]["prefix_length"], 64)
        self.assertEqual(by_iface["Loopback0"]["prefix_length"], 128)
        self.assertEqual(by_iface["Vlan100"]["address"], "2001:db8:1:100::1")

    def test_link_local_is_skipped(self):
        # `ipv6 address fe80::1 link-local` has no /prefix and shouldn't match.
        results = parse_ipv6_addresses(IPV6_INTERFACE_CONFIG)
        self.assertNotIn("fe80::1", [r["address"] for r in results])

    def test_autoconfig_and_dhcp_skipped(self):
        cfg = """!
interface Gi0/1
 ipv6 address autoconfig
 ipv6 address dhcp
!
"""
        self.assertEqual(parse_ipv6_addresses(cfg), [])

    def test_empty_config(self):
        self.assertEqual(parse_ipv6_addresses(""), [])
        self.assertEqual(parse_ipv6_addresses(None), [])

    def test_ipv6_outside_interface_block_is_ignored(self):
        # An ipv6 address line at indent 0 (i.e., not inside an interface) shouldn't be picked up.
        cfg = """!
ipv6 address 2001:db8::1/64
!
"""
        self.assertEqual(parse_ipv6_addresses(cfg), [])


NAMED_MODE_CONFIG = """!
hostname rtr-dca-01
!
interface GigabitEthernet0/1
 ip address 10.10.0.1 255.255.255.0
!
router eigrp TSA-EIGRP
 !
 address-family ipv4 unicast autonomous-system 22
  !
  af-interface Tunnel5000
   summary-address 10.1.0.0 255.255.252.0
   authentication mode md5
   authentication key-chain RoutePW
  exit-af-interface
  !
  af-interface Tunnel5001
   summary-address 10.2.0.0 255.255.0.0
   summary-address 192.168.5.0 255.255.255.0 leak-map STUB-LEAK
  exit-af-interface
  !
  af-interface Loopback100
   passive-interface
  exit-af-interface
  !
  topology base
  exit-af-topology
 exit-address-family
!
end
"""

CLASSIC_MODE_CONFIG = """!
hostname rtr-bos-01
!
interface Tunnel100
 ip address 10.99.0.1 255.255.255.0
 ip summary-address eigrp 100 10.20.0.0 255.255.0.0
!
interface Tunnel200
 ip address 10.99.1.1 255.255.255.0
 ip summary-address eigrp 100 172.16.0.0 255.240.0.0
!
end
"""

MIXED_CONFIG = NAMED_MODE_CONFIG + CLASSIC_MODE_CONFIG


class TestEIGRPParser(unittest.TestCase):
    def test_named_mode_extracts_all_summaries(self):
        results = parse_eigrp_summaries(NAMED_MODE_CONFIG)
        # Three summary-address lines across two af-interface blocks
        self.assertEqual(len(results), 3)

        first = results[0]
        self.assertEqual(first["network"], "10.1.0.0")
        self.assertEqual(first["prefix_length"], 22)
        self.assertEqual(first["af_interface"], "Tunnel5000")
        self.assertEqual(first["eigrp_process"], "TSA-EIGRP")
        self.assertEqual(first["eigrp_as"], 22)
        self.assertEqual(first["mode"], "named")

        second = results[1]
        self.assertEqual(second["network"], "10.2.0.0")
        self.assertEqual(second["prefix_length"], 16)
        self.assertEqual(second["af_interface"], "Tunnel5001")

        third = results[2]
        self.assertEqual(third["network"], "192.168.5.0")
        self.assertEqual(third["prefix_length"], 24)
        self.assertEqual(third["af_interface"], "Tunnel5001")

    def test_classic_mode(self):
        results = parse_eigrp_summaries(CLASSIC_MODE_CONFIG)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["network"], "10.20.0.0")
        self.assertEqual(results[0]["prefix_length"], 16)
        self.assertEqual(results[0]["af_interface"], "Tunnel100")
        self.assertEqual(results[0]["eigrp_as"], 100)
        self.assertEqual(results[0]["mode"], "classic")
        self.assertEqual(results[1]["network"], "172.16.0.0")
        self.assertEqual(results[1]["prefix_length"], 12)

    def test_mixed_modes_in_same_config(self):
        results = parse_eigrp_summaries(MIXED_CONFIG)
        self.assertEqual(len(results), 5)
        modes = {r["mode"] for r in results}
        self.assertEqual(modes, {"named", "classic"})

    def test_empty_or_missing_config(self):
        self.assertEqual(parse_eigrp_summaries(""), [])
        self.assertEqual(parse_eigrp_summaries(None), [])

    def test_summary_outside_af_interface_is_ignored(self):
        cfg = """!
router eigrp TSA-EIGRP
 address-family ipv4 unicast autonomous-system 22
  summary-address 10.99.0.0 255.255.0.0
 exit-address-family
!
"""
        # Bare `summary-address` directly under address-family (not inside af-interface)
        # is not a valid summary-address declaration we want to capture.
        self.assertEqual(parse_eigrp_summaries(cfg), [])

    def test_invalid_mask_skipped(self):
        cfg = """!
router eigrp TSA-EIGRP
 address-family ipv4 unicast autonomous-system 22
  af-interface Tunnel1
   summary-address 10.1.0.0 garbage
  exit-af-interface
 exit-address-family
!
"""
        self.assertEqual(parse_eigrp_summaries(cfg), [])

    def test_zero_prefix_skipped(self):
        cfg = """!
router eigrp TSA-EIGRP
 address-family ipv4 unicast autonomous-system 22
  af-interface Tunnel1
   summary-address 0.0.0.0 0.0.0.0
  exit-af-interface
 exit-address-family
!
"""
        # /0 is the default route, not a meaningful summary.
        self.assertEqual(parse_eigrp_summaries(cfg), [])


if __name__ == "__main__":
    unittest.main()
