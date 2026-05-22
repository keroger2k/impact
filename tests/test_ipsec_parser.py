"""Tests for utils.ipsec_parser and utils.tunnel_inventory."""
from __future__ import annotations

from utils.ipsec_parser import (
    parse_ipsec_config,
    classify_tunnel,
    dmvpn_role,
)
from utils.tunnel_inventory import build_inventory, build_ip_index, resolve_ip


DMVPN_HUB = """!
hostname HUB-DCA-01
!
crypto ikev2 proposal STRONG
 encryption aes-cbc-256 aes-cbc-128
 integrity sha384 sha256
 group 19 14
!
crypto ikev2 profile WAN-PROFILE
 match identity remote address 0.0.0.0
 authentication local pre-share
 authentication remote pre-share
 keyring local TSA-KR
!
crypto ipsec transform-set TSA-TS esp-aes 256 esp-sha256-hmac
 mode tunnel
!
crypto ipsec profile DMVPN-PROFILE
 set transform-set TSA-TS
 set pfs group14
 set ikev2-profile WAN-PROFILE
 set security-association lifetime seconds 3600
!
interface Tunnel100
 description DMVPN Hub
 ip address 172.16.0.1 255.255.0.0
 ip nhrp network-id 100
 ip nhrp map multicast dynamic
 ip nhrp redirect
 tunnel source GigabitEthernet0/1
 tunnel mode gre multipoint
 tunnel key 100
 tunnel protection ipsec profile DMVPN-PROFILE
!
end
"""

DMVPN_SPOKE = """!
hostname SPOKE-BOS-01
!
crypto ipsec profile DMVPN-PROFILE
 set transform-set TSA-TS
!
crypto ipsec transform-set TSA-TS esp-aes 256 esp-sha256-hmac
!
interface Tunnel100
 description DMVPN Spoke
 ip address 172.16.20.1 255.255.0.0
 ip nhrp network-id 100
 ip nhrp nhs 172.16.0.1
 tunnel source GigabitEthernet0/1
 tunnel mode gre multipoint
 tunnel key 100
 tunnel protection ipsec profile DMVPN-PROFILE
!
end
"""

SVTI = """!
hostname HUB-DCA-01
!
crypto ipsec profile SVTI-PROFILE
 set transform-set TSA-TS
!
crypto ipsec transform-set TSA-TS esp-aes 256 esp-sha256-hmac
!
interface Tunnel200
 description sVTI to Partner
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/1
 tunnel destination 203.0.113.42
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile SVTI-PROFILE
!
end
"""

DVTI = """!
hostname HUB-DCA-01
!
crypto ipsec profile DVTI-PROFILE
 set transform-set TSA-TS
!
crypto ipsec transform-set TSA-TS esp-aes 256 esp-sha256-hmac
!
interface Virtual-Template10 type tunnel
 ip unnumbered Loopback0
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile DVTI-PROFILE
!
end
"""

CRYPTO_MAP = """!
hostname EDGE-01
!
crypto isakmp policy 10
 encryption aes 256
 hash sha
 authentication pre-share
 group 14
 lifetime 28800
!
crypto isakmp key SECRET address 198.51.100.7
!
crypto ipsec transform-set LEGACY-TS esp-aes 256 esp-sha-hmac
!
crypto map LEGACY-MAP 10 ipsec-isakmp
 description Partner VPN (IKEv1)
 set peer 198.51.100.7
 set transform-set LEGACY-TS
 set pfs group2
 match address LEGACY-IPSEC-ACL
!
interface GigabitEthernet0/2
 ip address 198.51.100.1 255.255.255.0
 crypto map LEGACY-MAP
!
end
"""


def test_parse_dmvpn_hub():
    p = parse_ipsec_config(DMVPN_HUB)
    assert p["hostname"] == "HUB-DCA-01"
    assert len(p["tunnel_interfaces"]) == 1
    t = p["tunnel_interfaces"][0]
    assert t["name"] == "Tunnel100"
    assert t["tunnel_mode"] == "gre multipoint"
    assert t["nhrp_network_id"] == 100
    assert t["nhrp_redirect"] is True
    assert t["tunnel_protection_profile"] == "DMVPN-PROFILE"
    assert classify_tunnel(t) == "dmvpn"
    assert dmvpn_role(t) == "hub"


def test_parse_dmvpn_spoke():
    p = parse_ipsec_config(DMVPN_SPOKE)
    t = p["tunnel_interfaces"][0]
    assert classify_tunnel(t) == "dmvpn"
    assert dmvpn_role(t) == "spoke"
    assert t["nhrp_nhs"] == ["172.16.0.1"]


def test_parse_svti():
    p = parse_ipsec_config(SVTI)
    t = p["tunnel_interfaces"][0]
    assert classify_tunnel(t) == "svti"
    assert t["tunnel_destination"] == "203.0.113.42"
    assert t["tunnel_protection_profile"] == "SVTI-PROFILE"


def test_parse_dvti():
    p = parse_ipsec_config(DVTI)
    assert len(p["virtual_templates"]) == 1
    vt = p["virtual_templates"][0]
    assert classify_tunnel(vt) == "dvti"
    assert vt["tunnel_protection_profile"] == "DVTI-PROFILE"


def test_parse_crypto_map():
    p = parse_ipsec_config(CRYPTO_MAP)
    assert len(p["crypto_map_entries"]) == 1
    e = p["crypto_map_entries"][0]
    assert e["map_name"] == "LEGACY-MAP"
    assert e["sequence"] == 10
    assert e["peers"] == ["198.51.100.7"]
    assert e["transform_sets"] == ["LEGACY-TS"]
    # Physical interface bound to the map
    assert any(p_iface["crypto_map"] == "LEGACY-MAP"
               for p_iface in p["physical_iface_crypto_maps"])
    # ISAKMP policy + key captured
    assert len(p["isakmp_policies"]) == 1
    assert p["isakmp_policies"][0]["encryption"] == "aes-256"
    assert p["isakmp_policies"][0]["hash"] == "sha"
    assert len(p["isakmp_keys"]) == 1


def test_parse_ikev2_proposal():
    p = parse_ipsec_config(DMVPN_HUB)
    assert len(p["ikev2_proposals"]) == 1
    prop = p["ikev2_proposals"][0]
    assert prop["name"] == "STRONG"
    assert "aes-cbc-256" in prop["encryption"]
    assert "sha384" in prop["integrity"]
    assert "19" in prop["group"]


def test_build_inventory_groups_dmvpn():
    """Two devices sharing (nhrp_id, tunnel_key, profile) should collapse into ONE dmvpn entry."""
    parsed = {
        "dev-hub":   parse_ipsec_config(DMVPN_HUB),
        "dev-spoke": parse_ipsec_config(DMVPN_SPOKE),
    }
    meta = {
        "dev-hub":   {"hostname": "HUB-DCA-01",   "managementIpAddress": "10.10.5.1"},
        "dev-spoke": {"hostname": "SPOKE-BOS-01", "managementIpAddress": "10.20.5.1"},
    }
    inv = build_inventory(parsed_ios=parsed, device_meta=meta, palo=None)
    dmvpn_tunnels = [t for t in inv["tunnels"] if t["type"] == "dmvpn"]
    assert len(dmvpn_tunnels) == 1
    cloud = dmvpn_tunnels[0]
    assert len(cloud["endpoints"]) == 2
    roles = sorted(ep["role"] for ep in cloud["endpoints"])
    assert roles == ["hub", "spoke"]


def test_build_inventory_svti_separate_from_dmvpn():
    parsed = {
        "dev-1": parse_ipsec_config(DMVPN_HUB + "\n" + SVTI),
    }
    meta = {"dev-1": {"hostname": "HUB-DCA-01", "managementIpAddress": "10.10.5.1"}}
    inv = build_inventory(parsed_ios=parsed, device_meta=meta)
    types = sorted(t["type"] for t in inv["tunnels"])
    assert "dmvpn" in types
    assert "svti" in types
    assert inv["stats"]["total"] == len(inv["tunnels"])


def test_build_inventory_palo():
    """Palo tunnels join gateway + ike profile + ipsec profile."""
    palo = {
        "ike_gateways": [{
            "scope": "shared", "template": "", "name": "GW-X",
            "peer_address": "1.2.3.4", "local_interface": "ethernet1/2", "local_ip": "5.6.7.8",
            "protocol": "ikev2", "ikev1_profile": "", "ikev1_mode": "",
            "ikev2_profile": "Strong-IKE", "auth": "pre-shared-key", "disabled": False,
        }],
        "ipsec_tunnels": [{
            "scope": "shared", "template": "", "name": "VPN-X",
            "tunnel_interface": "tunnel.7",
            "ike_gateway": "GW-X",
            "ipsec_profile": "Strong-IPsec",
            "proxy_ids": [], "disabled": False, "anti_replay": "yes",
        }],
        "ike_profiles": [{
            "scope": "shared", "name": "Strong-IKE",
            "encryption": ["aes-256-cbc"], "hash": ["sha256"], "dh_group": ["group14"],
            "lifetime_value": "8", "lifetime_unit": "hours", "authentication_multiple": "0",
        }],
        "ipsec_profiles": [{
            "scope": "shared", "name": "Strong-IPsec", "protocol": "esp",
            "encryption": ["aes-256-gcm"], "authentication": ["none"], "dh_group": "group14",
            "lifetime_value": "1", "lifetime_unit": "hours",
            "lifesize_value": "", "lifesize_unit": "",
        }],
    }
    inv = build_inventory(parsed_ios={}, device_meta={}, palo=palo)
    palos = [t for t in inv["tunnels"] if t["type"] == "palo_ipsec"]
    assert len(palos) == 1
    t = palos[0]
    assert t["phase1"]["encryption"] == ["aes-256-cbc"]
    assert t["phase1"]["dh_group"] == ["group14"]
    assert t["phase2"]["encryption"] == ["aes-256-gcm"]
    assert t["endpoints"][0]["peer_ip"] == "1.2.3.4"


def test_parse_empty():
    assert parse_ipsec_config("")["hostname"] == ""
    assert parse_ipsec_config("")["tunnel_interfaces"] == []


def test_stub_tunnel_classified_as_stub_and_skipped():
    """interface TunnelN / no ip address declarations should not pollute the inventory."""
    cfg = """!
hostname TEST
!
interface Tunnel101
 no ip address
!
end
"""
    p = parse_ipsec_config(cfg)
    assert len(p["tunnel_interfaces"]) == 1
    assert classify_tunnel(p["tunnel_interfaces"][0]) == "stub"

    inv = build_inventory({"d": p}, {"d": {"hostname": "TEST", "managementIpAddress": "10.0.0.1"}})
    assert inv["stats"]["total"] == 0  # stubs excluded


def test_dmvpn_inferred_from_nhrp_even_without_explicit_mode():
    """NHRP is the unambiguous DMVPN signal — trust it over a missing `tunnel mode` line."""
    cfg = """!
hostname TEST
!
crypto ipsec profile DMVPN-P
 set transform-set TS
!
crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac
!
interface Tunnel5000
 ip nhrp network-id 5000
 ip nhrp nhs 10.0.0.1
 tunnel source GigabitEthernet0/0/1
 tunnel key 5000
 tunnel protection ipsec profile DMVPN-P
!
end
"""
    p = parse_ipsec_config(cfg)
    iface = p["tunnel_interfaces"][0]
    assert iface["tunnel_mode"] == ""    # no `tunnel mode` line
    assert classify_tunnel(iface) == "dmvpn"


def test_crypto_map_with_ikev2_profile_classifies_as_ikev2():
    """A crypto map entry that pins `set ikev2-profile X` should NOT fall back
    to the device's ISAKMP policy and be misreported as IKEv1."""
    cfg = """!
hostname TEST
!
crypto ikev2 proposal STRONG
 encryption aes-cbc-256
 integrity sha256
 group 14
!
crypto ikev2 profile PARTNER
 match identity remote address 1.2.3.4
 authentication remote pre-share
 authentication local pre-share
 keyring local KR
!
crypto isakmp policy 10
 encryption aes 256
 hash sha
 group 2
!
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
!
crypto map MYMAP 10 ipsec-isakmp
 set peer 1.2.3.4
 set transform-set TS
 set ikev2-profile PARTNER
 match address ACL
!
interface GigabitEthernet0/0/1
 crypto map MYMAP redundancy HSRP
!
end
"""
    p = parse_ipsec_config(cfg)
    inv = build_inventory({"d": p}, {"d": {"hostname": "TEST", "managementIpAddress": "10.0.0.1"}})
    cm_tunnels = [t for t in inv["tunnels"] if t["type"] == "crypto_map"]
    assert len(cm_tunnels) == 1
    assert cm_tunnels[0]["phase1"]["protocol"] == "ikev2"
    assert cm_tunnels[0]["phase1"]["profile_name"] == "PARTNER"


def test_dnac_obfuscated_lines_dont_break_interface_block():
    """DNAC strips leading whitespace from lines containing redacted values
    (`tunnel key xxxxxx`, `ip nhrp authentication xxxxxxxxx`). The parser
    must treat them as continuations, not as block terminators.
    """
    # Reproduces the exact shape from RTGFS005AD001's cached config:
    # description + a couple normal child lines, then an obfuscated indent-0
    # line, then more indent-1 children including the lines that classify
    # the tunnel as DMVPN.
    cfg = (
        "hostname RTGFS005AD001\n"
        "!\n"
        "crypto ipsec profile SOHO-PRODUCTION\n"
        " set transform-set TS\n"
        "!\n"
        "crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac\n"
        "!\n"
        "interface Tunnel201\n"
        " description SOHO PRODUCTION TRAFFIC\n"
        " bandwidth 100000\n"
        " ip address 10.36.190.17 255.255.255.128\n"
        " ip mtu 1140\n"
        "ip nhrp authentication xxxxxxxxx\n"     # ← DNAC-obfuscated, indent 0
        " no ip nhrp map multicast dynamic\n"
        " ip nhrp network-id 201\n"
        " ip nhrp nhs 10.36.190.1 nbma 173.255.51.85 multicast\n"
        " tunnel source GigabitEthernet0/0/1\n"
        " tunnel mode gre multipoint\n"
        "tunnel key xxxxxx\n"                    # ← DNAC-obfuscated, indent 0
        " tunnel vrf INTERNET\n"
        " tunnel protection ipsec profile SOHO-PRODUCTION shared\n"
        " ip virtual-reassembly\n"
        "!\n"
        "end\n"
    )
    p = parse_ipsec_config(cfg)
    assert len(p["tunnel_interfaces"]) == 1
    iface = p["tunnel_interfaces"][0]

    # All of these were lost before the fix because _block_lines stopped at
    # the first obfuscated indent-0 line.
    assert iface["tunnel_mode"] == "gre multipoint"
    assert iface["tunnel_protection_profile"] == "SOHO-PRODUCTION"
    assert iface["nhrp_network_id"] == 201
    assert iface["tunnel_source"] == "GigabitEthernet0/0/1"
    assert iface["tunnel_vrf"] == "INTERNET"
    assert len(iface["nhrp_nhs"]) == 1
    assert classify_tunnel(iface) == "dmvpn"


def test_obfuscated_line_doesnt_swallow_next_block():
    """Sanity: a real `interface X` following a block must still terminate
    the previous block, even after we've made indent-0 continuation tolerant.
    """
    cfg = (
        "interface Tunnel201\n"
        " description Spoke\n"
        " tunnel mode gre multipoint\n"
        " ip nhrp network-id 201\n"
        "interface Tunnel251\n"                  # ← real block-starter
        " description Mgmt\n"
        " tunnel mode gre multipoint\n"
        " ip nhrp network-id 251\n"
        "!\n"
        "end\n"
    )
    p = parse_ipsec_config(cfg)
    assert len(p["tunnel_interfaces"]) == 2
    assert p["tunnel_interfaces"][0]["name"] == "Tunnel201"
    assert p["tunnel_interfaces"][0]["nhrp_network_id"] == 201
    assert p["tunnel_interfaces"][1]["name"] == "Tunnel251"
    assert p["tunnel_interfaces"][1]["nhrp_network_id"] == 251


def test_crypto_map_binding_accepts_trailing_redundancy_keyword():
    """`crypto map NAME redundancy HSRP` on an interface should still bind."""
    cfg = """!
hostname TEST
!
crypto map MYMAP 10 ipsec-isakmp
 set peer 1.2.3.4
!
interface GigabitEthernet0/0/1
 crypto map MYMAP redundancy INTERNETHSRP
!
end
"""
    p = parse_ipsec_config(cfg)
    bindings = p["physical_iface_crypto_maps"]
    assert len(bindings) == 1
    assert bindings[0]["name"] == "GigabitEthernet0/0/1"
    assert bindings[0]["crypto_map"] == "MYMAP"


# ── IP → device/site resolution ─────────────────────────────────────────────

def test_build_ip_index_indexes_mgmt_and_tunnel_ips():
    """Both DNAC mgmt IPs and parsed tunnel overlay IPs should land in the index."""
    parsed = {
        "dev-hub":   parse_ipsec_config(DMVPN_HUB),
        "dev-spoke": parse_ipsec_config(DMVPN_SPOKE),
    }
    meta = {
        "dev-hub":   {"hostname": "HUB-DCA-01",   "managementIpAddress": "10.10.5.1"},
        "dev-spoke": {"hostname": "SPOKE-BOS-01", "managementIpAddress": "10.20.5.1"},
    }
    site_map = {"dev-hub": "TSA-DCA-HQ", "dev-spoke": "TSA-BOS-T1"}
    idx = build_ip_index(parsed, meta, site_map)

    # mgmt IPs resolve to their device + site
    assert "10.10.5.1" in idx
    assert idx["10.10.5.1"][0]["device"] == "HUB-DCA-01"
    assert idx["10.10.5.1"][0]["site"] == "TSA-DCA-HQ"
    assert idx["10.10.5.1"][0]["source"] == "mgmt"

    # tunnel overlay IP also resolved
    assert "172.16.0.1" in idx
    assert idx["172.16.0.1"][0]["source"] == "tunnel-overlay"


def test_resolve_ip_strips_cidr():
    """A resolver lookup with a /24 suffix should still hit the bare IP."""
    idx = {"10.0.0.1": [{"device": "R1", "site": "S", "source": "mgmt"}]}
    assert resolve_ip("10.0.0.1/24", idx)[0]["device"] == "R1"
    assert resolve_ip("(multipoint)", idx) == []
    assert resolve_ip("", idx) == []


def test_inventory_annotates_endpoints_with_site_and_peer_match():
    """build_inventory should attach local_site + peer_matches to every endpoint."""
    parsed = {
        "dev-hub":   parse_ipsec_config(DMVPN_HUB),
        "dev-spoke": parse_ipsec_config(DMVPN_SPOKE),
    }
    meta = {
        "dev-hub":   {"hostname": "HUB-DCA-01",   "managementIpAddress": "10.10.5.1"},
        "dev-spoke": {"hostname": "SPOKE-BOS-01", "managementIpAddress": "10.20.5.1"},
    }
    site_map = {"dev-hub": "TSA-DCA-HQ", "dev-spoke": "TSA-BOS-T1"}
    inv = build_inventory(
        parsed_ios=parsed, device_meta=meta, palo=None, device_site_map=site_map,
    )

    cloud = next(t for t in inv["tunnels"] if t["type"] == "dmvpn")
    by_role = {ep["role"]: ep for ep in cloud["endpoints"]}

    # Local site populated from device_site_map
    assert by_role["hub"]["local_site"] == "TSA-DCA-HQ"
    assert by_role["spoke"]["local_site"] == "TSA-BOS-T1"

    # Spoke's NHS list (its peer_ip is the hub overlay 172.16.0.1) resolves
    # to the hub device + site through the tunnel-overlay source.
    spoke_pm = by_role["spoke"]["peer_matches"]
    assert spoke_pm and spoke_pm[0]["ip"] == "172.16.0.1"
    assert spoke_pm[0]["matches"][0]["device"] == "HUB-DCA-01"
    assert spoke_pm[0]["matches"][0]["site"] == "TSA-DCA-HQ"

    # The inventory also stashes the ip_index for the live router to reuse.
    assert "172.16.0.1" in inv["ip_index"]


def test_resolver_returns_all_candidates_for_duplicate_ip():
    """If two devices share an IP (RFC1918 reuse across sites), the index keeps both."""
    parsed = {
        "dev-a": {"hostname": "DEV-A", "tunnel_interfaces": [
            {"name": "Tunnel0", "ip_address": "10.0.0.1"}
        ]},
        "dev-b": {"hostname": "DEV-B", "tunnel_interfaces": [
            {"name": "Tunnel0", "ip_address": "10.0.0.1"}
        ]},
    }
    meta = {
        "dev-a": {"hostname": "DEV-A", "managementIpAddress": "192.168.1.1"},
        "dev-b": {"hostname": "DEV-B", "managementIpAddress": "192.168.2.1"},
    }
    site_map = {"dev-a": "SITE-A", "dev-b": "SITE-B"}
    idx = build_ip_index(parsed, meta, site_map)
    matches = idx["10.0.0.1"]
    devices = sorted(m["device"] for m in matches)
    assert devices == ["DEV-A", "DEV-B"]
    sites = sorted(m["site"] for m in matches)
    assert sites == ["SITE-A", "SITE-B"]


def test_build_ip_index_uses_dnac_interfaces_for_wan_ips():
    """DMVPN NBMA peers are the spoke's WAN-facing physical IP. The parser
    never sees those (only tunnel + crypto-map interfaces). The DNAC
    interface inventory is the source that closes that gap."""
    meta = {"dev-1": {"hostname": "SPOKE-01", "managementIpAddress": "10.0.0.1"}}
    site_map = {"dev-1": "BRANCH-42"}
    dnac_ifaces = [
        # The WAN-facing physical — never appears in parse_ipsec_config output
        # unless it has a crypto map bound. But DMVPN uses tunnel protection,
        # so this interface never lands in our parsed view.
        {"deviceId": "dev-1", "deviceName": "SPOKE-01",
         "portName": "GigabitEthernet0/0/0", "ipv4Address": "203.0.113.42"},
        # Loopback (control-plane / EIGRP router-id)
        {"deviceId": "dev-1", "deviceName": "SPOKE-01",
         "portName": "Loopback0", "ipv4Address": "10.99.99.42"},
    ]
    idx = build_ip_index({}, meta, site_map, dnac_interfaces=dnac_ifaces)

    assert "203.0.113.42" in idx
    m = idx["203.0.113.42"][0]
    assert m["device"] == "SPOKE-01"
    assert m["site"] == "BRANCH-42"
    assert m["interface"] == "GigabitEthernet0/0/0"
    assert m["source"] == "interface"

    # Loopback too
    assert "10.99.99.42" in idx
    assert idx["10.99.99.42"][0]["source"] == "interface"


def test_build_ip_index_includes_palo_firewall_ips():
    """Palo firewall IPs (from pan_interfaces cache) must land in the index
    so Palo↔Palo peer resolution works. Site_code is derived from the
    firewall hostname since Palos aren't in DNAC."""
    pan_ifaces = [{
        "hostname": "k024fwl006",
        "serial":   "001801000123",
        "iface_map": {
            "management":   {"ipv4": "10.25.72.34"},
            "ethernet1/12": {"ipv4": "10.16.103.193"},
        },
    }]
    idx = build_ip_index({}, {}, {}, pan_interfaces=pan_ifaces)

    assert "10.25.72.34" in idx
    m = idx["10.25.72.34"][0]
    assert m["device"] == "k024fwl006"
    assert m["site_code"] == "K024"          # derived from hostname
    assert m["source"] == "palo-mgmt"

    # Data-plane interface — also indexed.
    assert "10.16.103.193" in idx
    m = idx["10.16.103.193"][0]
    assert m["device"] == "k024fwl006"
    assert m["site_code"] == "K024"
    assert m["source"] == "palo-iface"


def test_build_ip_index_precomputes_site_code_for_dnac_entries():
    """Every match should carry a `site_code` so the UI doesn't need to
    re-derive it. Site path wins; hostname is the fallback."""
    meta = {"dev-1": {"hostname": "core-rtr-01", "managementIpAddress": "10.0.0.1"}}
    site_map = {"dev-1": "Global/California/DC15 K024/DC15 K024"}
    idx = build_ip_index({}, meta, site_map)
    m = idx["10.0.0.1"][0]
    assert m["site_code"] == "K024"          # extracted from the site path
