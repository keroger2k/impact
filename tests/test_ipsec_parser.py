"""Tests for utils.ipsec_parser and utils.tunnel_inventory."""
from __future__ import annotations

from utils.ipsec_parser import (
    parse_ipsec_config,
    classify_tunnel,
    dmvpn_role,
)
from utils.tunnel_inventory import build_inventory


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
