"""
ipsec_parser.py — Extract IPsec/IKE configuration from Cisco IOS/IOS-XE
running-configs. Pure functions over text; no I/O.

Covers all four tunnel families the Catalyst-based fleet uses:
  - DMVPN              (interface Tunnel + tunnel mode gre multipoint + NHRP)
  - sVTI (static)      (interface Tunnel + tunnel mode ipsec ipv4 + tunnel destination)
  - dVTI (dynamic hub) (interface Virtual-Template + tunnel mode ipsec ipv4)
  - Policy-based       (crypto map NAME N ipsec-isakmp on a physical interface)

Plus the underlying crypto material: ISAKMP policies, IKEv2 proposals/policies/
profiles, transform-sets, and ipsec profiles.
"""
from __future__ import annotations

import re
from typing import Optional


# ── Top-level regexes ───────────────────────────────────────────────────────────
_RE_HOSTNAME        = re.compile(r"^hostname\s+(\S+)\s*$")
_RE_INTERFACE       = re.compile(r"^interface\s+(\S+)(?:\s+.*)?$")

_RE_ISAKMP_POLICY   = re.compile(r"^crypto\s+isakmp\s+policy\s+(\d+)\s*$")
_RE_ISAKMP_KEY      = re.compile(
    r"^crypto\s+isakmp\s+key\s+(?:\d+\s+)?(\S+)\s+address\s+(\S+)(?:\s+(\S+))?"
)
_RE_IKEV2_PROPOSAL  = re.compile(r"^crypto\s+ikev2\s+proposal\s+(\S+)\s*$")
_RE_IKEV2_POLICY    = re.compile(r"^crypto\s+ikev2\s+policy\s+(\S+)\s*$")
_RE_IKEV2_PROFILE   = re.compile(r"^crypto\s+ikev2\s+profile\s+(\S+)\s*$")
_RE_IKEV2_KEYRING   = re.compile(r"^crypto\s+ikev2\s+keyring\s+(\S+)\s*$")

_RE_TS              = re.compile(r"^crypto\s+ipsec\s+transform-set\s+(\S+)\s+(.+?)\s*$")
_RE_IPSEC_PROFILE   = re.compile(r"^crypto\s+ipsec\s+profile\s+(\S+)\s*$")
_RE_CRYPTO_MAP_HDR  = re.compile(
    r"^crypto\s+map\s+(\S+)\s+(\d+)\s+(ipsec-isakmp|ipsec-manual|gdoi)\s*(.*)$"
)

# ── Within-block regexes ────────────────────────────────────────────────────────
_RE_TUN_SOURCE      = re.compile(r"^tunnel\s+source\s+(\S+)")
_RE_TUN_DEST        = re.compile(r"^tunnel\s+destination\s+(\S+)")
_RE_TUN_MODE        = re.compile(r"^tunnel\s+mode\s+(.+)$")
_RE_TUN_KEY         = re.compile(r"^tunnel\s+key\s+(\d+)")
_RE_TUN_VRF         = re.compile(r"^tunnel\s+vrf\s+(\S+)")
_RE_TUN_PROTECT     = re.compile(
    r"^tunnel\s+protection\s+ipsec\s+profile\s+(\S+)"
)
_RE_NHRP_NETID      = re.compile(r"^ip\s+nhrp\s+network-id\s+(\d+)")
_RE_NHRP_NHS        = re.compile(r"^ip\s+nhrp\s+nhs\s+(\S+)")
_RE_NHRP_MAP_MCAST  = re.compile(r"^ip\s+nhrp\s+map\s+multicast\s+(\S+)")
_RE_NHRP_REDIRECT   = re.compile(r"^ip\s+nhrp\s+redirect")
_RE_NHRP_SHORTCUT   = re.compile(r"^ip\s+nhrp\s+shortcut")
_RE_NHRP_AUTH       = re.compile(r"^ip\s+nhrp\s+authentication\s+(\S+)")
_RE_IP_ADDR         = re.compile(r"^ip\s+address\s+(\S+)\s+(\S+)")
_RE_IP_UNNUMBERED   = re.compile(r"^ip\s+unnumbered\s+(\S+)")
_RE_DESCRIPTION     = re.compile(r"^description\s+(.+)$")
_RE_SHUTDOWN        = re.compile(r"^shutdown\s*$")
_RE_VRF_FORWARDING  = re.compile(r"^(?:ip\s+vrf\s+forwarding|vrf\s+forwarding)\s+(\S+)")

# ISAKMP policy attributes
_RE_ENC             = re.compile(r"^encryption\s+(\S+)(?:\s+(\d+))?")
_RE_HASH            = re.compile(r"^hash\s+(\S+)")
_RE_AUTH            = re.compile(r"^authentication\s+(\S+)")
_RE_GROUP           = re.compile(r"^group\s+(\S+)")
_RE_LIFETIME        = re.compile(r"^lifetime\s+(\d+)")

# IKEv2 proposal attributes (multi-value possible)
_RE_IKEV2_ENC       = re.compile(r"^encryption\s+(.+)$")
_RE_IKEV2_INTEG     = re.compile(r"^integrity\s+(.+)$")
_RE_IKEV2_GROUP     = re.compile(r"^group\s+(.+)$")
_RE_IKEV2_PRF       = re.compile(r"^prf\s+(.+)$")

# IKEv2 profile match attributes
_RE_IKEV2_MATCH_ID  = re.compile(r"^match\s+identity\s+remote\s+(.+)$")
_RE_IKEV2_AUTH_LOC  = re.compile(r"^authentication\s+local\s+(.+)$")
_RE_IKEV2_AUTH_REM  = re.compile(r"^authentication\s+remote\s+(.+)$")
_RE_IKEV2_KEYRING_R = re.compile(r"^keyring\s+local\s+(\S+)")

# IPSec profile attributes
_RE_SET_TS          = re.compile(r"^set\s+transform-set\s+(.+)$")
_RE_SET_PFS         = re.compile(r"^set\s+pfs\s+(?:group\s+)?(\S+)")
_RE_SET_SA_SEC      = re.compile(
    r"^set\s+security-association\s+lifetime\s+seconds\s+(\d+)"
)
_RE_SET_SA_KB       = re.compile(
    r"^set\s+security-association\s+lifetime\s+kilobytes\s+(\S+)"
)
_RE_SET_IKEV2_PROF  = re.compile(r"^set\s+ikev2-profile\s+(\S+)")

# Crypto map attributes
_RE_CMAP_PEER       = re.compile(r"^set\s+peer\s+(\S+)")
_RE_CMAP_MATCH_ACL  = re.compile(r"^match\s+address\s+(\S+)")
_RE_IFACE_CMAP      = re.compile(r"^crypto\s+map\s+(\S+)(?:\s+.*)?$")


def _iter_blocks(config: str):
    """Yield (indent_level, line_stripped, raw_line) for non-empty lines."""
    for raw in config.splitlines():
        s = raw.rstrip()
        if not s or s.lstrip().startswith("!"):
            continue
        indent = len(s) - len(s.lstrip())
        yield indent, s.strip(), raw


def _block_lines(lines: list[tuple[int, str, str]], start: int) -> tuple[list[str], int]:
    """Collect indented child lines starting at `start`. Returns (children, end_idx)."""
    if start >= len(lines):
        return [], start
    parent_indent = lines[start - 1][0] if start > 0 else 0
    children = []
    i = start
    while i < len(lines):
        indent, stripped, _ = lines[i]
        if indent <= parent_indent and stripped not in ("exit-af-interface", "exit-address-family"):
            break
        children.append(stripped)
        i += 1
    return children, i


def _mask_to_prefix(mask: str) -> Optional[int]:
    try:
        parts = [int(x) for x in mask.split(".")]
        if len(parts) != 4:
            return None
        bits = 0
        for p in parts:
            bits += bin(p).count("1")
        return bits
    except Exception:
        return None


def parse_ipsec_config(config: str) -> dict:
    """
    Parse a Cisco IOS/IOS-XE running-config and return all IPsec/IKE artifacts.

    Returned dict has keys:
      hostname, isakmp_policies, isakmp_keys, ikev2_proposals, ikev2_policies,
      ikev2_profiles, ikev2_keyrings, transform_sets, ipsec_profiles,
      crypto_map_entries, tunnel_interfaces, virtual_templates,
      physical_iface_crypto_maps
    """
    if not config:
        return _empty()

    hostname = ""
    isakmp_policies: list[dict] = []
    isakmp_keys: list[dict] = []
    ikev2_proposals: list[dict] = []
    ikev2_policies: list[dict] = []
    ikev2_profiles: list[dict] = []
    ikev2_keyrings: list[str] = []
    transform_sets: list[dict] = []
    ipsec_profiles: list[dict] = []
    crypto_map_entries: list[dict] = []
    tunnel_interfaces: list[dict] = []
    virtual_templates: list[dict] = []
    physical_iface_crypto_maps: list[dict] = []

    lines = list(_iter_blocks(config))

    i = 0
    while i < len(lines):
        indent, stripped, _ = lines[i]

        # Top-level lines only
        if indent != 0:
            i += 1
            continue

        m = _RE_HOSTNAME.match(stripped)
        if m:
            hostname = m.group(1)
            i += 1
            continue

        m = _RE_ISAKMP_KEY.match(stripped)
        if m:
            isakmp_keys.append({
                "peer": m.group(2),
                "mask": m.group(3) or "",
                "auth": "pre-share",
            })
            i += 1
            continue

        m = _RE_ISAKMP_POLICY.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            isakmp_policies.append(_parse_isakmp_policy(int(m.group(1)), children))
            continue

        m = _RE_IKEV2_PROPOSAL.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            ikev2_proposals.append(_parse_ikev2_proposal(m.group(1), children))
            continue

        m = _RE_IKEV2_POLICY.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            proposals = []
            for c in children:
                if c.startswith("proposal "):
                    proposals.append(c.split(None, 1)[1].strip())
            ikev2_policies.append({"name": m.group(1), "proposals": proposals})
            continue

        m = _RE_IKEV2_PROFILE.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            ikev2_profiles.append(_parse_ikev2_profile(m.group(1), children))
            continue

        m = _RE_IKEV2_KEYRING.match(stripped)
        if m:
            ikev2_keyrings.append(m.group(1))
            i += 1
            continue

        m = _RE_TS.match(stripped)
        if m:
            transform_sets.append({
                "name": m.group(1),
                "transforms": m.group(2).split(),
            })
            i += 1
            continue

        m = _RE_IPSEC_PROFILE.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            ipsec_profiles.append(_parse_ipsec_profile(m.group(1), children))
            continue

        m = _RE_CRYPTO_MAP_HDR.match(stripped)
        if m:
            children, i = _block_lines(lines, i + 1)
            crypto_map_entries.append(_parse_crypto_map_entry(
                map_name=m.group(1),
                seq=int(m.group(2)),
                kind=m.group(3),
                children=children,
            ))
            continue

        m = _RE_INTERFACE.match(stripped)
        if m:
            iface_name = m.group(1)
            children, i = _block_lines(lines, i + 1)
            iface = _parse_interface(iface_name, children)
            if iface_name.lower().startswith("tunnel"):
                tunnel_interfaces.append(iface)
            elif iface_name.lower().startswith("virtual-template"):
                virtual_templates.append(iface)
            elif iface.get("crypto_map"):
                physical_iface_crypto_maps.append(iface)
            continue

        i += 1

    return {
        "hostname": hostname,
        "isakmp_policies": isakmp_policies,
        "isakmp_keys": isakmp_keys,
        "ikev2_proposals": ikev2_proposals,
        "ikev2_policies": ikev2_policies,
        "ikev2_profiles": ikev2_profiles,
        "ikev2_keyrings": ikev2_keyrings,
        "transform_sets": transform_sets,
        "ipsec_profiles": ipsec_profiles,
        "crypto_map_entries": crypto_map_entries,
        "tunnel_interfaces": tunnel_interfaces,
        "virtual_templates": virtual_templates,
        "physical_iface_crypto_maps": physical_iface_crypto_maps,
    }


def _empty() -> dict:
    return {
        "hostname": "",
        "isakmp_policies": [],
        "isakmp_keys": [],
        "ikev2_proposals": [],
        "ikev2_policies": [],
        "ikev2_profiles": [],
        "ikev2_keyrings": [],
        "transform_sets": [],
        "ipsec_profiles": [],
        "crypto_map_entries": [],
        "tunnel_interfaces": [],
        "virtual_templates": [],
        "physical_iface_crypto_maps": [],
    }


def _parse_isakmp_policy(priority: int, children: list[str]) -> dict:
    pol = {
        "priority": priority,
        "encryption": "des",     # IOS defaults
        "hash": "sha",
        "authentication": "rsa-sig",
        "group": "1",
        "lifetime": 86400,
    }
    for line in children:
        m = _RE_ENC.match(line)
        if m:
            enc = m.group(1)
            if m.group(2):
                enc = f"{enc}-{m.group(2)}"
            pol["encryption"] = enc
            continue
        m = _RE_HASH.match(line)
        if m:
            pol["hash"] = m.group(1); continue
        m = _RE_AUTH.match(line)
        if m:
            pol["authentication"] = m.group(1); continue
        m = _RE_GROUP.match(line)
        if m:
            pol["group"] = m.group(1); continue
        m = _RE_LIFETIME.match(line)
        if m:
            pol["lifetime"] = int(m.group(1)); continue
    return pol


def _split_multi(value: str) -> list[str]:
    return [v for v in value.split() if v]


def _parse_ikev2_proposal(name: str, children: list[str]) -> dict:
    prop = {
        "name": name,
        "encryption": [],
        "integrity": [],
        "group": [],
        "prf": [],
    }
    for line in children:
        m = _RE_IKEV2_ENC.match(line)
        if m: prop["encryption"] = _split_multi(m.group(1)); continue
        m = _RE_IKEV2_INTEG.match(line)
        if m: prop["integrity"] = _split_multi(m.group(1)); continue
        m = _RE_IKEV2_GROUP.match(line)
        if m: prop["group"] = _split_multi(m.group(1)); continue
        m = _RE_IKEV2_PRF.match(line)
        if m: prop["prf"] = _split_multi(m.group(1)); continue
    return prop


def _parse_ikev2_profile(name: str, children: list[str]) -> dict:
    prof = {
        "name": name,
        "match_identity_remote": [],
        "auth_local": "",
        "auth_remote": "",
        "keyring_local": "",
    }
    for line in children:
        m = _RE_IKEV2_MATCH_ID.match(line)
        if m: prof["match_identity_remote"].append(m.group(1).strip()); continue
        m = _RE_IKEV2_AUTH_LOC.match(line)
        if m: prof["auth_local"] = m.group(1).strip(); continue
        m = _RE_IKEV2_AUTH_REM.match(line)
        if m: prof["auth_remote"] = m.group(1).strip(); continue
        m = _RE_IKEV2_KEYRING_R.match(line)
        if m: prof["keyring_local"] = m.group(1); continue
    return prof


def _parse_ipsec_profile(name: str, children: list[str]) -> dict:
    prof = {
        "name": name,
        "transform_sets": [],
        "ikev2_profile": "",
        "pfs_group": "",
        "sa_lifetime_sec": None,
        "sa_lifetime_kb": None,
    }
    for line in children:
        m = _RE_SET_TS.match(line)
        if m: prof["transform_sets"] = _split_multi(m.group(1)); continue
        m = _RE_SET_IKEV2_PROF.match(line)
        if m: prof["ikev2_profile"] = m.group(1); continue
        m = _RE_SET_PFS.match(line)
        if m: prof["pfs_group"] = m.group(1); continue
        m = _RE_SET_SA_SEC.match(line)
        if m: prof["sa_lifetime_sec"] = int(m.group(1)); continue
        m = _RE_SET_SA_KB.match(line)
        if m:
            v = m.group(1)
            prof["sa_lifetime_kb"] = v if v == "disable" else int(v)
            continue
    return prof


def _parse_crypto_map_entry(map_name: str, seq: int, kind: str, children: list[str]) -> dict:
    entry = {
        "map_name": map_name,
        "sequence": seq,
        "kind": kind,
        "peers": [],
        "acl": "",
        "transform_sets": [],
        "pfs_group": "",
        "ikev2_profile": "",
        "sa_lifetime_sec": None,
        "sa_lifetime_kb": None,
        "description": "",
    }
    for line in children:
        m = _RE_CMAP_PEER.match(line)
        if m: entry["peers"].append(m.group(1)); continue
        m = _RE_CMAP_MATCH_ACL.match(line)
        if m: entry["acl"] = m.group(1); continue
        m = _RE_SET_TS.match(line)
        if m: entry["transform_sets"] = _split_multi(m.group(1)); continue
        m = _RE_SET_PFS.match(line)
        if m: entry["pfs_group"] = m.group(1); continue
        m = _RE_SET_IKEV2_PROF.match(line)
        if m: entry["ikev2_profile"] = m.group(1); continue
        m = _RE_SET_SA_SEC.match(line)
        if m: entry["sa_lifetime_sec"] = int(m.group(1)); continue
        m = _RE_SET_SA_KB.match(line)
        if m:
            v = m.group(1)
            entry["sa_lifetime_kb"] = v if v == "disable" else int(v)
            continue
        m = _RE_DESCRIPTION.match(line)
        if m: entry["description"] = m.group(1).strip(); continue
    return entry


def _parse_interface(name: str, children: list[str]) -> dict:
    iface = {
        "name": name,
        "description": "",
        "tunnel_source": "",
        "tunnel_destination": "",
        "tunnel_mode": "",
        "tunnel_key": None,
        "tunnel_vrf": "",
        "tunnel_protection_profile": "",
        "nhrp_network_id": None,
        "nhrp_nhs": [],
        "nhrp_map_multicast": [],
        "nhrp_redirect": False,
        "nhrp_shortcut": False,
        "nhrp_auth": "",
        "ip_address": "",
        "ip_prefix": None,
        "ip_unnumbered": "",
        "vrf_forwarding": "",
        "shutdown": False,
        "crypto_map": "",
    }
    for line in children:
        m = _RE_DESCRIPTION.match(line)
        if m: iface["description"] = m.group(1).strip(); continue
        m = _RE_TUN_SOURCE.match(line)
        if m: iface["tunnel_source"] = m.group(1); continue
        m = _RE_TUN_DEST.match(line)
        if m: iface["tunnel_destination"] = m.group(1); continue
        m = _RE_TUN_MODE.match(line)
        if m: iface["tunnel_mode"] = m.group(1).strip(); continue
        m = _RE_TUN_KEY.match(line)
        if m: iface["tunnel_key"] = int(m.group(1)); continue
        m = _RE_TUN_VRF.match(line)
        if m: iface["tunnel_vrf"] = m.group(1); continue
        m = _RE_TUN_PROTECT.match(line)
        if m: iface["tunnel_protection_profile"] = m.group(1); continue
        m = _RE_NHRP_NETID.match(line)
        if m: iface["nhrp_network_id"] = int(m.group(1)); continue
        m = _RE_NHRP_NHS.match(line)
        if m: iface["nhrp_nhs"].append(m.group(1)); continue
        m = _RE_NHRP_MAP_MCAST.match(line)
        if m: iface["nhrp_map_multicast"].append(m.group(1)); continue
        if _RE_NHRP_REDIRECT.match(line): iface["nhrp_redirect"] = True; continue
        if _RE_NHRP_SHORTCUT.match(line): iface["nhrp_shortcut"] = True; continue
        m = _RE_NHRP_AUTH.match(line)
        if m: iface["nhrp_auth"] = m.group(1); continue
        m = _RE_IP_ADDR.match(line)
        if m:
            iface["ip_address"] = m.group(1)
            prefix = _mask_to_prefix(m.group(2))
            if prefix is not None:
                iface["ip_prefix"] = prefix
            continue
        m = _RE_IP_UNNUMBERED.match(line)
        if m: iface["ip_unnumbered"] = m.group(1); continue
        m = _RE_VRF_FORWARDING.match(line)
        if m: iface["vrf_forwarding"] = m.group(1); continue
        if _RE_SHUTDOWN.match(line): iface["shutdown"] = True; continue
        m = _RE_IFACE_CMAP.match(line)
        if m and line.startswith("crypto map"):
            iface["crypto_map"] = m.group(1)
            continue
    return iface


# ── DMVPN role inference ─────────────────────────────────────────────────────

def classify_tunnel(iface: dict) -> str:
    """Return one of: 'dmvpn', 'svti', 'dvti', 'gre_over_ipsec', 'gre', 'stub', 'unknown'.

    A 'stub' is a declared tunnel interface with no real config (no mode, no
    source, no destination, no protection, no NHRP). Common in fleet configs
    where `interface TunnelN / no ip address` lives on every device.
    """
    mode = (iface.get("tunnel_mode") or "").lower()
    has_protection = bool(iface.get("tunnel_protection_profile"))
    has_dest = bool(iface.get("tunnel_destination"))
    has_source = bool(iface.get("tunnel_source"))
    has_nhrp = iface.get("nhrp_network_id") is not None

    # Stub: declared but unconfigured. Don't pollute the inventory.
    if not (mode or has_protection or has_dest or has_source or has_nhrp):
        return "stub"

    # NHRP is the unambiguous DMVPN signal. Trust it over `tunnel mode`,
    # which may be missing (relying on the IOS default of GRE).
    if has_nhrp:
        return "dmvpn"
    if "gre multipoint" in mode:
        return "dmvpn"
    if "ipsec" in mode:
        return "svti" if has_dest else "dvti"
    if has_protection and has_dest:
        return "gre_over_ipsec"
    if "gre" in mode and has_dest:
        return "gre"
    # If we got here it has *some* tunnel config but nothing classifying:
    # treat as plain GRE if there's a destination, otherwise unknown.
    if has_dest:
        return "gre"
    return "unknown"


def dmvpn_role(iface: dict) -> str:
    """Infer DMVPN role from NHRP signals. 'hub', 'spoke', or 'unknown'."""
    if iface.get("nhrp_nhs"):
        return "spoke"
    if iface.get("nhrp_redirect") or any(
        m.lower() == "dynamic" for m in iface.get("nhrp_map_multicast", [])
    ):
        return "hub"
    return "unknown"
