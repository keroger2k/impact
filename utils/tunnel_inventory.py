"""
tunnel_inventory.py — Normalize IOS + Palo Alto IPsec/IKE artifacts into a
single enterprise-wide tunnel inventory.

Input:
  parsed_ios:  {device_id: parse_ipsec_config() output}
  device_meta: {device_id: {hostname, managementIpAddress, family, ...}}
  palo:        {
      "ike_gateways":   [...],
      "ipsec_tunnels":  [...],
      "ike_profiles":   [...],
      "ipsec_profiles": [...],
  }

Output:
  {"tunnels": [...], "built_at": float, "stats": {...}}
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from utils.ipsec_parser import classify_tunnel, dmvpn_role


# ── Public entry point ───────────────────────────────────────────────────────

def build_inventory(
    parsed_ios:  dict[str, dict],
    device_meta: dict[str, dict],
    palo:        dict[str, list] | None = None,
) -> dict:
    tunnels: list[dict] = []

    # Fleet-wide fallback lookups so crypto resolution still works when a
    # tunnel references an ipsec profile that's only defined on another device
    # (e.g. a DMVPN profile pushed by template that the snapshot for some
    # spokes happens to miss).
    global_lookups = _build_global_lookups(parsed_ios)

    ios_tunnels = _build_ios_tunnels(parsed_ios, device_meta, global_lookups)
    tunnels.extend(ios_tunnels)

    if palo:
        tunnels.extend(_build_palo_tunnels(palo))

    return {
        "tunnels":  tunnels,
        "built_at": time.time(),
        "stats":    _stats(tunnels),
    }


def _build_global_lookups(parsed_ios: dict[str, dict]) -> dict:
    """Fleet-wide fallback for crypto resolution. Keys are profile/transform-set
    names; values are the *last* definition seen across the fleet.

    Enterprises with consistent template-driven config will end up with one
    canonical definition per name. Fleets with divergent definitions get the
    last-seen one — still better than empty.
    """
    ipsec_profiles: dict[str, dict] = {}
    transform_sets: dict[str, dict] = {}
    ikev2_profiles: dict[str, dict] = {}
    ikev2_proposals: dict[str, dict] = {}
    isakmp_policies: list[dict] = []

    for parsed in parsed_ios.values():
        for p in parsed.get("ipsec_profiles", []):
            ipsec_profiles[p["name"]] = p
        for t in parsed.get("transform_sets", []):
            transform_sets[t["name"]] = t
        for p in parsed.get("ikev2_profiles", []):
            ikev2_profiles[p["name"]] = p
        for p in parsed.get("ikev2_proposals", []):
            ikev2_proposals[p["name"]] = p
        isakmp_policies.extend(parsed.get("isakmp_policies", []))

    return {
        "ipsec_profile_by_name":   ipsec_profiles,
        "transform_set_by_name":   transform_sets,
        "ikev2_profile_by_name":   ikev2_profiles,
        "ikev2_proposal_by_name":  ikev2_proposals,
        "isakmp_policies_sorted":  sorted(isakmp_policies, key=lambda p: p.get("priority", 9999)),
    }


def _merge_lookups(primary: dict, fallback: dict) -> dict:
    """Return a lookup that prefers `primary` entries but falls back to `fallback`.
    Used so per-device crypto resolution still works when the device's snapshot
    doesn't include a profile that's referenced by its own tunnel."""
    out = {}
    for key in ("ipsec_profile_by_name", "transform_set_by_name",
                "ikev2_profile_by_name", "ikev2_proposal_by_name"):
        merged = dict(fallback.get(key, {}))
        merged.update(primary.get(key, {}))
        out[key] = merged
    out["isakmp_policies_sorted"] = (primary.get("isakmp_policies_sorted") or
                                     fallback.get("isakmp_policies_sorted", []))
    return out


# ── IOS side ─────────────────────────────────────────────────────────────────

def _build_ios_tunnels(
    parsed_ios:  dict[str, dict],
    device_meta: dict[str, dict],
    global_lookups: dict | None = None,
) -> list[dict]:
    """
    Walk every parsed device and emit one tunnel per:
      - Tunnel interface (sVTI / dVTI hub-template / gre_over_ipsec / unknown)
      - DMVPN cloud (grouped across hub + spokes)
      - crypto map entry (legacy policy-based)

    Virtual-Templates (dVTI) are emitted as a hub-side tunnel definition.
    """
    out: list[dict] = []

    # First pass: collect everything keyed for cross-device grouping
    dmvpn_groups: dict[tuple, list[dict]] = {}     # key -> [{device_id, iface}]
    per_device_p1_p2: dict[str, dict] = {}         # device_id -> resolved p1/p2 lookups

    global_lookups = global_lookups or {}
    for dev_id, parsed in parsed_ios.items():
        per_device_p1_p2[dev_id] = _merge_lookups(
            _build_crypto_lookups(parsed), global_lookups,
        )

    for dev_id, parsed in parsed_ios.items():
        meta = device_meta.get(dev_id, {}) or {}
        hostname = parsed.get("hostname") or meta.get("hostname", dev_id)

        for iface in parsed.get("tunnel_interfaces", []):
            ttype = classify_tunnel(iface)
            if ttype == "stub":
                # Empty `interface TunnelN / no ip address` declarations — skip.
                continue
            if ttype == "dmvpn":
                key = (
                    iface.get("nhrp_network_id"),
                    iface.get("tunnel_key"),
                    iface.get("tunnel_protection_profile") or "",
                )
                dmvpn_groups.setdefault(key, []).append({
                    "device_id": dev_id,
                    "hostname":  hostname,
                    "mgmt_ip":   meta.get("managementIpAddress", ""),
                    "iface":     iface,
                })
                continue

            tun = _make_p2p_tunnel(
                ttype=ttype,
                device_id=dev_id,
                hostname=hostname,
                mgmt_ip=meta.get("managementIpAddress", ""),
                iface=iface,
                lookups=per_device_p1_p2[dev_id],
            )
            out.append(tun)

        for vt in parsed.get("virtual_templates", []):
            ttype = classify_tunnel(vt)
            if ttype != "dvti":
                # Virtual-Templates without ipsec mode aren't tunnels we care about
                continue
            tun = _make_p2p_tunnel(
                ttype="dvti",
                device_id=dev_id,
                hostname=hostname,
                mgmt_ip=meta.get("managementIpAddress", ""),
                iface=vt,
                lookups=per_device_p1_p2[dev_id],
            )
            out.append(tun)

        for cmap in parsed.get("crypto_map_entries", []):
            tun = _make_cryptomap_tunnel(
                device_id=dev_id,
                hostname=hostname,
                mgmt_ip=meta.get("managementIpAddress", ""),
                entry=cmap,
                parsed=parsed,
                lookups=per_device_p1_p2[dev_id],
            )
            out.append(tun)

    for key, members in dmvpn_groups.items():
        out.append(_make_dmvpn_cloud(key, members, per_device_p1_p2))

    return out


def _build_crypto_lookups(parsed: dict) -> dict:
    """
    Per-device dicts so a tunnel can resolve its phase1/phase2 settings by name:
      - profile -> ipsec_profile dict
      - transform_set name -> transform list
      - ikev2 profile -> profile dict (and via it, proposal -> proposal dict)
      - isakmp policy -> policy dict (best-effort: priority is per-device global)
    """
    profiles = {p["name"]: p for p in parsed.get("ipsec_profiles", [])}
    ts       = {t["name"]: t for t in parsed.get("transform_sets", [])}
    v2profs  = {p["name"]: p for p in parsed.get("ikev2_profiles", [])}
    v2props  = {p["name"]: p for p in parsed.get("ikev2_proposals", [])}
    v1pols   = sorted(parsed.get("isakmp_policies", []), key=lambda p: p.get("priority", 9999))
    return {
        "ipsec_profile_by_name": profiles,
        "transform_set_by_name": ts,
        "ikev2_profile_by_name": v2profs,
        "ikev2_proposal_by_name": v2props,
        "isakmp_policies_sorted": v1pols,
    }


def _resolve_phase1(profile_name: str, lookups: dict) -> dict:
    """Best-effort phase 1: prefer IKEv2 chain (profile→proposal); fall back to first ISAKMP policy."""
    p1 = {
        "protocol": "",
        "encryption": [],
        "integrity": [],
        "dh_group": [],
        "lifetime": "",
        "auth": "",
        "profile_name": "",
    }
    prof = lookups["ipsec_profile_by_name"].get(profile_name) if profile_name else None
    if prof:
        v2_prof_name = prof.get("ikev2_profile")
        v2prof = lookups["ikev2_profile_by_name"].get(v2_prof_name) if v2_prof_name else None
        if v2prof:
            p1["protocol"] = "ikev2"
            p1["profile_name"] = v2prof.get("name", "")
            p1["auth"] = v2prof.get("auth_local", "") or v2prof.get("auth_remote", "")
            # Resolve proposals via policy match. We don't always know which
            # policy applies — take the first proposal we can find.
            for pol in (lookups.get("ikev2_proposal_by_name") or {}).values():
                p1["encryption"] = pol.get("encryption", [])
                p1["integrity"]  = pol.get("integrity", [])
                p1["dh_group"]   = pol.get("group", [])
                break

    if not p1["protocol"] and lookups["isakmp_policies_sorted"]:
        pol = lookups["isakmp_policies_sorted"][0]
        p1["protocol"]   = "ikev1"
        p1["encryption"] = [pol.get("encryption", "")] if pol.get("encryption") else []
        p1["integrity"]  = [pol.get("hash", "")] if pol.get("hash") else []
        p1["dh_group"]   = [pol.get("group", "")] if pol.get("group") else []
        p1["auth"]       = pol.get("authentication", "")
        p1["lifetime"]   = str(pol.get("lifetime", ""))
        p1["profile_name"] = f"isakmp policy {pol.get('priority')}"
    return p1


def _resolve_phase2(profile_name: str, lookups: dict, transform_set_names: list[str] | None = None) -> dict:
    p2 = {
        "name": "",
        "transform_sets": [],
        "encryption": [],
        "integrity": [],
        "pfs_group": "",
        "sa_lifetime_sec": None,
        "sa_lifetime_kb": None,
    }
    ts_names: list[str] = []

    prof = lookups["ipsec_profile_by_name"].get(profile_name) if profile_name else None
    # Always echo the referenced profile name even when the body can't be
    # resolved — that way the UI shows "TSA_IPSEC_PROFILE" rather than "—"
    # for the Profile/TS field, which is more useful than nothing.
    if profile_name:
        p2["name"] = profile_name
    if prof:
        p2["name"] = prof.get("name", "") or p2["name"]
        p2["pfs_group"] = prof.get("pfs_group", "")
        p2["sa_lifetime_sec"] = prof.get("sa_lifetime_sec")
        p2["sa_lifetime_kb"] = prof.get("sa_lifetime_kb")
        ts_names = prof.get("transform_sets", []) or []

    if transform_set_names:
        ts_names = list(transform_set_names) + ts_names

    seen_ts: list[str] = []
    encs: list[str] = []
    auths: list[str] = []
    for tname in ts_names:
        if tname in seen_ts: continue
        seen_ts.append(tname)
        ts = lookups["transform_set_by_name"].get(tname)
        if not ts: continue
        # IOS syntax: `esp-aes 256 esp-sha256-hmac` — pair encryption tokens
        # with the following numeric key size.
        toks = list(ts.get("transforms", []))
        idx = 0
        while idx < len(toks):
            tok = toks[idx]
            nxt = toks[idx + 1] if idx + 1 < len(toks) else ""
            if tok.startswith("esp-") and "hmac" in tok:
                auths.append(tok)
            elif tok.startswith("esp-"):
                if nxt.isdigit():
                    encs.append(f"{tok}-{nxt}")
                    idx += 1
                else:
                    encs.append(tok)
            elif tok.startswith("ah-"):
                auths.append(tok)
            idx += 1
    p2["transform_sets"] = seen_ts
    p2["encryption"] = encs
    p2["integrity"] = auths
    return p2


def _stable_id(*parts: Any) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8", "replace"))
        h.update(b"|")
    return h.hexdigest()[:16]


def _make_p2p_tunnel(
    ttype: str,
    device_id: str,
    hostname: str,
    mgmt_ip: str,
    iface: dict,
    lookups: dict,
) -> dict:
    profile_name = iface.get("tunnel_protection_profile", "")
    phase1 = _resolve_phase1(profile_name, lookups)
    phase2 = _resolve_phase2(profile_name, lookups)

    endpoints = [{
        "device":     hostname,
        "device_id":  device_id,
        "device_ip":  mgmt_ip,
        "role":       "local" if ttype != "dvti" else "hub",
        "interface":  iface.get("name", ""),
        "local_ip":   iface.get("ip_address", ""),
        "local_prefix": iface.get("ip_prefix"),
        "tunnel_source": iface.get("tunnel_source", ""),
        "peer_ip":    iface.get("tunnel_destination", ""),
        "shutdown":   iface.get("shutdown", False),
        "vrf":        iface.get("vrf_forwarding") or iface.get("tunnel_vrf", ""),
        "description": iface.get("description", ""),
    }]

    tid = _stable_id("ios", ttype, device_id, iface.get("name", ""))
    return {
        "id":        tid,
        "type":      ttype,
        "platform":  "ios",
        "name":      f"{hostname}:{iface.get('name','')}",
        "endpoints": endpoints,
        "phase1":    phase1,
        "phase2":    phase2,
        "tags": {
            "tunnel_mode": iface.get("tunnel_mode", ""),
            "vrf":         iface.get("vrf_forwarding") or iface.get("tunnel_vrf", ""),
        },
    }


def _make_cryptomap_tunnel(
    device_id: str,
    hostname: str,
    mgmt_ip: str,
    entry: dict,
    parsed: dict,
    lookups: dict,
) -> dict:
    # Find which physical interface is bound to this crypto map (if any).
    bound_iface = ""
    for piface in parsed.get("physical_iface_crypto_maps", []):
        if piface.get("crypto_map") == entry.get("map_name"):
            bound_iface = piface.get("name", "")
            break

    # Phase 1: if the crypto map entry pins an IKEv2 profile, resolve via that
    # — otherwise fall back to "best-effort first ISAKMP policy".
    ikev2_prof_name = entry.get("ikev2_profile") or ""
    if ikev2_prof_name and ikev2_prof_name in lookups.get("ikev2_profile_by_name", {}):
        v2prof = lookups["ikev2_profile_by_name"][ikev2_prof_name]
        proposal = next(iter(lookups.get("ikev2_proposal_by_name", {}).values()), {})
        phase1 = {
            "protocol":     "ikev2",
            "encryption":   proposal.get("encryption", []),
            "integrity":    proposal.get("integrity", []),
            "dh_group":     proposal.get("group", []),
            "lifetime":     "",
            "auth":         v2prof.get("auth_local", "") or v2prof.get("auth_remote", ""),
            "profile_name": ikev2_prof_name,
        }
    else:
        phase1 = _resolve_phase1("", lookups)
    # Phase 2: from transform-set on the entry itself
    phase2 = _resolve_phase2(
        profile_name="",
        lookups=lookups,
        transform_set_names=entry.get("transform_sets", []) or [],
    )
    phase2["pfs_group"] = entry.get("pfs_group", "") or phase2["pfs_group"]
    phase2["sa_lifetime_sec"] = entry.get("sa_lifetime_sec") or phase2["sa_lifetime_sec"]
    phase2["sa_lifetime_kb"]  = entry.get("sa_lifetime_kb")  or phase2["sa_lifetime_kb"]

    endpoints = [{
        "device":     hostname,
        "device_id":  device_id,
        "device_ip":  mgmt_ip,
        "role":       "local",
        "interface":  bound_iface,
        "local_ip":   "",
        "peer_ip":    ", ".join(entry.get("peers", [])),
        "shutdown":   False,
        "vrf":        "",
        "description": entry.get("description", ""),
    }]

    name = f"{hostname}:{entry.get('map_name','')}/{entry.get('sequence','')}"
    tid = _stable_id("ios", "crypto_map", device_id, entry.get("map_name", ""), entry.get("sequence"))
    return {
        "id":        tid,
        "type":      "crypto_map",
        "platform":  "ios",
        "name":      name,
        "endpoints": endpoints,
        "phase1":    phase1,
        "phase2":    phase2,
        "tags": {
            "acl":      entry.get("acl", ""),
            "bound_to": bound_iface,
        },
    }


def _make_dmvpn_cloud(
    key: tuple,
    members: list[dict],
    per_device_lookups: dict[str, dict],
) -> dict:
    nhrp_id, tunnel_key, profile_name = key

    # Pick the first device that has the profile defined to resolve crypto
    # (most fleets use a globally-replicated DMVPN profile name).
    sample_dev_id = next((m["device_id"] for m in members
                          if profile_name in per_device_lookups[m["device_id"]]["ipsec_profile_by_name"]),
                         members[0]["device_id"])
    lookups = per_device_lookups[sample_dev_id]
    phase1 = _resolve_phase1(profile_name, lookups)
    phase2 = _resolve_phase2(profile_name, lookups)

    endpoints: list[dict] = []
    hub_count = 0
    spoke_count = 0
    for m in members:
        role = dmvpn_role(m["iface"])
        if role == "hub": hub_count += 1
        elif role == "spoke": spoke_count += 1
        endpoints.append({
            "device":     m["hostname"],
            "device_id":  m["device_id"],
            "device_ip":  m["mgmt_ip"],
            "role":       role,
            "interface":  m["iface"].get("name", ""),
            "local_ip":   m["iface"].get("ip_address", ""),
            "local_prefix": m["iface"].get("ip_prefix"),
            "tunnel_source": m["iface"].get("tunnel_source", ""),
            "peer_ip":    ", ".join(m["iface"].get("nhrp_nhs", [])) or "(multipoint)",
            "shutdown":   m["iface"].get("shutdown", False),
            "vrf":        m["iface"].get("vrf_forwarding") or m["iface"].get("tunnel_vrf", ""),
            "description": m["iface"].get("description", ""),
        })

    name = f"DMVPN nhrp-{nhrp_id}/key-{tunnel_key}/{profile_name or 'unprotected'}"
    tid = _stable_id("dmvpn", nhrp_id, tunnel_key, profile_name)
    return {
        "id":        tid,
        "type":      "dmvpn",
        "platform":  "ios",
        "name":      name,
        "endpoints": endpoints,
        "phase1":    phase1,
        "phase2":    phase2,
        "tags": {
            "nhrp_network_id": str(nhrp_id) if nhrp_id is not None else "",
            "tunnel_key":      str(tunnel_key) if tunnel_key is not None else "",
            "profile":         profile_name,
            "hubs":            str(hub_count),
            "spokes":          str(spoke_count),
        },
    }


# ── Palo Alto side ───────────────────────────────────────────────────────────

def _build_palo_tunnels(palo: dict[str, list]) -> list[dict]:
    """
    Build palo_ipsec entries by joining ipsec_tunnels -> ike_gateways ->
    ike_crypto_profiles + ipsec_crypto_profiles.
    """
    gateways      = {g["name"]: g for g in palo.get("ike_gateways", [])}
    ike_profiles  = {p["name"]: p for p in palo.get("ike_profiles", [])}
    ipsec_profiles = {p["name"]: p for p in palo.get("ipsec_profiles", [])}

    out: list[dict] = []
    for t in palo.get("ipsec_tunnels", []):
        gw = gateways.get(t.get("ike_gateway", ""), {})
        ikep_name = gw.get("ikev2_profile") or gw.get("ikev1_profile") or ""
        ikep = ike_profiles.get(ikep_name, {})

        ipsec_prof_name = t.get("ipsec_profile", "")
        ipsec_prof = ipsec_profiles.get(ipsec_prof_name, {})

        phase1 = {
            "protocol":     gw.get("protocol", "") or ("ikev2" if gw.get("ikev2_profile") else "ikev1"),
            "encryption":   ikep.get("encryption", []),
            "integrity":    ikep.get("hash", []),
            "dh_group":     ikep.get("dh_group", []),
            "lifetime":     f"{ikep.get('lifetime_value','')} {ikep.get('lifetime_unit','')}".strip(),
            "auth":         gw.get("auth", ""),
            "profile_name": ikep_name,
        }

        phase2 = {
            "name":            ipsec_prof_name,
            "transform_sets":  [],
            "encryption":      ipsec_prof.get("encryption", []),
            "integrity":       ipsec_prof.get("authentication", []),
            "pfs_group":       ipsec_prof.get("dh_group", ""),
            "sa_lifetime_sec": _palo_seconds(ipsec_prof.get("lifetime_value"), ipsec_prof.get("lifetime_unit")),
            "sa_lifetime_kb":  _palo_kb(ipsec_prof.get("lifesize_value"), ipsec_prof.get("lifesize_unit")),
        }

        endpoints = [{
            "device":     t.get("template") or t.get("scope") or "panorama",
            "device_id":  "",
            "device_ip":  "",
            "role":       "local",
            "interface":  t.get("tunnel_interface", ""),
            "local_ip":   gw.get("local_ip", ""),
            "local_prefix": None,
            "tunnel_source": gw.get("local_interface", ""),
            "peer_ip":    gw.get("peer_address", ""),
            "shutdown":   t.get("disabled", False) or gw.get("disabled", False),
            "vrf":        "",
            "description": "",
        }]

        tid = _stable_id("palo", t.get("scope", ""), t.get("template", ""), t.get("name", ""))
        out.append({
            "id":        tid,
            "type":      "palo_ipsec",
            "platform":  "palo",
            "name":      t.get("name", ""),
            "endpoints": endpoints,
            "phase1":    phase1,
            "phase2":    phase2,
            "tags": {
                "scope":         t.get("scope", ""),
                "template":      t.get("template", ""),
                "ike_gateway":   t.get("ike_gateway", ""),
                "ipsec_profile": ipsec_prof_name,
                "tunnel_interface": t.get("tunnel_interface", ""),
            },
        })
    return out


def _palo_seconds(val, unit) -> int | None:
    if not val: return None
    try: n = int(val)
    except (TypeError, ValueError): return None
    u = (unit or "").lower()
    if u == "seconds": return n
    if u == "minutes": return n * 60
    if u == "hours":   return n * 3600
    if u == "days":    return n * 86400
    return None


def _palo_kb(val, unit) -> int | None:
    if not val: return None
    try: n = int(val)
    except (TypeError, ValueError): return None
    u = (unit or "").lower()
    if u == "kb": return n
    if u == "mb": return n * 1024
    if u == "gb": return n * 1024 * 1024
    return None


# ── Stats ────────────────────────────────────────────────────────────────────

def _stats(tunnels: list[dict]) -> dict:
    by_type:        dict[str, int] = {}
    by_platform:    dict[str, int] = {}
    endpoints_by_type: dict[str, int] = {}
    for t in tunnels:
        by_type[t["type"]]            = by_type.get(t["type"], 0) + 1
        by_platform[t["platform"]]    = by_platform.get(t["platform"], 0) + 1
        endpoints_by_type[t["type"]]  = endpoints_by_type.get(t["type"], 0) + len(t.get("endpoints", []))
    total_endpoints = sum(endpoints_by_type.values())
    return {
        "total":              len(tunnels),
        "total_endpoints":    total_endpoints,
        "by_type":            by_type,
        "by_platform":        by_platform,
        "endpoints_by_type":  endpoints_by_type,
    }
