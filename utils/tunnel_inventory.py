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
    device_site_map: dict[str, str] | None = None,
    dnac_interfaces: list[dict] | None = None,
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

    # Build a fleet-wide reverse index from IP → device/site/interface, then
    # walk every endpoint to attach local_site + peer_matches. The same index
    # is stashed in the returned dict so the live-fetch path can resolve
    # session peer IPs without rebuilding it on every click.
    ip_index = build_ip_index(
        parsed_ios, device_meta, device_site_map or {}, dnac_interfaces or [],
    )
    _annotate_endpoints(tunnels, ip_index, device_site_map or {})

    return {
        "tunnels":  tunnels,
        "built_at": time.time(),
        "stats":    _stats(tunnels),
        "ip_index": ip_index,
    }


# ── IP → device/site resolution ──────────────────────────────────────────────

def build_ip_index(
    parsed_ios:      dict[str, dict],
    device_meta:     dict[str, dict],
    device_site_map: dict[str, str],
    dnac_interfaces: list[dict] | None = None,
) -> dict[str, list[dict]]:
    """Reverse index from IP (bare, no CIDR) to a list of resolution candidates.

    Candidates carry source so the UI can show *why* something matched:
      - "mgmt"          — the device's DNAC management IP
      - "interface"     — any interface IPv4 from the DNAC interface inventory
                          (covers WAN-facing physicals — the underlay/NBMA
                          address DMVPN `show crypto session detail` reports)
      - "tunnel-overlay"— an IP on a Tunnel/VT/Virtual-Template interface
      - "crypto-map"    — an IP on a physical interface with a crypto map bound

    A single IP may map to multiple devices (RFC1918 reuse across sites). We
    surface every match rather than first-wins; the UI marks ambiguity. Same
    device hitting via multiple sources (mgmt + interface) collapses into
    one entry per (device_id, source, interface).
    """
    index: dict[str, list[dict]] = {}

    def add(ip: str, device_id: str, device: str, site: str, interface: str, source: str) -> None:
        ip = _normalize_ip(ip)
        if not ip:
            return
        bucket = index.setdefault(ip, [])
        # Dedupe by (device_id, source, interface) so re-runs / overlapping
        # parses don't pile up duplicates for the same logical match.
        for existing in bucket:
            if (existing.get("device_id") == device_id
                    and existing.get("source") == source
                    and existing.get("interface") == interface):
                return
        bucket.append({
            "device_id": device_id,
            "device":    device,
            "site":      site,
            "interface": interface,
            "source":    source,
        })

    # 1) DNAC management IPs — the strongest anchor: peer = mgmt IP means the
    #    peer is a managed device we know about.
    for dev_id, meta in (device_meta or {}).items():
        mgmt = meta.get("managementIpAddress") or ""
        if not mgmt:
            continue
        hostname = meta.get("hostname") or dev_id
        site = (device_site_map or {}).get(dev_id, "")
        add(mgmt, dev_id, hostname, site, "(management)", "mgmt")

    # 2) Fleet-wide DNAC interface inventory. Critical for DMVPN — the NBMA
    #    address reported by `show crypto session` / `show dmvpn` is the
    #    underlay/WAN-facing physical interface IP, which we never get from
    #    parsing the IPsec subset of the running-config. DNAC has every iface.
    if dnac_interfaces:
        # Resolve deviceId → hostname via device_meta (DNAC's per-interface
        # `deviceName` field is occasionally blank or stale).
        host_by_id = {
            dev_id: (meta or {}).get("hostname") or dev_id
            for dev_id, meta in (device_meta or {}).items()
        }
        for iface in dnac_interfaces:
            ip = iface.get("ipv4Address") or ""
            if not ip:
                continue
            dev_id = iface.get("deviceId") or ""
            hostname = host_by_id.get(dev_id) or iface.get("deviceName") or dev_id
            site = (device_site_map or {}).get(dev_id, "")
            port = iface.get("portName") or ""
            add(ip, dev_id, hostname, site, port, "interface")

    # 3) Tunnel-interface overlay IPs + physical crypto-map interface IPs from
    #    every parsed config. The tunnel-overlay source is what resolves
    #    `show dmvpn` *tunnel* column entries (the NHRP overlay address).
    for dev_id, parsed in (parsed_ios or {}).items():
        meta = (device_meta or {}).get(dev_id, {}) or {}
        hostname = parsed.get("hostname") or meta.get("hostname", dev_id)
        site = (device_site_map or {}).get(dev_id, "")
        for iface in parsed.get("tunnel_interfaces", []) + parsed.get("virtual_templates", []):
            add(iface.get("ip_address", ""), dev_id, hostname, site,
                iface.get("name", ""), "tunnel-overlay")
        for iface in parsed.get("physical_iface_crypto_maps", []):
            add(iface.get("ip_address", ""), dev_id, hostname, site,
                iface.get("name", ""), "crypto-map")

    return index


def _normalize_ip(ip: str) -> str:
    """Strip CIDR suffix, whitespace, port suffix, etc. Returns "" for inputs
    that aren't a single bare IPv4. Multi-peer placeholders like "(multipoint)"
    fall through to "" so callers can skip them."""
    if not ip:
        return ""
    s = ip.strip()
    if not s or s.startswith("("):
        return ""
    # Strip CIDR
    if "/" in s:
        s = s.split("/", 1)[0]
    # Strip optional ":port" or zone IDs — we only care about the address
    if s.count(".") == 3 and ":" in s:
        s = s.split(":", 1)[0]
    return s


def resolve_ip(ip: str, ip_index: dict[str, list[dict]]) -> list[dict]:
    """Look up a single peer IP. Returns [] when unknown (external peer)."""
    if not ip_index:
        return []
    norm = _normalize_ip(ip)
    if not norm:
        return []
    return list(ip_index.get(norm, []))


def _split_peer_ips(peer: str) -> list[str]:
    """`peer_ip` is sometimes a comma-joined list (DMVPN NHS, crypto map peers).
    Split and de-dupe in order."""
    if not peer or peer.startswith("("):
        return []
    out: list[str] = []
    for chunk in peer.split(","):
        norm = _normalize_ip(chunk)
        if norm and norm not in out:
            out.append(norm)
    return out


def _annotate_endpoints(
    tunnels:         list[dict],
    ip_index:        dict[str, list[dict]],
    device_site_map: dict[str, str],
) -> None:
    """Walk every endpoint and attach local_site (from device_site_map) and
    peer_matches (resolved through ip_index). Mutates tunnels in-place."""
    for t in tunnels:
        for ep in t.get("endpoints", []):
            # local_site — exact device_id we already know
            dev_id = ep.get("device_id") or ""
            ep["local_site"] = device_site_map.get(dev_id, "") if dev_id else ""

            # peer_matches — each unique peer IP gets a list of candidates.
            # The shape is [{ip, matches: [...]}, ...] so the template can
            # render multi-peer (NHS list) cases cleanly.
            peer_ips = _split_peer_ips(ep.get("peer_ip", ""))
            ep["peer_matches"] = [
                {"ip": ip, "matches": resolve_ip(ip, ip_index)}
                for ip in peer_ips
            ]


def _coalesce(existing: dict, new: dict) -> dict:
    """Merge two parses of the same named object (ipsec profile, transform-set,
    ikev2 profile, …), preferring non-empty values from either side.

    Lists are unioned (order-preserving). Scalars keep the existing value unless
    it's falsy, in which case the new value wins. This way, if one device's
    snapshot of a profile is missing `set ikev2-profile` but another device's
    snapshot includes it, the merged record has both — which is the difference
    between "this tunnel is IKEv2" and "we fell through to ISAKMP guesswork".
    """
    out = dict(existing)
    for k, v in new.items():
        cur = out.get(k)
        if isinstance(v, list) and isinstance(cur, list):
            for item in v:
                if item not in cur:
                    cur.append(item)
        elif not cur and v:
            out[k] = v
    return out


def _build_global_lookups(parsed_ios: dict[str, dict]) -> dict:
    """Fleet-wide fallback for crypto resolution. Definitions of the same name
    seen on multiple devices are *merged* field-by-field via :func:`_coalesce`,
    so the global record reflects the most complete picture available.
    """
    ipsec_profiles: dict[str, dict] = {}
    transform_sets: dict[str, dict] = {}
    ikev2_profiles: dict[str, dict] = {}
    ikev2_proposals: dict[str, dict] = {}
    isakmp_policies: list[dict] = []

    def absorb(bucket: dict, item: dict) -> None:
        name = item.get("name")
        if not name:
            return
        bucket[name] = _coalesce(bucket.get(name, {}), item)

    for parsed in parsed_ios.values():
        for p in parsed.get("ipsec_profiles", []):
            absorb(ipsec_profiles, p)
        for t in parsed.get("transform_sets", []):
            absorb(transform_sets, t)
        for p in parsed.get("ikev2_profiles", []):
            absorb(ikev2_profiles, p)
        for p in parsed.get("ikev2_proposals", []):
            absorb(ikev2_proposals, p)
        isakmp_policies.extend(parsed.get("isakmp_policies", []))

    return {
        "ipsec_profile_by_name":   ipsec_profiles,
        "transform_set_by_name":   transform_sets,
        "ikev2_profile_by_name":   ikev2_profiles,
        "ikev2_proposal_by_name":  ikev2_proposals,
        "isakmp_policies_sorted":  sorted(isakmp_policies, key=lambda p: p.get("priority", 9999)),
    }


def _merge_lookups(primary: dict, fallback: dict) -> dict:
    """Return a lookup that prefers ``primary`` entries but falls back to
    ``fallback``. Crucially, when both sides know about the same name we do a
    *field-by-field* merge so a partial per-device snapshot can't blank out a
    complete fleet-wide one.

    Example: if the per-device parse of ``TSA_IPSEC_PROFILE`` is missing
    ``set ikev2-profile`` (because the snapshot was incomplete) but the global
    aggregate captured it from another device, plain ``dict.update`` would
    *replace* the global entry with the local incomplete one — losing the
    IKEv2 binding. Using :func:`_coalesce` here means truthy values from
    either side win.
    """
    out = {}
    for key in ("ipsec_profile_by_name", "transform_set_by_name",
                "ikev2_profile_by_name", "ikev2_proposal_by_name"):
        merged = dict(fallback.get(key, {}))
        for name, item in (primary.get(key) or {}).items():
            if name in merged:
                merged[name] = _coalesce(merged[name], item)
            else:
                merged[name] = item
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


_NAME_STOPWORDS = {"profile", "ipsec", "ike", "ikev", "tunnel", "crypto"}


def _name_tokens(s: str) -> set[str]:
    """Tokenize a profile/binding name for similarity scoring. Splits on
    ``_`` and ``-``, lowercases, and drops generic tokens (``profile``,
    ``ipsec``, ...) so the *distinctive* parts of the name drive matching."""
    import re as _re
    out: set[str] = set()
    for part in _re.split(r"[_\-]+", (s or "").lower()):
        if part and part not in _NAME_STOPWORDS:
            out.add(part)
    return out


def _score_binding(tunnel_ref: str, binding_name: str) -> int:
    """Count shared distinctive tokens between the tunnel's referenced
    profile name and an obfuscated profile's IKE-binding name. Used to
    pick the right obfuscated profile when a device has both an IKEv1 and
    an IKEv2 obfuscated block and the named lookup is impossible (DNAC
    redacted both headers).

    Example: ``TSA_HSDN_IPSEC_PROFILE`` vs binding ``TSA_HSDN_ISAKMP_PROFILE``
    shares {tsa, hsdn} → score 2; vs ``TSA_PROFILE_IKEv2`` shares {tsa} →
    score 1. The IKEv1 binding wins. For ``TSA_IPSEC_PROFILE`` both bindings
    score 1 → tiebreaker (IKEv2) wins.
    """
    return len(_name_tokens(tunnel_ref) & _name_tokens(binding_name))


def _ikev2_proposal_fields(lookups: dict) -> dict:
    """Pull encryption/integrity/dh_group from the first IKEv2 proposal we can
    find. The IKEv2 proposal selection in IOS is policy-driven and we don't
    track which proposal a given session negotiated — taking the first one
    available is the same heuristic IOS-XE's `show crypto session detail`
    output exposes when there's only one policy/proposal pair on the device.
    """
    for pol in (lookups.get("ikev2_proposal_by_name") or {}).values():
        return {
            "encryption": pol.get("encryption", []),
            "integrity":  pol.get("integrity", []),
            "dh_group":   pol.get("group", []),
        }
    return {"encryption": [], "integrity": [], "dh_group": []}


def _resolve_phase1(profile_name: str, lookups: dict) -> dict:
    """Best-effort phase 1: prefer IKEv2 chain (profile→proposal); fall back to first ISAKMP policy.

    Key signal for the IKE version is the IPsec profile body:
      - ``set ikev2-profile NAME``  → tunnel uses IKEv2 (regardless of whether
        we can find the ``crypto ikev2 profile`` block to enrich details).
      - ``set isakmp-profile NAME`` → tunnel uses IKEv1 (explicit).
      - Profile not findable by name (DNAC redacts ``crypto ipsec profile
        <name>`` to ``crypto ipsec xxxx`` on its API output) → scan all
        obfuscated profiles in the lookup. If any carry ``set ikev2-profile``
        we report IKEv2; if only ``set isakmp-profile`` is present we report
        IKEv1. In a mixed-fleet device the IKEv2 binding wins because every
        named IKEv1 fallback would otherwise mask the IKEv2 evidence.
      - Truly no profile binding anywhere → fall back to the first ISAKMP
        policy as a last-resort guess.
    """
    p1 = {
        "protocol": "",
        "encryption": [],
        "integrity": [],
        "dh_group": [],
        "lifetime": "",
        "auth": "",
        "profile_name": "",
    }

    def apply_ikev2(v2_prof_name: str) -> None:
        p1["protocol"] = "ikev2"
        p1["profile_name"] = v2_prof_name
        v2prof = lookups["ikev2_profile_by_name"].get(v2_prof_name)
        if v2prof:
            p1["auth"] = v2prof.get("auth_local", "") or v2prof.get("auth_remote", "")
        proposal = _ikev2_proposal_fields(lookups)
        p1["encryption"] = proposal["encryption"]
        p1["integrity"]  = proposal["integrity"]
        p1["dh_group"]   = proposal["dh_group"]

    prof = lookups["ipsec_profile_by_name"].get(profile_name) if profile_name else None
    if prof:
        v2_prof_name = prof.get("ikev2_profile") or ""
        v1_prof_name = prof.get("isakmp_profile") or ""
        if v2_prof_name:
            apply_ikev2(v2_prof_name)
        elif v1_prof_name:
            # Profile body says explicitly IKEv1 (set isakmp-profile). Use
            # the device's ISAKMP policy for crypto details but tag the
            # profile_name with the *real* binding rather than the generic
            # "isakmp policy N" placeholder.
            if lookups["isakmp_policies_sorted"]:
                pol = lookups["isakmp_policies_sorted"][0]
                p1["protocol"]   = "ikev1"
                p1["encryption"] = [pol.get("encryption", "")] if pol.get("encryption") else []
                p1["integrity"]  = [pol.get("hash", "")] if pol.get("hash") else []
                p1["dh_group"]   = [pol.get("group", "")] if pol.get("group") else []
                p1["auth"]       = pol.get("authentication", "")
                p1["lifetime"]   = str(pol.get("lifetime", ""))
                p1["profile_name"] = v1_prof_name

    # Named lookup missed → fall back to obfuscated profiles. When a device
    # has both IKEv1 and IKEv2 obfuscated blocks (common in mixed fleets that
    # are mid-migration), we pick the one whose binding *name* best matches
    # the tunnel's referenced profile name. Token-overlap scoring works well
    # because the customer's naming convention almost always shares the same
    # site/realm tokens between the tunnel's profile reference and the
    # underlying IKE binding (e.g. ``TSA_HSDN_IPSEC_PROFILE`` ↔
    # ``TSA_HSDN_ISAKMP_PROFILE``).
    if not p1["protocol"]:
        obfuscated = [
            v for k, v in lookups["ipsec_profile_by_name"].items()
            if k.startswith("__obfuscated_ipsec_profile_") or v.get("_obfuscated")
        ]

        best_v2_score, best_v2_name = -1, ""
        best_v1_score, best_v1_name = -1, ""
        for prof in obfuscated:
            v2 = prof.get("ikev2_profile") or ""
            v1 = prof.get("isakmp_profile") or ""
            if v2:
                s = _score_binding(profile_name, v2)
                if s > best_v2_score:
                    best_v2_score, best_v2_name = s, v2
            if v1:
                s = _score_binding(profile_name, v1)
                if s > best_v1_score:
                    best_v1_score, best_v1_name = s, v1

        chosen = None
        if best_v2_name and best_v1_name:
            # Highest score wins; tie goes to IKEv2 since the modern protocol
            # is more likely in active use and the IKEv1 path is usually a
            # legacy holdover.
            chosen = "v2" if best_v2_score >= best_v1_score else "v1"
        elif best_v2_name:
            chosen = "v2"
        elif best_v1_name:
            chosen = "v1"

        if chosen == "v2":
            apply_ikev2(best_v2_name)
        elif chosen == "v1" and lookups["isakmp_policies_sorted"]:
            pol = lookups["isakmp_policies_sorted"][0]
            p1["protocol"]   = "ikev1"
            p1["encryption"] = [pol.get("encryption", "")] if pol.get("encryption") else []
            p1["integrity"]  = [pol.get("hash", "")] if pol.get("hash") else []
            p1["dh_group"]   = [pol.get("group", "")] if pol.get("group") else []
            p1["auth"]       = pol.get("authentication", "")
            p1["lifetime"]   = str(pol.get("lifetime", ""))
            p1["profile_name"] = best_v1_name

    # Last resort: no IPsec profile bindings anywhere. Guess from the first
    # ISAKMP policy. This is the only place we synthesize a "isakmp policy N"
    # profile_name — if the user sees that string in the UI, it means we
    # couldn't find a single profile-level binding to report on.
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


def _classify_dmvpn_members(members: list[dict]) -> dict[int, str]:
    """Decide hub vs spoke for every member of a DMVPN cloud by analyzing the
    NHS reference graph across the whole cloud.

    Reasoning: a hub's tunnel IP is named in *other* members' ``ip nhrp nhs``
    lines (every spoke registers with every hub; hubs in a multi-hub mesh
    also list peer hubs). A spoke's tunnel IP is never referenced by anyone.

    So we count NHS references for each tunnel IP across all members. A
    member whose ``local_ip`` shows up in someone else's NHS list is a hub.
    Members with NHS entries but who aren't themselves referenced are spokes.
    Per-interface signals (``ip nhrp map multicast dynamic``) are kept as a
    fallback for the lone-snapshot case where the reference graph is empty.

    Returns a dict mapping ``id(member)`` → role. Caller looks up roles by
    object identity to avoid index/order coupling.
    """
    # NHS lines are parsed as a list of the first whitespace-separated token,
    # which for "ip nhrp nhs <tunnel-ip> nbma <nbma-ip> multicast" is the
    # tunnel-side IP — exactly what matches a peer's local_ip on the overlay.
    nhs_ref_count: dict[str, int] = {}
    for m in members:
        for nhs_ip in (m["iface"].get("nhrp_nhs") or []):
            nhs_ref_count[nhs_ip] = nhs_ref_count.get(nhs_ip, 0) + 1

    roles: dict[int, str] = {}
    for m in members:
        local_ip = m["iface"].get("ip_address", "")
        nhs_list = m["iface"].get("nhrp_nhs") or []
        nhs_self_refs = sum(1 for nhs in nhs_list if nhs == local_ip)
        peer_refs = nhs_ref_count.get(local_ip, 0) - nhs_self_refs

        if peer_refs > 0:
            # Someone else lists me as their NHS → I'm a hub.
            roles[id(m)] = "hub"
        elif any(mc.lower() == "dynamic" for mc in m["iface"].get("nhrp_map_multicast", [])):
            # Fallback hub signal — useful when we only have the hub's own
            # snapshot and no spoke configs in cache to vouch for it.
            roles[id(m)] = "hub"
        elif nhs_list:
            roles[id(m)] = "spoke"
        else:
            roles[id(m)] = "unknown"
    return roles


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

    # Cloud-aware role classification — overrides the per-interface guess by
    # cross-referencing every member's NHS list against every other member's
    # local IP. See _classify_dmvpn_members above for why.
    roles = _classify_dmvpn_members(members)

    endpoints: list[dict] = []
    hub_count = 0
    spoke_count = 0
    for m in members:
        role = roles.get(id(m), "unknown")
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
