"""utils/ip_audit.py — Reconcile the IP registry against the live network.

The registry (``clients.ip_registry``) is *intent* — what TSA says each site
should own. This module gathers what's actually **observed** on the network
from the platform caches and classifies the difference, per site:

    in-sync        registry prefix confirmed by at least one live source
    registry-only  documented but not seen anywhere (stale, or — for IPv6 —
                   simply not deployed yet)
    network-only   seen on the network but undocumented (the big win: shadow
                   subnets you can bulk-accept into the registry)
    mismatch       a network prefix overlaps a registry prefix without nesting
                   cleanly (e.g. registry /24 vs a live /23)

Two classes of observation are pulled OUT of per-site drift first, because they
are not per-site allocations and otherwise drown the signal:

  * **DMVPN / shared overlays** — IPs on ``Tunnel*`` / ``Virtual-Template*``
    interfaces. The same overlay subnet (e.g. a /21) lives on every router in
    the DMVPN, so it's modeled as a *shared container* (like the STIP /48),
    grouped by tunnel and de-duped across sites with a participant count.
  * **Infrastructure host routes** — loopbacks, mgmt, point-to-point links and
    anything host-length (``/30``+ v4, ``/126``+ v6). Bucketed and collapsed,
    counted but not treated as drift.

It is **cache-only** — reads whatever the platform warmers populated (IPAM
tree, DNAC interfaces/pools, Nexus interfaces, Panorama interfaces/address
objects, cached ACI BD/EPG subnets) and makes no live API calls. Source
extractors are defensive (an unexpected shape yields nothing, not an
exception); ``reconcile`` is a pure function and is unit-tested without a cache.
"""
from __future__ import annotations

import datetime as _dt
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from cache import IPAM_TREE_CACHE_KEY
from utils import ipam_net
from utils.site_code import site_code_from_hostname, site_code_strict

logger = logging.getLogger(__name__)

ALL_SOURCES = ("dnac", "nexus", "panorama", "aci")

# Host-route thresholds (the "bucket & collapse" knobs). A prefix at or beyond
# these lengths is infrastructure (loopback/p2p/host), not a site allocation.
HOST_V4_MIN_PREFIX = 30      # /30, /31, /32
HOST_V6_MIN_PREFIX = 126     # /126, /127, /128
# Interface types (from the shared classifier) that are always infrastructure.
HOST_IFACE_TYPES = frozenset({"loopback", "p2p", "management"})


@dataclass
class Observed:
    """One concrete network seen on the live network."""
    cidr: str
    family: int
    source: str            # dnac | nexus | panorama | aci
    site_code: str = ""    # best-effort attribution ("" when unknown)
    label: str = ""        # device / interface / object name for context
    interface: str = ""    # raw interface name when known (e.g. "Tunnel200")
    iface_type: str = ""   # classified type (tunnel/loopback/p2p/svi/…)


# Mirrors utils.ipam_engine.classify_interface (kept local so the audit has no
# heavy import) — plus Virtual-Template so dVTI tunnels group with DMVPN.
_RE_TUNNEL = re.compile(r"^(tu|tunnel|vt|virtual-?template)[\d/.]*", re.I)
_RE_LOOPBACK = re.compile(r"^(lo|loopback)\d", re.I)
_RE_MGMT = re.compile(r"^ma\d", re.I)
_RE_SVI = re.compile(r"^(vl|vlan)\d", re.I)


def _iface_type(name: str, family: int, prefixlen: int) -> str:
    n = (name or "").strip()
    if _RE_TUNNEL.match(n):
        return "tunnel"
    if _RE_LOOPBACK.match(n) or (family == 4 and prefixlen == 32) or (family == 6 and prefixlen == 128):
        return "loopback"
    if _RE_SVI.match(n):
        return "svi"
    if "mgmt" in n.lower() or "management" in n.lower() or _RE_MGMT.match(n):
        return "management"
    if (family == 4 and prefixlen in (30, 31)) or (family == 6 and prefixlen == 127):
        return "p2p"
    return ""


def _canon(value: Optional[str]) -> Optional[tuple[int, str, int]]:
    """(family, canonical_cidr, prefixlen) or None for pseudo-labels / junk."""
    if not value:
        return None
    if "/" not in value and ":" not in value and "." not in value:
        return None  # tree pseudo-labels: "Host Routes (X)", "Loopbacks (n)"
    try:
        fam, _, plen, canon = ipam_net.canonical(value)
        return fam, canon, plen
    except (ValueError, TypeError):
        return None


def _obs(cidr_raw: Optional[str], source: str, *, site_code: str = "",
         label: str = "", interface: str = "",
         iface_type_hint: str = "") -> Optional[Observed]:
    c = _canon(cidr_raw)
    if not c:
        return None
    fam, canon, plen = c
    itype = iface_type_hint or _iface_type(interface, fam, plen)
    return Observed(cidr=canon, family=fam, source=source, site_code=site_code,
                    label=label, interface=interface, iface_type=itype)


# ── Source extractors ──────────────────────────────────────────────────────────

def _from_ipam_tree(cache) -> list[Observed]:
    """Walk the aggregated IPAM tree — nodes carry a ``site`` path, both
    families, and an ``interface_type`` (loopback/tunnel/svi/…)."""
    tree = cache.get(IPAM_TREE_CACHE_KEY)
    if not tree:
        return []
    out: list[Observed] = []

    def walk(nodes):
        for n in nodes or []:
            o = _obs(n.get("cidr"), "dnac",
                     site_code=site_code_strict(n.get("site") or "").upper(),
                     label=n.get("display_name") or n.get("source") or "",
                     iface_type_hint=n.get("interface_type") or "")
            if o:
                out.append(o)
            walk(n.get("children"))

    walk(tree.get("ipv4"))
    walk(tree.get("ipv6"))
    return out


def _from_dnac_interfaces(cache) -> list[Observed]:
    """Raw DNAC interfaces — the authoritative place for the interface NAME
    (``portName`` like ``Tunnel200``/``Loopback0``), which the tree drops."""
    sitemap = cache.get("device_site_map") or {}
    out: list[Observed] = []
    for i in cache.get("dnac_interfaces") or []:
        addr, mask = i.get("ipv4Address"), i.get("ipv4Mask")
        if not addr or not mask:
            continue
        port = i.get("portName") or ""
        o = _obs(f"{addr}/{mask}", "dnac",
                 site_code=site_code_strict(sitemap.get(i.get("deviceId"), "") or "").upper(),
                 label=i.get("deviceName") or port, interface=port)
        if o:
            out.append(o)
    return out


def _from_dnac_pools(cache) -> list[Observed]:
    out: list[Observed] = []
    for p in cache.get("dnac_global_pools") or []:
        o = _obs(p.get("ipPoolCidr") or p.get("cidr"), "dnac",
                 label=p.get("ipPoolName") or "global-pool")
        if o:
            out.append(o)
    for sp in cache.get("dnac_reserve_subpools") or []:
        code = site_code_strict(sp.get("siteName") or sp.get("groupName") or "").upper()
        for ip in (sp.get("ipPools") or []):
            o = _obs(ip.get("ipPoolCidr") or ip.get("cidr"), "dnac",
                     site_code=code, label=ip.get("ipPoolName") or "reserve-pool")
            if o:
                out.append(o)
    return out


def _from_nexus(cache) -> list[Observed]:
    out: list[Observed] = []
    for i in cache.get("nexus_interfaces") or []:
        name = i.get("interface_name") or ""
        o = _obs(i.get("ipv4_address"), "nexus",
                 site_code=site_code_from_hostname(i.get("hostname") or "").upper(),
                 label=f"{i.get('hostname','')} {name}".strip(), interface=name)
        if o:
            out.append(o)
    return out


def _from_panorama(cache) -> list[Observed]:
    out: list[Observed] = []
    for dev in cache.get("pan_interfaces") or []:
        host = dev.get("hostname") or ""
        code = site_code_from_hostname(host).upper()
        for iface in (dev.get("interfaces") or []):
            name = iface.get("name") or ""
            o = _obs(iface.get("ipv4"), "panorama", site_code=code,
                     label=f"{host} {name}".strip(), interface=name)
            if o:
                out.append(o)
    for obj in cache.get("pan_address_objects") or []:
        if obj.get("type") != "ip-netmask":
            continue
        o = _obs(obj.get("value"), "panorama",
                 site_code=site_code_strict(obj.get("name") or "").upper(),
                 label=obj.get("name") or "addr-object")
        if o:
            out.append(o)
    return out


def _from_aci(cache) -> list[Observed]:
    """ACI BD/EPG subnets from cached per-fabric data (attribute by containment
    only — DC fabrics rarely carry a site code)."""
    keys_for_prefix = getattr(cache, "keys_for_prefix", None)
    if not callable(keys_for_prefix):
        return []
    out: list[Observed] = []

    def add(ip, label):
        o = _obs(ip, "aci", label=label)
        if o:
            out.append(o)

    try:
        keys = list(keys_for_prefix("aci_"))
    except Exception:  # pragma: no cover
        return []
    for key in keys:
        if not (key.endswith("subnets") or "bridge_domains" in key or key.endswith("subnets_bd")):
            continue
        val = cache.get(key)
        if isinstance(val, dict) and "imdata" in val:
            for item in val.get("imdata") or []:
                for cls, body in (item or {}).items():
                    attrs = (body or {}).get("attributes", {}) if isinstance(body, dict) else {}
                    if cls == "fvSubnet" or attrs.get("ip"):
                        add(attrs.get("ip"), attrs.get("dn") or key)
        elif isinstance(val, list):
            for bd in val:
                for sn in (bd.get("subnets") or []) if isinstance(bd, dict) else []:
                    add(sn.get("ip"), bd.get("name") or key)
    return out


_EXTRACTORS = {
    # DNAC: raw interfaces FIRST (they carry the interface name needed for
    # tunnel/loopback classification + tunnel labels), then the tree (v6,
    # aggregates, anything raw missed), then pools.
    "dnac": lambda cache: _from_dnac_interfaces(cache) + _from_ipam_tree(cache) + _from_dnac_pools(cache),
    "nexus": _from_nexus,
    "panorama": _from_panorama,
    "aci": _from_aci,
}


def _richness(o: Observed) -> int:
    return (1 if o.interface else 0) + (1 if o.iface_type else 0) + (1 if o.site_code else 0)


def collect_observed(cache, sources: Iterable[str] = ALL_SOURCES) -> list[Observed]:
    """Run the enabled extractors and de-dupe by ``(cidr, source, site_code)``,
    keeping the richest record. Keying on site_code (not just cidr) preserves
    one sighting per site — essential so a shared overlay isn't collapsed to a
    single site and so DMVPN participant counts survive."""
    raw: list[Observed] = []
    for name in sources:
        fn = _EXTRACTORS.get(name)
        if not fn:
            continue
        try:
            raw.extend(fn(cache))
        except Exception:  # pragma: no cover
            logger.exception("ip_audit: source %r extractor failed", name)
    best: dict[tuple[str, str, str], Observed] = {}
    for o in raw:
        k = (o.cidr, o.source, o.site_code)
        if k not in best or _richness(o) > _richness(best[k]):
            best[k] = o
    return list(best.values())


# ── Classification helpers ───────────────────────────────────────────────────

def _plen(cidr: str) -> int:
    try:
        return int(cidr.split("/")[1])
    except (IndexError, ValueError):
        return 0


def is_tunnel(o: Observed) -> bool:
    return o.iface_type == "tunnel"


def is_host(o: Observed, *, v4_min: int = HOST_V4_MIN_PREFIX,
            v6_min: int = HOST_V6_MIN_PREFIX) -> bool:
    if o.iface_type in HOST_IFACE_TYPES:
        return True
    p = _plen(o.cidr)
    return (o.family == 4 and p >= v4_min) or (o.family == 6 and p >= v6_min)


# ── Classification core (pure) ──────────────────────────────────────────────────

def _same(a: str, b: str) -> bool:
    try:
        return ipam_net.canonical(a)[3] == ipam_net.canonical(b)[3]
    except ValueError:
        return False


def _confirms(reg_cidr: str, obs_cidr: str) -> bool:
    return (_same(reg_cidr, obs_cidr)
            or ipam_net.contains(reg_cidr, obs_cidr)
            or ipam_net.contains(obs_cidr, reg_cidr))


@dataclass
class _Drift:
    cidr: str
    family: int
    site_id: Optional[int]
    site_code: str
    kind: str
    sources: set = field(default_factory=set)
    related: list = field(default_factory=list)
    label: str = ""

    def as_dict(self) -> dict:
        return {"cidr": self.cidr, "family": self.family, "site_id": self.site_id,
                "site_code": self.site_code, "kind": self.kind,
                "sources": sorted(self.sources), "related": self.related,
                "label": self.label,
                "suggested_role": "site-aggregate" if self.family == 4 else "subnet"}


def reconcile(sites: list[dict], prefixes: list[dict], observed: list[Observed], *,
              sources: Iterable[str] = ALL_SOURCES,
              host_v4_min: int = HOST_V4_MIN_PREFIX,
              host_v6_min: int = HOST_V6_MIN_PREFIX) -> dict:
    """Pure classifier. ``sites``/``prefixes`` are registry rows; ``observed``
    is the collected live view. Returns a JSON-able report."""
    registry_cidrs = {p["cidr"] for p in prefixes}
    code_to_site = {(s["site_code"] or "").upper(): s for s in sites if s.get("site_code")}
    site_prefixes: dict[int, list[dict]] = defaultdict(list)
    for p in prefixes:
        if p.get("site_id") is not None:        # skip shared containers
            site_prefixes[p["site_id"]].append(p)

    # 1) Pull tunnels + host routes out of the per-site stream first.
    tunnels = [o for o in observed if is_tunnel(o)]
    rest = [o for o in observed if not is_tunnel(o)]
    hosts = [o for o in rest if is_host(o, v4_min=host_v4_min, v6_min=host_v6_min)]
    normal = [o for o in rest if not is_host(o, v4_min=host_v4_min, v6_min=host_v6_min)]

    # 2) Attribute the remaining observations to a site (code, then containment).
    per_site_obs: dict[int, list[Observed]] = defaultdict(list)
    unattributed: list[Observed] = []
    for o in normal:
        sid = None
        if o.site_code and o.site_code in code_to_site:
            sid = code_to_site[o.site_code]["id"]
        if sid is None:
            for s in sites:
                if any(ipam_net.contains(p["cidr"], o.cidr)
                       for p in site_prefixes.get(s["id"], [])):
                    sid = s["id"]
                    break
        (per_site_obs[sid].append(o) if sid is not None else unattributed.append(o))

    # 3) Per-site classification.
    site_reports: list[dict] = []
    totals = {"in_sync": 0, "registry_only": 0, "registry_only_v6": 0,
              "network_only": 0, "mismatch": 0}
    for s in sites:
        regp = site_prefixes.get(s["id"], [])
        sobs = per_site_obs.get(s["id"], [])
        findings: list[dict] = []
        for p in regp:
            seen = [o for o in sobs if _confirms(p["cidr"], o.cidr)]
            if seen:
                findings.append({"prefix": p, "state": "in-sync",
                                 "sources": sorted({o.source for o in seen})})
                totals["in_sync"] += 1
            else:
                findings.append({"prefix": p, "state": "registry-only", "sources": []})
                totals["registry_only"] += 1
                if p.get("family") == 6:
                    totals["registry_only_v6"] += 1

        drift_by_cidr: dict[str, _Drift] = {}
        for o in sobs:
            if any(_same(o.cidr, p["cidr"]) for p in regp):
                continue
            if any(ipam_net.contains(p["cidr"], o.cidr) for p in regp):
                continue            # member of an aggregate — not drift
            overlap = [p for p in regp if ipam_net.overlaps(p["cidr"], o.cidr)]
            d = drift_by_cidr.get(o.cidr)
            if d is None:
                d = _Drift(cidr=o.cidr, family=o.family, site_id=s["id"],
                           site_code=s["site_code"], label=o.label,
                           kind="mismatch" if overlap else "network-only",
                           related=[p["cidr"] for p in overlap])
                drift_by_cidr[o.cidr] = d
            d.sources.add(o.source)

        drift = [d.as_dict() for d in drift_by_cidr.values()]
        for d in drift:
            totals[d["kind"].replace("-", "_")] += 1

        if findings or drift:
            site_reports.append({
                "site": s, "findings": findings, "drift": drift,
                "counts": {
                    "in_sync": sum(1 for f in findings if f["state"] == "in-sync"),
                    "registry_only": sum(1 for f in findings if f["state"] == "registry-only"),
                    "network_only": sum(1 for d in drift if d["kind"] == "network-only"),
                    "mismatch": sum(1 for d in drift if d["kind"] == "mismatch"),
                },
            })

    # 4) DMVPN / shared overlays — group tunnel sightings by overlay subnet.
    overlays: dict[str, dict] = {}
    for o in tunnels:
        e = overlays.setdefault(o.cidr, {"cidr": o.cidr, "family": o.family,
                                         "labels": set(), "sources": set(), "sites": set()})
        if o.interface:
            e["labels"].add(o.interface)
        e["sources"].add(o.source)
        if o.site_code:
            e["sites"].add(o.site_code)
    dmvpn_overlays = [{
        "cidr": e["cidr"], "family": e["family"],
        "labels": sorted(e["labels"]),
        "label": ", ".join(sorted(e["labels"])),
        "sources": sorted(e["sources"]),
        "participants": len(e["sites"]),
        "participant_sites": sorted(e["sites"]),
        "in_registry": e["cidr"] in registry_cidrs,
        "suggested_role": "dmvpn",
    } for e in sorted(overlays.values(), key=lambda x: x["cidr"])]

    # 5) Infrastructure host routes — counted, collapsed, not drift.
    host_by_type: dict[str, int] = defaultdict(int)
    host_items: list[dict] = []
    for o in hosts:
        host_by_type[o.iface_type or "host"] += 1
        host_items.append({"cidr": o.cidr, "family": o.family,
                           "iface_type": o.iface_type or "host",
                           "sources": [o.source], "site_code": o.site_code,
                           "label": o.label})
    host_items.sort(key=lambda x: (x["family"], x["cidr"]))

    # New-site candidates vs. truly loose unattributed.
    new_site_candidates: dict[str, list[dict]] = defaultdict(list)
    loose: list[dict] = []
    for o in unattributed:
        rec = {"cidr": o.cidr, "family": o.family, "sources": [o.source],
               "label": o.label, "site_code": o.site_code,
               "suggested_role": "site-aggregate" if o.family == 4 else "subnet"}
        (new_site_candidates[o.site_code].append(rec) if o.site_code else loose.append(rec))

    return {
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "sources": list(sources),
        "summary": {
            "sites_reported": len(site_reports),
            "observed_total": len(observed),
            **totals,
            "dmvpn_overlays": len(dmvpn_overlays),
            "dmvpn_unregistered": sum(1 for d in dmvpn_overlays if not d["in_registry"]),
            "host_routes": len(host_items),
            "unattributed": len(loose),
            "new_site_candidates": len(new_site_candidates),
        },
        "sites": site_reports,
        "dmvpn_overlays": dmvpn_overlays,
        "infrastructure": {"count": len(host_items),
                           "by_type": dict(sorted(host_by_type.items())),
                           "items": host_items},
        "new_site_candidates": [
            {"site_code": code, "prefixes": recs}
            for code, recs in sorted(new_site_candidates.items())],
        "unattributed": loose,
    }


def run_audit(cache, sites: list[dict], prefixes: list[dict], *,
              sources: Iterable[str] = ALL_SOURCES) -> dict:
    """Convenience: collect from the cache, then reconcile."""
    return reconcile(sites, prefixes, collect_observed(cache, sources), sources=sources)
