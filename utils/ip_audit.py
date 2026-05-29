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
    vlan: Optional[int] = None  # VLAN id for SVIs (e.g. Vlan100 → 100)


# Mirrors utils.ipam_engine.classify_interface (kept local so the audit has no
# heavy import) — plus Virtual-Template so dVTI tunnels group with DMVPN.
_RE_TUNNEL = re.compile(r"^(tu|tunnel|vt|virtual-?template)[\d/.]*", re.I)
_RE_LOOPBACK = re.compile(r"^(lo|loopback)\d", re.I)
_RE_MGMT = re.compile(r"^ma\d", re.I)
_RE_SVI = re.compile(r"^(vl|vlan)\d", re.I)


_RE_VLAN_ID = re.compile(r"^(?:vl|vlan)\s*(\d+)", re.I)

# How a discovered prefix's interface type maps to a registry role suggestion.
_ROLE_BY_IFACE = {
    "svi": "vlan", "aggregate": "site-aggregate", "tunnel": "dmvpn",
    "loopback": "loopback", "management": "mgmt", "p2p": "transit",
}


def _vlan_from(name: str) -> Optional[int]:
    m = _RE_VLAN_ID.match((name or "").strip())
    return int(m.group(1)) if m else None


def _suggest_role(iface_type: str, family: int) -> str:
    """A sensible registry role for an accepted prefix, from its interface type.
    Falls back to 'subnet' (NOT 'site-aggregate') so VLAN/host subnets aren't
    mislabeled as the site's aggregate."""
    return _ROLE_BY_IFACE.get(iface_type, "subnet")


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
    """(family, canonical_cidr, prefixlen) or None for pseudo-labels / junk.
    Default routes (/0) are rejected — they are not allocations, and a 0.0.0.0/0
    in the registry would 'cover' every address and silence the audit."""
    if not value:
        return None
    if "/" not in value and ":" not in value and "." not in value:
        return None  # tree pseudo-labels: "Host Routes (X)", "Loopbacks (n)"
    try:
        fam, _, plen, canon = ipam_net.canonical(value)
    except (ValueError, TypeError):
        return None
    if plen == 0:
        return None  # 0.0.0.0/0 or ::/0 — default route, not address space
    return fam, canon, plen


def _obs(cidr_raw: Optional[str], source: str, *, site_code: str = "",
         label: str = "", interface: str = "", iface_type_hint: str = "",
         vlan_hint: Optional[int] = None) -> Optional[Observed]:
    c = _canon(cidr_raw)
    if not c:
        return None
    fam, canon, plen = c
    itype = iface_type_hint or _iface_type(interface, fam, plen)
    vlan = vlan_hint if vlan_hint is not None else _vlan_from(interface)
    return Observed(cidr=canon, family=fam, source=source, site_code=site_code,
                    label=label, interface=interface, iface_type=itype, vlan=vlan)


def _code(*texts: Optional[str]) -> str:
    """First real 4-char site code found across the given strings (site path,
    then device hostname). SOHO and other tag-shaped tokens are filtered by
    site_code_strict's stopword list, so the real code wins."""
    for t in texts:
        c = site_code_strict(t or "")
        if c:
            return c.upper()
    return ""


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
                     site_code=_code(n.get("site"), n.get("device")),
                     label=n.get("display_name") or n.get("source") or "",
                     iface_type_hint=n.get("interface_type") or "",
                     vlan_hint=n.get("vlan_id"))
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
                 site_code=_code(sitemap.get(i.get("deviceId"), ""), i.get("deviceName")),
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


def _host_by_length(o: Observed, v4_min: int = HOST_V4_MIN_PREFIX,
                    v6_min: int = HOST_V6_MIN_PREFIX) -> bool:
    p = _plen(o.cidr)
    return (o.family == 4 and p >= v4_min) or (o.family == 6 and p >= v6_min)


def is_host(o: Observed, *, v4_min: int = HOST_V4_MIN_PREFIX,
            v6_min: int = HOST_V6_MIN_PREFIX) -> bool:
    return o.iface_type in HOST_IFACE_TYPES or _host_by_length(o, v4_min, v6_min)


def is_overlay(o: Observed, *, v4_min: int = HOST_V4_MIN_PREFIX,
               v6_min: int = HOST_V6_MIN_PREFIX) -> bool:
    """A tunnel that is NOT host-length — i.e. a multipoint DMVPN overlay. A
    /30-/31 (or /127) tunnel is a point-to-point link and falls to host bucket."""
    return is_tunnel(o) and not _host_by_length(o, v4_min, v6_min)


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
    iface_type: str = ""
    vlan: Optional[int] = None

    def as_dict(self) -> dict:
        return {"cidr": self.cidr, "family": self.family, "site_id": self.site_id,
                "site_code": self.site_code, "kind": self.kind,
                "sources": sorted(self.sources), "related": self.related,
                "label": self.label, "vlan_id": self.vlan,
                "suggested_role": _suggest_role(self.iface_type, self.family)}


def reconcile(sites: list[dict], prefixes: list[dict], observed: list[Observed], *,
              sources: Iterable[str] = ALL_SOURCES,
              host_v4_min: int = HOST_V4_MIN_PREFIX,
              host_v6_min: int = HOST_V6_MIN_PREFIX) -> dict:
    """Pure classifier. ``sites``/``prefixes`` are registry rows; ``observed``
    is the collected live view. Returns a JSON-able report."""
    registry_cidrs = {p["cidr"] for p in prefixes}
    sites_by_id = {s["id"]: s for s in sites}
    code_to_site = {(s["site_code"] or "").upper(): s for s in sites if s.get("site_code")}
    site_prefixes: dict[int, list[dict]] = defaultdict(list)
    for p in prefixes:
        if p.get("site_id") is not None:        # skip shared containers
            site_prefixes[p["site_id"]].append(p)

    containers = [p for p in prefixes if p.get("site_id") is None]

    # 1) Partition: multipoint tunnel overlays and host routes come out of the
    #    per-site stream first. A tunnel at host length (/30+ v4, /127+ v6) is a
    #    point-to-point link, not a shared overlay → it falls to the host bucket.
    tunnels = [o for o in observed if is_overlay(o, v4_min=host_v4_min, v6_min=host_v6_min)]
    rest = [o for o in observed if not is_overlay(o, v4_min=host_v4_min, v6_min=host_v6_min)]
    hosts = [o for o in rest if is_host(o, v4_min=host_v4_min, v6_min=host_v6_min)]
    normal = [o for o in rest if not is_host(o, v4_min=host_v4_min, v6_min=host_v6_min)]

    # 2) Attribute remaining observations:
    #    - contains 2+ sites' blocks  → shared SUPERNET (org /48), a container
    #    - site code match            → that site
    #    - inside a site block        → that site (member)
    #    - supernet of exactly 1 site → that site (the /48-vs-/56 mismatch)
    #    - matches a shared container → covered (STIP /48, accepted overlay)
    #    - else                       → unattributed
    per_site_obs: dict[int, list[Observed]] = defaultdict(list)
    unattributed: list[Observed] = []
    container_seen: set = set()
    supernets: dict[str, dict] = {}
    for o in normal:
        containing = {
            s["id"] for s in sites
            if any(ipam_net.contains(o.cidr, p["cidr"])
                   for p in site_prefixes.get(s["id"], []))
        }
        if len(containing) >= 2:                        # spans multiple sites → shared
            e = supernets.setdefault(o.cidr, {"cidr": o.cidr, "family": o.family,
                                              "sites": set(), "sources": set(), "label": ""})
            e["sites"].update(sites_by_id[i]["site_code"] for i in containing)
            e["sources"].add(o.source)
            e["label"] = e["label"] or o.label
            continue

        sid = None
        if o.site_code and o.site_code in code_to_site:
            sid = code_to_site[o.site_code]["id"]
        if sid is None:                                 # obs inside a site block (member)
            for s in sites:
                if any(ipam_net.contains(p["cidr"], o.cidr)
                       for p in site_prefixes.get(s["id"], [])):
                    sid = s["id"]
                    break
        if sid is None and len(containing) == 1:        # supernet of exactly one site
            sid = next(iter(containing))
        if sid is not None:
            per_site_obs[sid].append(o)
            continue
        cont = next((c for c in containers if _confirms(c["cidr"], o.cidr)), None)
        if cont:
            container_seen.add(cont["id"])              # covered by shared infra
        else:
            unattributed.append(o)

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
                           iface_type=o.iface_type, vlan=o.vlan,
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
        t = o.iface_type or "host"
        if t == "tunnel":
            t = "p2p"   # a host-length tunnel is a point-to-point link, not an overlay
        host_by_type[t] += 1
        host_items.append({"cidr": o.cidr, "family": o.family, "iface_type": t,
                           "sources": [o.source], "site_code": o.site_code,
                           "label": o.label})
    host_items.sort(key=lambda x: (x["family"], x["cidr"]))

    # Shared supernets — observed prefixes that span 2+ sites' blocks (org /48s).
    shared_supernets = [{
        "cidr": e["cidr"], "family": e["family"],
        "sites": sorted(e["sites"]), "site_count": len(e["sites"]),
        "sources": sorted(e["sources"]), "label": e["label"],
        "in_registry": e["cidr"] in registry_cidrs,
        "suggested_role": "supernet",
    } for e in sorted(supernets.values(), key=lambda x: x["cidr"])]

    # Shared containers (STIP /48 etc.) — credited as in-sync when the live
    # network was seen inside them. DMVPN overlays are reported separately.
    container_findings: list[dict] = []
    containers_in_sync = 0
    for c in containers:
        if c.get("role") == "dmvpn":
            continue
        state = "in-sync" if c["id"] in container_seen else "registry-only"
        if state == "in-sync":
            containers_in_sync += 1
        container_findings.append({"prefix": c, "state": state})

    # New-site candidates vs. truly loose unattributed.
    new_site_candidates: dict[str, list[dict]] = defaultdict(list)
    loose: list[dict] = []
    for o in unattributed:
        rec = {"cidr": o.cidr, "family": o.family, "sources": [o.source],
               "label": o.label, "site_code": o.site_code, "vlan_id": o.vlan,
               "suggested_role": _suggest_role(o.iface_type, o.family)}
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
            "shared_supernets": len(shared_supernets),
            "host_routes": len(host_items),
            "containers_total": len(container_findings),
            "containers_in_sync": containers_in_sync,
            "unattributed": len(loose),
            "new_site_candidates": len(new_site_candidates),
        },
        "sites": site_reports,
        "shared_supernets": shared_supernets,
        "containers": container_findings,
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
