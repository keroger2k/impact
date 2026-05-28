"""utils/ip_audit.py — Reconcile the IP registry against the live network.

The registry (``clients.ip_registry``) is *intent* — what TSA says each site
should own. This module gathers what's actually **observed** on the network
from the platform caches and classifies the difference, four ways, per site:

    in-sync        registry prefix confirmed by at least one live source
    registry-only  documented but not seen anywhere (stale, or — for IPv6 —
                   simply not deployed yet)
    network-only   seen on the network but undocumented (the big win: shadow
                   subnets you can bulk-accept into the registry)
    mismatch       a network prefix overlaps a registry prefix without nesting
                   cleanly (e.g. registry /24 vs a live /23)

It is **cache-only** — it reads whatever the platform warmers have already
populated (IPAM tree, DNAC interfaces/pools, Nexus interfaces, Panorama
interfaces/address-objects, cached ACI BD/EPG subnets) and makes no live API
calls, so it's fast and side-effect free. Warm the caches first for full
coverage. Supersedes the IPv6-only ``utils.ipv6_audit``.

Source extractors are intentionally defensive: an unexpected/empty cache shape
yields nothing rather than raising. The classification core (``reconcile``) is
a pure function over plain lists and is unit-tested without any cache.
"""
from __future__ import annotations

import datetime as _dt
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from cache import IPAM_TREE_CACHE_KEY
from utils import ipam_net
from utils.site_code import site_code_from_hostname, site_code_strict

logger = logging.getLogger(__name__)

ALL_SOURCES = ("dnac", "nexus", "panorama", "aci")


@dataclass
class Observed:
    """One concrete network seen on the live network."""
    cidr: str
    family: int
    source: str            # dnac | nexus | panorama | aci
    site_code: str = ""    # best-effort attribution ("" when unknown)
    label: str = ""        # device / interface / object name for context


def _canon(value: Optional[str]) -> Optional[tuple[int, str]]:
    """(family, canonical_cidr) or None for v6 pseudo-labels / junk / blanks."""
    if not value or "/" not in value:
        # Bare host with no mask is still valid (ip_network → /32 or /128) but
        # the tree/pseudo-labels ("Host Routes (X)") must be rejected.
        if not value or ":" not in value and "." not in value:
            return None
    try:
        fam, _, _, canon = ipam_net.canonical(value)
        return fam, canon
    except (ValueError, TypeError):
        return None


# ── Source extractors ──────────────────────────────────────────────────────────

def _from_ipam_tree(cache) -> list[Observed]:
    """Walk the aggregated IPAM tree — its nodes already carry a ``site`` path
    and cover both families, summaries and leaf subnets."""
    tree = cache.get(IPAM_TREE_CACHE_KEY)
    if not tree:
        return []
    out: list[Observed] = []

    def walk(nodes: Iterable[dict]):
        for n in nodes or []:
            c = _canon(n.get("cidr"))
            if c:
                fam, canon = c
                out.append(Observed(
                    cidr=canon, family=fam, source="dnac",
                    site_code=site_code_strict(n.get("site") or "").upper(),
                    label=n.get("display_name") or n.get("source") or "",
                ))
            walk(n.get("children"))

    walk(tree.get("ipv4"))
    walk(tree.get("ipv6"))
    return out


def _from_dnac_interfaces(cache) -> list[Observed]:
    """Raw DNAC SVIs/interfaces — used when the IPAM tree hasn't been built."""
    ifaces = cache.get("dnac_interfaces") or []
    sitemap = cache.get("device_site_map") or {}
    out: list[Observed] = []
    for i in ifaces:
        addr, mask = i.get("ipv4Address"), i.get("ipv4Mask")
        if not addr or not mask:
            continue
        c = _canon(f"{addr}/{mask}")
        if not c:
            continue
        fam, canon = c
        code = site_code_strict(sitemap.get(i.get("deviceId"), "") or "").upper()
        out.append(Observed(cidr=canon, family=fam, source="dnac", site_code=code,
                            label=i.get("deviceName") or i.get("portName") or ""))
    return out


def _from_dnac_pools(cache) -> list[Observed]:
    """DNAC global pools (enterprise-wide → unattributed) + per-site reserve
    subpools (attributed by site name)."""
    out: list[Observed] = []
    for p in cache.get("dnac_global_pools") or []:
        c = _canon(p.get("ipPoolCidr") or p.get("cidr"))
        if c:
            out.append(Observed(cidr=c[1], family=c[0], source="dnac",
                                label=p.get("ipPoolName") or "global-pool"))
    for sp in cache.get("dnac_reserve_subpools") or []:
        code = site_code_strict(sp.get("siteName") or sp.get("groupName") or "").upper()
        for ip in (sp.get("ipPools") or []):
            c = _canon(ip.get("ipPoolCidr") or ip.get("cidr"))
            if c:
                out.append(Observed(cidr=c[1], family=c[0], source="dnac",
                                    site_code=code,
                                    label=ip.get("ipPoolName") or "reserve-pool"))
    return out


def _from_nexus(cache) -> list[Observed]:
    """Nexus interface SVIs; ``ipv4_address`` is already a CIDR; attribute by
    hostname."""
    out: list[Observed] = []
    for i in cache.get("nexus_interfaces") or []:
        c = _canon(i.get("ipv4_address"))
        if not c:
            continue
        out.append(Observed(
            cidr=c[1], family=c[0], source="nexus",
            site_code=site_code_from_hostname(i.get("hostname") or "").upper(),
            label=f"{i.get('hostname','')} {i.get('interface_name','')}".strip()))
    return out


def _from_panorama(cache) -> list[Observed]:
    """Palo interfaces (per-device interface lists with ``ipv4`` CIDRs) plus
    ip-netmask address objects."""
    out: list[Observed] = []
    for dev in cache.get("pan_interfaces") or []:
        host = dev.get("hostname") or ""
        code = site_code_from_hostname(host).upper()
        for iface in (dev.get("interfaces") or []):
            c = _canon(iface.get("ipv4"))
            if c:
                out.append(Observed(cidr=c[1], family=c[0], source="panorama",
                                    site_code=code,
                                    label=f"{host} {iface.get('name','')}".strip()))
    for obj in cache.get("pan_address_objects") or []:
        if obj.get("type") != "ip-netmask":
            continue
        c = _canon(obj.get("value"))
        if c:
            out.append(Observed(cidr=c[1], family=c[0], source="panorama",
                                site_code=site_code_strict(obj.get("name") or "").upper(),
                                label=obj.get("name") or "addr-object"))
    return out


def _from_aci(cache) -> list[Observed]:
    """ACI BD/EPG subnets from whatever per-fabric data is cached. Datacenter
    fabrics rarely carry a site code, so these attribute by containment only
    (site_code left blank). Tolerant of both the imdata and BD-list shapes."""
    keys_for_prefix = getattr(cache, "keys_for_prefix", None)
    if not callable(keys_for_prefix):
        return []
    out: list[Observed] = []

    def add(ip: Optional[str], label: str):
        c = _canon(ip)
        if c:
            out.append(Observed(cidr=c[1], family=c[0], source="aci", label=label))

    try:
        keys = list(keys_for_prefix("aci_"))
    except Exception:  # pragma: no cover - cache backend variance
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
    "dnac": lambda cache: (_from_ipam_tree(cache) or _from_dnac_interfaces(cache)) + _from_dnac_pools(cache),
    "nexus": _from_nexus,
    "panorama": _from_panorama,
    "aci": _from_aci,
}


def collect_observed(cache, sources: Iterable[str] = ALL_SOURCES) -> list[Observed]:
    """Run the enabled source extractors and de-duplicate by (cidr, source,
    site_code), preferring an attributed copy over an unattributed one."""
    raw: list[Observed] = []
    for name in sources:
        fn = _EXTRACTORS.get(name)
        if not fn:
            continue
        try:
            raw.extend(fn(cache))
        except Exception:  # pragma: no cover - defensive against cache shape drift
            logger.exception("ip_audit: source %r extractor failed", name)
    best: dict[tuple[str, str], Observed] = {}
    for o in raw:
        k = (o.cidr, o.source)
        if k not in best or (not best[k].site_code and o.site_code):
            best[k] = o
    return list(best.values())


# ── Classification core (pure) ──────────────────────────────────────────────────

def _same(a: str, b: str) -> bool:
    try:
        return ipam_net.canonical(a)[3] == ipam_net.canonical(b)[3]
    except ValueError:
        return False


def _confirms(reg_cidr: str, obs_cidr: str) -> bool:
    """An observation confirms a registry prefix when they're equal, the
    observation sits inside it (a member subnet), or it sits inside the
    observation (a summary that covers it)."""
    return (_same(reg_cidr, obs_cidr)
            or ipam_net.contains(reg_cidr, obs_cidr)
            or ipam_net.contains(obs_cidr, reg_cidr))


@dataclass
class _Drift:
    cidr: str
    family: int
    site_id: Optional[int]
    site_code: str
    kind: str                       # network-only | mismatch
    sources: set = field(default_factory=set)
    related: list = field(default_factory=list)
    label: str = ""

    def as_dict(self) -> dict:
        return {"cidr": self.cidr, "family": self.family, "site_id": self.site_id,
                "site_code": self.site_code, "kind": self.kind,
                "sources": sorted(self.sources), "related": self.related,
                "label": self.label,
                # suggested role for one-click accept
                "suggested_role": "site-aggregate" if self.family == 4 else "subnet"}


def reconcile(sites: list[dict], prefixes: list[dict],
              observed: list[Observed], *,
              sources: Iterable[str] = ALL_SOURCES) -> dict:
    """Pure classifier. ``sites`` / ``prefixes`` are registry rows;
    ``observed`` is the collected live view. Returns a JSON-able report."""
    code_to_site = {(s["site_code"] or "").upper(): s for s in sites if s.get("site_code")}
    site_prefixes: dict[int, list[dict]] = defaultdict(list)
    for p in prefixes:
        if p.get("site_id") is not None:        # skip shared containers
            site_prefixes[p["site_id"]].append(p)

    # Attribute each observation to a site: by site code, else by containment
    # within one of a site's registry prefixes.
    per_site_obs: dict[int, list[Observed]] = defaultdict(list)
    unattributed: list[Observed] = []
    for o in observed:
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
                continue                                   # already counted in-sync
            if any(ipam_net.contains(p["cidr"], o.cidr) for p in regp):
                continue                                   # member of an aggregate — not drift
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
                "site": s,
                "findings": findings,
                "drift": drift,
                "counts": {
                    "in_sync": sum(1 for f in findings if f["state"] == "in-sync"),
                    "registry_only": sum(1 for f in findings if f["state"] == "registry-only"),
                    "network_only": sum(1 for d in drift if d["kind"] == "network-only"),
                    "mismatch": sum(1 for d in drift if d["kind"] == "mismatch"),
                },
            })

    # Unattributed observations: group by detected site code (new-site
    # candidates) vs. truly loose.
    new_site_candidates: dict[str, list[dict]] = defaultdict(list)
    loose: list[dict] = []
    for o in unattributed:
        rec = {"cidr": o.cidr, "family": o.family, "sources": [o.source],
               "label": o.label, "site_code": o.site_code,
               "suggested_role": "site-aggregate" if o.family == 4 else "subnet"}
        if o.site_code:
            new_site_candidates[o.site_code].append(rec)
        else:
            loose.append(rec)

    return {
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "sources": list(sources),
        "summary": {
            "sites_reported": len(site_reports),
            "observed_total": len(observed),
            **totals,
            "unattributed": len(loose),
            "new_site_candidates": len(new_site_candidates),
        },
        "sites": site_reports,
        "new_site_candidates": [
            {"site_code": code, "prefixes": recs}
            for code, recs in sorted(new_site_candidates.items())
        ],
        "unattributed": loose,
    }


def run_audit(cache, sites: list[dict], prefixes: list[dict], *,
              sources: Iterable[str] = ALL_SOURCES) -> dict:
    """Convenience: collect from the cache, then reconcile."""
    observed = collect_observed(cache, sources)
    return reconcile(sites, prefixes, observed, sources=sources)
