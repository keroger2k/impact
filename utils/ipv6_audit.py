"""utils/ipv6_audit.py — IPv6 Registry vs live-IPAM cross-check.

Compares the manually-curated IPv6 Registry (data/ipv6_registry.db) against
the live IPv6 addresses observed in the IPAM tree (cache["ipam_tree_v4"])
to surface three classes of drift:

  * coverage_gaps    — Registry sites whose prefix contains no live IPv6.
  * off_book         — live global-unicast IPv6 not contained by any
                       Registry prefix.
  * site_mismatches  — live IPv6 inside a Registry prefix, but the device's
                       DNAC site path resolves to a different site code than
                       the Registry site name's code (right prefix, wrong
                       site).

Pure functions only — no DB or cache I/O. Callers feed in `sites` and the
IPAM tree dict; `run_audit` returns a fully-formed report.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional, TypedDict

from utils.site_code import site_code

logger = logging.getLogger(__name__)

# 2000::/3 — IANA global unicast. Everything outside is link-local,
# loopback, multicast, ULA, etc. and isn't tracked by the Registry.
_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")

# Inferred/synthesized parent roles — they exist only to group real leaves
# in the IPAM tree, not as configured addresses. Counted toward matched
# sites (their presence proves coverage), but excluded from off-book and
# mismatch lists so we don't double-report alongside their children.
_INFERRED_ROLES = {"aggregate", "supernet"}


class LiveIPv6Record(TypedDict):
    cidr: str
    network: ipaddress.IPv6Network
    device: str
    site_path: str
    source: str
    interface_name: str
    display_name: str
    role: str


class GapRow(TypedDict):
    site_id: int
    name: str
    prefix: str
    prefix_length: int
    role: Optional[str]
    description: Optional[str]
    status: str


class OffBookRow(TypedDict):
    cidr: str
    device: str
    site_path: str
    source: str
    interface_name: str
    display_name: str


class ResurrectedRow(TypedDict):
    cidr: str
    device: str
    site_path: str
    source: str
    interface_name: str
    display_name: str
    registry_site_id: int
    registry_name: str
    registry_prefix: str


class MismatchRow(TypedDict):
    cidr: str
    device: str
    site_path: str
    device_code: str
    registry_site_id: int
    registry_name: str
    registry_prefix: str
    registry_code: str


class AuditCounts(TypedDict):
    coverage_gaps: int
    off_book: int
    site_mismatches: int
    resurrected: int
    decommissioned_sites: int
    planned_sites: int
    total_live_v6: int
    total_global_unicast: int
    total_registry_sites: int
    active_registry_sites: int


class AuditReport(TypedDict):
    coverage_gaps: list[GapRow]
    off_book: list[OffBookRow]
    site_mismatches: list[MismatchRow]
    resurrected: list[ResurrectedRow]
    decommissioned_sites: list[GapRow]
    planned_sites: list[GapRow]
    counts: AuditCounts
    generated_at: str


def flatten_ipv6_tree(tree: Optional[dict]) -> Iterator[LiveIPv6Record]:
    """Depth-first walk of `tree["ipv6"]`, yielding one record per node
    whose `cidr` parses as an IPv6 network. Nodes with unparseable CIDRs
    are skipped silently."""
    if not tree:
        return
    stack: list[dict] = list(tree.get("ipv6") or [])
    while stack:
        node = stack.pop()
        for child in node.get("children") or []:
            stack.append(child)
        cidr = node.get("cidr") or ""
        if not cidr:
            continue
        try:
            net = ipaddress.IPv6Network(cidr, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            continue
        yield LiveIPv6Record(
            cidr=cidr,
            network=net,
            device=node.get("device") or "",
            site_path=node.get("site") or "",
            source=node.get("source") or "",
            interface_name=node.get("interface_name") or "",
            display_name=node.get("display_name") or "",
            role=node.get("role") or "",
        )


def is_global_unicast(net: ipaddress.IPv6Network) -> bool:
    """True iff `net` is contained by 2000::/3."""
    return net.subnet_of(_GLOBAL_UNICAST)


def build_registry_index(
    sites: Iterable[dict],
) -> list[tuple[ipaddress.IPv6Network, dict]]:
    """Parse each Registry site's prefix into an IPv6Network. Sorted by
    prefixlen descending so the first containment hit during lookup is the
    longest match (handles overlapping /48 and /56 entries cleanly).

    Sites whose `prefix` doesn't parse are skipped with a warning."""
    index: list[tuple[ipaddress.IPv6Network, dict]] = []
    for site in sites:
        raw = site.get("prefix")
        length = site.get("prefix_length") or 48
        if not raw:
            continue
        # Registry stores prefixes as hextet-only strings (e.g. "2600:400:30e1")
        # so we have to attach "::/<len>" before parsing.
        candidate = raw if "/" in raw else f"{raw}::/{length}"
        try:
            net = ipaddress.IPv6Network(candidate, strict=False)
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.warning(
                "Registry site %s has unparseable prefix %r: %s",
                site.get("id"), raw, e,
            )
            continue
        index.append((net, site))
    index.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
    return index


def containing_site(
    net: ipaddress.IPv6Network,
    index: list[tuple[ipaddress.IPv6Network, dict]],
) -> Optional[dict]:
    """Return the most-specific Registry site whose prefix contains `net`,
    or None. Assumes `index` is already sorted by prefixlen descending."""
    for reg_net, site in index:
        if net.subnet_of(reg_net):
            return site
    return None


def _gap_row(site: dict) -> GapRow:
    return GapRow(
        site_id=site["id"],
        name=site["name"] or "",
        prefix=f"{site['prefix']}::/{site['prefix_length']}",
        prefix_length=site["prefix_length"],
        role=site.get("role"),
        description=site.get("description"),
        status=site.get("status") or "active",
    )


def run_audit(sites: list[dict], tree: Optional[dict]) -> AuditReport:
    """Execute all audit checks and return a fully-formed AuditReport.

    Bucketing logic:
      * Coverage gaps  — only active sites with no live IPv6 inside their prefix.
      * Decommissioned / Planned — sites in those statuses, listed separately
        so the user can see them at a glance without polluting the gaps list.
      * Resurrected    — live global-unicast IPv6 inside a decommissioned
        site's prefix (live where it isn't supposed to be).
      * Off-book / Mismatches — unchanged: outside every Registry prefix /
        in the wrong site's prefix.
    """
    index = build_registry_index(sites)
    matched_site_ids: set[int] = set()
    off_book: list[OffBookRow] = []
    site_mismatches: list[MismatchRow] = []
    resurrected: list[ResurrectedRow] = []

    total_live = 0
    total_global = 0

    for rec in flatten_ipv6_tree(tree):
        total_live += 1
        if not is_global_unicast(rec["network"]):
            continue
        total_global += 1
        site = containing_site(rec["network"], index)
        is_inferred = rec["role"] in _INFERRED_ROLES
        if site is None:
            if not is_inferred:
                off_book.append(OffBookRow(
                    cidr=rec["cidr"],
                    device=rec["device"],
                    site_path=rec["site_path"],
                    source=rec["source"],
                    interface_name=rec["interface_name"],
                    display_name=rec["display_name"],
                ))
            continue

        matched_site_ids.add(site["id"])
        if is_inferred:
            continue

        site_status = site.get("status") or "active"
        if site_status == "decommissioned":
            # The address is contained by a site that's supposed to be retired.
            # That's actionable — surface it as a "resurrected" entry rather
            # than counting it as healthy coverage or as off-book.
            resurrected.append(ResurrectedRow(
                cidr=rec["cidr"],
                device=rec["device"],
                site_path=rec["site_path"],
                source=rec["source"],
                interface_name=rec["interface_name"],
                display_name=rec["display_name"],
                registry_site_id=site["id"],
                registry_name=site["name"] or "",
                registry_prefix=f"{site['prefix']}::/{site['prefix_length']}",
            ))
            continue

        device_code = site_code(rec["site_path"])
        registry_code = site_code(site["name"] or "")
        # Only flag when both sides extracted a non-empty code AND they differ
        # — empty extraction on either side just means the regex didn't find
        # a recognizable code, not that the mapping is wrong.
        if device_code and registry_code and device_code != registry_code:
            site_mismatches.append(MismatchRow(
                cidr=rec["cidr"],
                device=rec["device"],
                site_path=rec["site_path"],
                device_code=device_code,
                registry_site_id=site["id"],
                registry_name=site["name"] or "",
                registry_prefix=f"{site['prefix']}::/{site['prefix_length']}",
                registry_code=registry_code,
            ))

    # Partition sites by status before building the gap list. Coverage gaps
    # only flag active sites — decommissioned and planned sites have their
    # own buckets so they don't drown the actionable list.
    active_sites = [s for s in sites if (s.get("status") or "active") == "active"]
    decommissioned_sites = [s for s in sites if s.get("status") == "decommissioned"]
    planned_sites = [s for s in sites if s.get("status") == "planned"]

    coverage_gaps = [_gap_row(s) for s in active_sites if s["id"] not in matched_site_ids]
    decommissioned_rows = [_gap_row(s) for s in decommissioned_sites]
    planned_rows = [_gap_row(s) for s in planned_sites]

    coverage_gaps.sort(key=lambda r: (r["name"] or "").lower())
    decommissioned_rows.sort(key=lambda r: (r["name"] or "").lower())
    planned_rows.sort(key=lambda r: (r["name"] or "").lower())
    off_book.sort(key=lambda r: r["cidr"])
    site_mismatches.sort(key=lambda r: (r["device"], r["cidr"]))
    resurrected.sort(key=lambda r: (r["registry_name"], r["cidr"]))

    return AuditReport(
        coverage_gaps=coverage_gaps,
        off_book=off_book,
        site_mismatches=site_mismatches,
        resurrected=resurrected,
        decommissioned_sites=decommissioned_rows,
        planned_sites=planned_rows,
        counts=AuditCounts(
            coverage_gaps=len(coverage_gaps),
            off_book=len(off_book),
            site_mismatches=len(site_mismatches),
            resurrected=len(resurrected),
            decommissioned_sites=len(decommissioned_rows),
            planned_sites=len(planned_rows),
            total_live_v6=total_live,
            total_global_unicast=total_global,
            total_registry_sites=len(sites),
            active_registry_sites=len(active_sites),
        ),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
