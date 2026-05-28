#!/usr/bin/env python3
"""scripts/discover_site_ipv4.py — Discover each IPv6 registry site's IPv4 supernet.

For every site in the IPv6 registry, this reads the **IPAM dashboard tree**
(the same hierarchy rendered at `/ipam`, cached under `IPAM_TREE_CACHE_KEY`)
and reports the real summary/aggregate the site's subnets roll up into, so the
`sites.ipv4_supernet` column can be populated.

Why the tree and not raw interface IPs:
  The previous version computed the *smallest CIDR covering every interface
  IP* it found for a site. Because a site's addressing is scattered (mgmt in
  one /24, loopbacks elsewhere, SVIs in another block) the covering network
  ballooned to 10.0.0.0/8 or /9 — useless. The IPAM engine already solves
  this: it parses configured **EIGRP `summary-address`, OSPF area ranges, BGP
  `aggregate-address`, static `… Null0` summaries, and DNAC reserve subpools**
  into aggregate nodes, then nests each interface subnet under the most
  specific one. Those aggregates ARE the site summaries. We just have to read
  them back out.

Algorithm, per registry site (matched to DNAC by site code via
`utils.site_code.site_code_strict`, with a site-name substring fallback):
  1. Find the site's **member subnets** — leaf nodes in the IPAM tree whose
     site-hierarchy path resolves to this site.
  2. Find **candidate summaries** — real aggregate nodes (source `DNAC-Config`
     or `DNAC-Pool`, excluding the enterprise-wide global pools) that are
     either attributed to this site OR contain one of its member subnets.
  3. Reduce to the maximal disjoint set (drop a summary nested inside a
     broader one) — that maximal set is "the summary address(es) the site fits
     into."
  4. Any member not covered by a real summary is rolled up into a single
     heuristic covering CIDR, reported separately. If a site has *no* real
     summary at all, that heuristic covering becomes the suggestion (old
     behavior, clearly labeled).

`sites.ipv4_supernet` accepts a comma-separated list (see
`routers/ipv6_registry._parse_ipv4_supernet`), so a site with several disjoint
summaries is stored as e.g. `1.2.0.0/16, 5.6.7.0/24`.

Dry-run by default; `--apply` writes the suggestion to `sites.ipv4_supernet`
(only when the column is empty — won't overwrite an operator-set value unless
`--force`).

Requires the **IPAM tree to be built**: run the app and trigger an IPAM
refresh (`/ipam` → Refresh, or POST `/api/ipam/refresh`) first. For the
configured summaries to appear, the refresh must include the `dnac_summaries`
source (it's in the default ALL set). The script never makes live API calls.

Run from the repo root:

    .venv/bin/python -m scripts.discover_site_ipv4              # dry-run
    .venv/bin/python -m scripts.discover_site_ipv4 --apply      # commit suggestions
    .venv/bin/python -m scripts.discover_site_ipv4 --apply --force  # overwrite existing
    .venv/bin/python -m scripts.discover_site_ipv4 --site K024      # one site only
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterator, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cache import cache as app_cache, IPAM_TREE_CACHE_KEY  # noqa: E402
from clients import ipv6_registry as registry  # noqa: E402
from utils.site_code import site_code_strict  # noqa: E402

# Aggregate-node sources we trust as real, configured summaries. The IPAM
# engine tags EIGRP/OSPF/BGP/static summaries as "DNAC-Config" and DNAC IP
# pools as "DNAC-Pool". Synthesized RFC1918 / IPv6 roots are tagged
# "Aggregate" and are deliberately NOT here — they're /8-/12 placeholders, not
# site summaries.
REAL_SUMMARY_SOURCES = {"DNAC-Config", "DNAC-Pool"}

# IPAM tree roles that mark a node as an aggregate/summary container rather
# than a leaf subnet.
SUMMARY_ROLES = {"aggregate", "supernet"}

# Interface types whose subnets we drop from the *heuristic covering-CIDR*
# fallback (they scatter and bloat the covering network). They're still fine
# as members for containment-matching against real summaries.
NOISE_IFACE_TYPES = {"loopback", "p2p", "management"}


class TreeNode:
    """A flattened IPAM tree node we care about (parseable IPv4 only)."""

    __slots__ = ("net", "source", "site", "code", "role", "display_name",
                 "logical_container", "device", "interface_type")

    def __init__(self, net: ipaddress.IPv4Network, raw: dict):
        self.net = net
        self.source = raw.get("source") or ""
        self.site = raw.get("site") or ""
        self.code = site_code_strict(self.site).upper()
        self.role = raw.get("role") or ""
        self.display_name = raw.get("display_name") or ""
        self.logical_container = raw.get("logical_container") or ""
        self.device = raw.get("device") or ""
        self.interface_type = raw.get("interface_type") or ""

    @property
    def is_summary(self) -> bool:
        return self.role in SUMMARY_ROLES

    @property
    def is_real_summary(self) -> bool:
        """A configured summary or per-site pool — but NOT a DNAC global pool
        (those are the 10.0.0.0/8-style enterprise roots that caused the
        original /8 suggestions)."""
        if not self.is_summary or self.source not in REAL_SUMMARY_SOURCES:
            return False
        if self.logical_container == "global-pool":
            return False
        if self.display_name.startswith("Global Pool"):
            return False
        # site="Global" is the global-pool sentinel set by the IPAM engine.
        if self.site == "Global":
            return False
        return True

    @property
    def is_noise(self) -> bool:
        return (
            self.interface_type in NOISE_IFACE_TYPES
            or self.net.prefixlen >= 30
        )


def _parse_v4(cidr: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Parse a tree-node cidr into an IPv4Network. None for v6, pseudo-node
    labels ('Host Routes (…)', 'Loopbacks (n)'), or anything unparseable."""
    if not cidr or ":" in cidr or "/" not in cidr:
        return None
    try:
        return ipaddress.IPv4Network(cidr, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def _flatten_tree(nodes: list[dict]) -> Iterator[TreeNode]:
    """Yield every IPv4 TreeNode in the tree, depth-first."""
    for raw in nodes:
        net = _parse_v4(raw.get("cidr"))
        if net is not None:
            yield TreeNode(net, raw)
        children = raw.get("children") or []
        if children:
            yield from _flatten_tree(children)


def _smallest_covering_cidr(
    networks: list[ipaddress.IPv4Network],
) -> Optional[ipaddress.IPv4Network]:
    """Return the smallest IPv4Network containing every input network.

    Used only for the heuristic fallback when no real summary is found."""
    if not networks:
        return None
    lo = min(int(n.network_address) for n in networks)
    hi = max(int(n.broadcast_address) for n in networks)
    if lo == hi:
        return ipaddress.IPv4Network((lo, 32))
    diff = lo ^ hi
    prefix = 32 - diff.bit_length()
    base = lo & (((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1))
    return ipaddress.IPv4Network((base, prefix))


def _reduce_to_maximal(
    summaries: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Drop any summary that is a subnet of another summary in the set, so the
    result is the minimal set of broadest containers (e.g. keep 10.4.0.0/16,
    drop the 10.4.30.0/24 pool nested inside it)."""
    uniq = sorted(set(summaries), key=lambda n: (n.prefixlen, int(n.network_address)))
    kept: list[ipaddress.IPv4Network] = []
    for n in uniq:
        if any(n != k and n.subnet_of(k) for k in uniq):
            continue
        kept.append(n)
    return sorted(kept, key=lambda n: int(n.network_address))


def _matches_site(node: TreeNode, code: str, name_lc: str) -> bool:
    """True if a tree node is attributed to this registry site, by site code
    (preferred) or site-name substring (fallback)."""
    if code and node.code == code:
        return True
    if name_lc and node.site and name_lc in node.site.lower():
        return True
    return False


def _format_member_breakdown(members: list[TreeNode], *, limit: int = 5) -> str:
    """Roll dozens of member subnets up into one line per /24 so the printout
    stays tight."""
    if not members:
        return "    member subnets: (none matched in IPAM tree)"
    by_24: dict[str, list[ipaddress.IPv4Network]] = defaultdict(list)
    for m in members:
        if m.net.prefixlen >= 24:
            key = str(ipaddress.IPv4Network((int(m.net.network_address) & 0xFFFFFF00, 24)))
        else:
            key = str(m.net)
        by_24[key].append(m.net)
    lines = [f"    member subnets: {len(members)} across {len(by_24)} /24(s)"]
    for slot, nets in sorted(by_24.items())[:limit]:
        examples = ", ".join(str(n) for n in nets[:3])
        more = f" (+{len(nets) - 3} more)" if len(nets) > 3 else ""
        lines.append(f"      • {slot}  ← {examples}{more}")
    if len(by_24) > limit:
        lines.append(f"      … and {len(by_24) - limit} more /24(s)")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true",
                    help="Write the suggestion to sites with no existing value")
    ap.add_argument("--force", action="store_true",
                    help="With --apply: overwrite even when ipv4_supernet is already set")
    ap.add_argument("--site", default=None,
                    help="Limit to the registry site whose name contains this string (case-insensitive)")
    args = ap.parse_args()

    tree = app_cache.get(IPAM_TREE_CACHE_KEY)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] reading IPAM tree from cache key '{IPAM_TREE_CACHE_KEY}'")

    if not tree or not tree.get("ipv4"):
        print("\nERROR: IPAM tree is empty. Build it first: run the app and trigger")
        print("       an IPAM refresh (/ipam → Refresh, or POST /api/ipam/refresh)")
        print("       with the default ALL sources so configured summaries are parsed.",
              file=sys.stderr)
        return 1

    all_nodes = list(_flatten_tree(tree["ipv4"]))
    real_summaries = [n for n in all_nodes if n.is_real_summary]
    # Leaf members = everything that isn't itself an aggregate/supernet.
    member_nodes = [n for n in all_nodes if not n.is_summary]

    print(f"        tree: {len(all_nodes)} IPv4 nodes "
          f"({len(real_summaries)} real summaries, {len(member_nodes)} member subnets)")
    if not real_summaries:
        print("        WARNING: no configured-summary or per-site-pool nodes in the tree.")
        print("        Did the IPAM refresh include the 'dnac_summaries' + 'dnac_pools' sources?")
        print("        Without them every site falls back to a heuristic covering CIDR.")

    registry.init_schema()
    sites = registry.list_sites()
    if args.site:
        needle = args.site.lower()
        sites = [s for s in sites if needle in (s["name"] or "").lower()]
        if not sites:
            print(f"\nNo registry site matched --site '{args.site}'.", file=sys.stderr)
            return 1
    print(f"        scanning {len(sites)} registry site(s)\n")

    stats = {
        "would_update": 0,
        "updated": 0,
        "from_summaries": 0,
        "from_heuristic": 0,
        "skipped_no_match": 0,
        "skipped_existing": 0,
    }

    for site in sites:
        name = site["name"]
        code = site_code_strict(name).upper()
        name_lc = name.lower()
        existing = site.get("ipv4_supernet") or ""
        print(f"── {name}  ({site['prefix']}::/{site['prefix_length']})  "
              f"code={code or '(none)'}  existing={existing or '(empty)'}")

        members = [n for n in member_nodes if _matches_site(n, code, name_lc)]

        # Candidate summaries: real summaries attributed to this site OR that
        # contain at least one of the site's member subnets.
        claimed = {
            str(s.net): s for s in real_summaries if _matches_site(s, code, name_lc)
        }
        containing: dict[str, TreeNode] = {}
        for s in real_summaries:
            if str(s.net) in claimed:
                continue
            if any(m.net.subnet_of(s.net) for m in members):
                containing[str(s.net)] = s

        candidate_nodes = {**claimed, **containing}
        candidate_nets = [s.net for s in candidate_nodes.values()]
        summaries = _reduce_to_maximal(candidate_nets)

        print(_format_member_breakdown(members))

        if candidate_nodes:
            shown = sorted(candidate_nodes.values(), key=lambda s: int(s.net.network_address))
            print(f"    real summaries ({len(shown)}):")
            for s in shown[:8]:
                covered = sum(1 for m in members if m.net.subnet_of(s.net))
                tag = "claimed" if str(s.net) in claimed else "contains-member"
                kept = "✓kept" if s.net in summaries else "·nested"
                print(f"      • {str(s.net):<20} {kept:<8} {tag:<16} "
                      f"covers {covered} member(s)  [{s.source}] {s.display_name}")
            if len(shown) > 8:
                print(f"      … and {len(shown) - 8} more")
        else:
            print("    real summaries: (none — no configured summary/pool matched)")

        # Members not covered by any kept real summary → heuristic rollup.
        uncovered = [
            m for m in members
            if not m.is_noise and not any(m.net.subnet_of(s) for s in summaries)
        ]
        heuristic = _smallest_covering_cidr([m.net for m in uncovered]) if uncovered else None

        if summaries:
            suggestion_nets = list(summaries)
            origin = "summaries"
            if heuristic:
                print(f"    uncovered:     {len(uncovered)} member(s) not under any summary "
                      f"→ heuristic {heuristic} (NOT written; review separately)")
        elif heuristic:
            # No real summary at all — fall back to the old covering-CIDR behavior.
            suggestion_nets = [heuristic]
            origin = "heuristic"
        else:
            suggestion_nets = []
            origin = None

        if not suggestion_nets:
            print("    SUGGESTION:    (no IPv4 found — nothing to apply)\n")
            stats["skipped_no_match"] += 1
            continue

        suggestion = ", ".join(str(n) for n in suggestion_nets)
        label = "configured summary" if origin == "summaries" else "HEURISTIC covering CIDR"
        print(f"    SUGGESTION:    {suggestion}   ({label})")

        if not args.apply:
            print()
            stats["would_update"] += 1
            stats["from_summaries" if origin == "summaries" else "from_heuristic"] += 1
            continue

        if existing and not args.force:
            print("    SKIP-EXISTS    site already has ipv4_supernet — pass --force to overwrite\n")
            stats["skipped_existing"] += 1
            continue

        registry.update_site(site["id"], ipv4_supernet=suggestion)
        print(f"    UPDATED        sites.ipv4_supernet = {suggestion}\n")
        stats["updated"] += 1
        stats["from_summaries" if origin == "summaries" else "from_heuristic"] += 1

    print(f"[{mode}] summary:")
    for k, v in stats.items():
        if v:
            print(f"  {k:<18} {v}")
    if not args.apply:
        print("\nDry-run complete. Re-run with --apply to write suggestions "
              "into the registry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
