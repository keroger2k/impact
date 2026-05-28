"""utils/ipam_net.py — Family-agnostic CIDR helpers for the IP registry.

Pure functions over the stdlib ``ipaddress`` module, working uniformly on
IPv4 and IPv6. The dual-stack registry (``clients.ip_registry``) and the
audit engine (``utils.ip_audit``) both build on these so canonicalization
and containment math live in exactly one place.

Nothing here touches the DB, the cache, or HTTP. ``parse_network`` raises
``ValueError`` on unparseable input — callers decide how to surface it.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_network(value: str) -> IPNetwork:
    """Parse a CIDR / bare-address / address+netmask string into a network.

    ``strict=False`` so host bits are masked off rather than rejected
    (``10.0.0.5/24`` → ``10.0.0.0/24``). Accepts IPv4 netmask form too
    (``10.0.0.0/255.255.255.0``). Raises ``ValueError`` on bad input.
    """
    return ipaddress.ip_network(value.strip(), strict=False)


def family_of(net: IPNetwork) -> int:
    """4 or 6."""
    return 4 if net.version == 4 else 6


def canonical(value: str) -> tuple[int, str, int, str]:
    """Normalize a network string into ``(family, network, prefix_length, cidr)``.

    ``network`` is the masked network address, ``cidr`` is ``network/len`` in
    the library's canonical (compressed, lowercase) form. This is the single
    normalization point used before anything is written to the registry.
    """
    net = parse_network(value)
    network = str(net.network_address)
    return family_of(net), network, net.prefixlen, f"{network}/{net.prefixlen}"


def overlaps(a: str, b: str) -> bool:
    """True if two networks of the same family share any address. Cross-family
    pairs never overlap (and never raise)."""
    na, nb = parse_network(a), parse_network(b)
    return na.version == nb.version and na.overlaps(nb)


def contains(outer: str, inner: str) -> bool:
    """True if ``inner`` is a subnet of (or equal to) ``outer``, same family."""
    no, ni = parse_network(outer), parse_network(inner)
    return no.version == ni.version and ni.subnet_of(no)


def find_overlaps(cidr: str, rows: Iterable[dict], *,
                  key: str = "cidr", exclude_id: Optional[int] = None) -> list[dict]:
    """Return rows whose ``row[key]`` network overlaps ``cidr`` (same family).
    Rows with a missing / unparseable value at ``key`` are skipped."""
    target = parse_network(cidr)
    hits: list[dict] = []
    for r in rows:
        if exclude_id is not None and r.get("id") == exclude_id:
            continue
        raw = r.get(key)
        if not raw:
            continue
        try:
            n = parse_network(raw)
        except ValueError:
            continue
        if n.version == target.version and n.overlaps(target):
            hits.append(r)
    return hits


def find_container(cidr: str, rows: Iterable[dict], *, key: str = "cidr") -> Optional[dict]:
    """Return the most-specific row whose network strictly contains ``cidr``
    (longest-prefix match). ``None`` if nothing contains it."""
    target = parse_network(cidr)
    best: Optional[tuple[int, dict]] = None
    for r in rows:
        raw = r.get(key)
        if not raw:
            continue
        try:
            n = parse_network(raw)
        except ValueError:
            continue
        if n.version != target.version:
            continue
        if target.subnet_of(n) and (best is None or n.prefixlen > best[0]):
            best = (n.prefixlen, r)
    return best[1] if best else None


def smallest_covering(cidrs: Iterable[str]) -> Optional[str]:
    """Smallest single CIDR containing every input network. All inputs must be
    the same family; mixed families or an empty iterable → ``None``.

    Used as a heuristic rollup when no configured summary covers a set of
    member subnets (mirrors the old IPv4-only helper in
    ``scripts/discover_site_ipv4.py``, generalized to both families)."""
    nets = [parse_network(c) for c in cidrs]
    if not nets:
        return None
    versions = {n.version for n in nets}
    if len(versions) != 1:
        return None
    bits = 32 if nets[0].version == 4 else 128
    cls = ipaddress.IPv4Network if nets[0].version == 4 else ipaddress.IPv6Network
    lo = min(int(n.network_address) for n in nets)
    hi = max(int(n.broadcast_address) for n in nets)
    if lo == hi:
        return str(cls((lo, bits)))
    prefix = bits - (lo ^ hi).bit_length()
    base = lo & (((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1))
    return str(cls((base, prefix)))
