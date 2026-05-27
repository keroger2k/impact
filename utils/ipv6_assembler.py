"""utils/ipv6_assembler.py — Hierarchical IPv6 conversion math.

Pure functions, no DB or HTTP. The full address layout is:

    [ prefix_48 (48 bits) ] [ vvvv (16 bits) ] [ 0000:0000 (32 bits) ] [ ipv4 (32 bits) ]
       hextets 1..3            hextet 4              hextets 5..6              hextets 7..8

Example: site DC1 with /48 = 1000:2000:3000, vvvv = 0100, host = 1.2.3.4
         -> 1000:2000:3000:100::102:304

All addresses are canonicalized via the stdlib ipaddress module.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional


# ── Validation helpers ───────────────────────────────────────────────────────

def normalize_prefix_48(prefix_48: str) -> str:
    """Canonical compressed form of a /48 prefix as the leading 3 hextets only.
    Accepts loose input like '1000:2000:3000' or '0100:0200:0300'."""
    net = ipaddress.IPv6Network(f"{prefix_48.strip()}::/48", strict=False)
    full = net.network_address.exploded.split(":")  # 8 groups, padded
    # Drop the trailing zero groups, keep the first 3, normalize each hextet
    return ":".join(hextet.lstrip("0") or "0" for hextet in full[:3])


def normalize_vvvv(vvvv: str) -> str:
    """Canonical 4-hex-char lowercase representation. '134' -> '0134'."""
    s = vvvv.strip().lower().removeprefix("0x")
    if not s:
        raise ValueError("vvvv is empty")
    value = int(s, 16)
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"vvvv out of range: {vvvv}")
    return f"{value:04x}"


def validate_prefix_length(prefix_length: int) -> None:
    """vvvv-aligned allocations only live in /49..../64. Anything longer
    doesn't carve the vvvv hextet; anything shorter is the site itself."""
    if not 49 <= prefix_length <= 64:
        raise ValueError(
            f"prefix_length {prefix_length} unsupported; must be 49..64 "
            "(48 is the site itself; >64 lives below the vvvv segment)"
        )


def vvvv_block_size(prefix_length: int) -> int:
    """Number of consecutive vvvv values covered by an allocation of this length.

    /49 -> 0x8000, /50 -> 0x4000, ..., /56 -> 0x0100, ..., /64 -> 0x0001.
    """
    validate_prefix_length(prefix_length)
    return 1 << (64 - prefix_length)


# ── Forward: IPv4 -> IPv6 ────────────────────────────────────────────────────

def ipv4_to_suffix(ipv4: str) -> str:
    """'1.2.3.4' -> '102:304' (canonical compressed lowercase)."""
    v4 = ipaddress.IPv4Address(ipv4.strip())
    high = (int(v4) >> 16) & 0xFFFF
    low = int(v4) & 0xFFFF
    return f"{high:x}:{low:x}"


def assemble(prefix_48: str, vvvv: str, ipv4: str) -> ipaddress.IPv6Address:
    """Combine site /48 prefix, vvvv segment, zero hextets, and the IPv4
    host-tail into a fully-formed IPv6Address."""
    prefix_int = int(ipaddress.IPv6Address(f"{normalize_prefix_48(prefix_48)}::"))
    vvvv_int = int(normalize_vvvv(vvvv), 16)
    v4_int = int(ipaddress.IPv4Address(ipv4.strip()))

    addr_int = (
        (prefix_int & ((1 << 128) - (1 << 80)))   # top 48 bits from prefix
        | (vvvv_int << 64)                         # vvvv into bits 79..64
        | v4_int                                   # IPv4 into bottom 32
    )
    return ipaddress.IPv6Address(addr_int)


# ── Reverse: IPv6 -> (site, vvvv, IPv4) ──────────────────────────────────────

@dataclass
class DecodeResult:
    site_id: Optional[int]
    site_name: Optional[str]
    site_prefix_48: Optional[str]
    vvvv: str
    ipv4: str
    warnings: list[str]
    canonical: str  # canonical compressed form of the input address


def decode(ipv6: str, sites: Iterable[dict]) -> DecodeResult:
    """Reverse direction. Always reports the site because IPv4 alone is
    ambiguous across sites.

    `sites` is an iterable of dicts with at least `id`, `name`, `prefix_48`
    (typically rows from clients.ipv6_registry.list_sites())."""
    addr = ipaddress.IPv6Address(ipv6.strip())
    addr_int = int(addr)

    # Hextets 4 and 5 (bits 47..16) must be zero for a well-formed entry
    warnings: list[str] = []
    mid = (addr_int >> 32) & 0xFFFFFFFF
    if mid != 0:
        warnings.append(
            f"Hextets 5-6 are non-zero (0x{mid:08x}); address does not follow "
            "the standard scheme — host-tail recovery may be unreliable"
        )

    prefix_int = (addr_int >> 80) << 80
    candidate_prefix = ipaddress.IPv6Address(prefix_int).exploded.split(":")[:3]
    candidate_prefix_norm = ":".join(h.lstrip("0") or "0" for h in candidate_prefix)

    site_id = site_name = site_prefix_48 = None
    for s in sites:
        try:
            if normalize_prefix_48(s["prefix_48"]) == candidate_prefix_norm:
                site_id = s.get("id")
                site_name = s.get("name")
                site_prefix_48 = s.get("prefix_48")
                break
        except (ValueError, KeyError):
            continue

    if site_id is None:
        warnings.append(
            f"No registered site matches /48 prefix {candidate_prefix_norm} — "
            "site context cannot be resolved"
        )

    vvvv = f"{(addr_int >> 64) & 0xFFFF:04x}"
    v4 = ipaddress.IPv4Address(addr_int & 0xFFFFFFFF)

    return DecodeResult(
        site_id=site_id,
        site_name=site_name,
        site_prefix_48=site_prefix_48,
        vvvv=vvvv,
        ipv4=str(v4),
        warnings=warnings,
        canonical=addr.compressed,
    )


# ── Allocator: next free vvvv at a given mask ────────────────────────────────

def find_overlap(vvvv: str, prefix_length: int,
                 allocations: Iterable[dict],
                 exclude_alloc_id: Optional[int] = None) -> list[dict]:
    """Return existing allocations whose vvvv range intersects the
    [start, start+size) range of (vvvv, prefix_length). Catches both
    exact match and prefix containment in either direction."""
    size = vvvv_block_size(prefix_length)
    new_start = int(normalize_vvvv(vvvv), 16) & ~(size - 1)
    new_end = new_start + size

    hits: list[dict] = []
    for a in allocations:
        if exclude_alloc_id is not None and a.get("id") == exclude_alloc_id:
            continue
        try:
            v = int(a["vvvv"], 16)
            p = int(a["prefix_length"])
            existing_size = vvvv_block_size(p)
        except (KeyError, ValueError):
            continue
        existing_start = v & ~(existing_size - 1)
        existing_end = existing_start + existing_size
        if new_start < existing_end and existing_start < new_end:
            hits.append(a)
    return hits


def next_block(prefix_length: int, allocations: Iterable[dict]) -> Optional[str]:
    """Walk vvvv from 0x0000 to 0xFFFF on the natural interval for the given
    mask; return the first vvvv whose [start, start+size) range overlaps
    nothing in `allocations`. Returns None when fully exhausted.

    `allocations` is an iterable of dicts with `vvvv` (hex string) and
    `prefix_length` (int) — typically rows from
    clients.ipv6_registry.list_allocations(site_id=...).
    """
    size = vvvv_block_size(prefix_length)

    # Build occupied ranges as (start, end_exclusive)
    occupied: list[tuple[int, int]] = []
    for a in allocations:
        try:
            v = int(a["vvvv"], 16)
            p = int(a["prefix_length"])
            block = vvvv_block_size(p)
        except (KeyError, ValueError):
            continue
        aligned = v & ~(block - 1)
        occupied.append((aligned, aligned + block))

    for start in range(0, 0x10000, size):
        end = start + size
        if not any(start < o_end and o_start < end for o_start, o_end in occupied):
            return f"{start:04x}"
    return None
