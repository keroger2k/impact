"""utils/ipv6_assembler.py — Hierarchical IPv6 conversion math.

Pure functions, no DB or HTTP. Sites can be /32../64; the default carving
shape (used for vvvv-style allocations) is built around a /48 site:

    [ site prefix (48 bits) ] [ vvvv (16 bits) ] [ 0000:0000 (32 bits) ] [ ipv4 (32 bits) ]
       hextets 1..3                hextet 4              hextets 5..6              hextets 7..8

Example: site DC1 with /48 = 1000:2000:3000, vvvv = 0100, host = 1.2.3.4
         -> 1000:2000:3000:100::102:304

Sites with prefix lengths other than /48 are leaf prefixes — they don't
carve vvvv sub-allocations (the assembler does not run for them).

All addresses are canonicalized via the stdlib ipaddress module.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional

# Bounds on site prefix lengths the registry will accept.
SITE_PREFIX_MIN = 32
SITE_PREFIX_MAX = 64

# Sites that carve vvvv sub-allocations must be exactly /48 — the vvvv hextet
# sits in bits 49..64 by construction.
SITE_PREFIX_FOR_VVVV = 48


# ── Validation helpers ───────────────────────────────────────────────────────

def validate_site_prefix_length(prefix_length: int) -> None:
    if not SITE_PREFIX_MIN <= prefix_length <= SITE_PREFIX_MAX:
        raise ValueError(
            f"site prefix_length {prefix_length} out of range; "
            f"must be {SITE_PREFIX_MIN}..{SITE_PREFIX_MAX}"
        )


def normalize_prefix(prefix: str, prefix_length: int = 48) -> str:
    """Canonical leading-hextets representation of a site prefix at the given
    length. Strips trailing zero hextets that lie beyond the prefix boundary
    and drops leading zeros in each kept hextet.

    Examples:
        normalize_prefix("0100:0200:0300", 48)        -> "100:200:300"
        normalize_prefix("2600:0400:3031:0100", 56)   -> "2600:400:3031:100"
        normalize_prefix("2600:400::", 32)            -> "2600:400"
    """
    validate_site_prefix_length(prefix_length)
    cleaned = prefix.strip().rstrip(":")
    # strict=False zeroes host bits, giving us a canonical network address
    net = ipaddress.IPv6Network(f"{cleaned}::/{prefix_length}", strict=False)
    full = net.network_address.exploded.split(":")  # 8 groups, padded
    needed = (prefix_length + 15) // 16  # ceil(prefix_length / 16)
    return ":".join(h.lstrip("0") or "0" for h in full[:needed])


def normalize_prefix_48(prefix_48: str) -> str:
    """Back-compat shim: /48-only callers."""
    return normalize_prefix(prefix_48, 48)


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
    """Allocation prefix length. vvvv-aligned allocations only live in
    /49..../64 — anything longer doesn't carve the vvvv hextet; anything
    shorter is the site itself."""
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
    """Combine a /48 site prefix, vvvv segment, zero hextets, and the IPv4
    host-tail into a fully-formed IPv6Address.

    Sites that aren't /48 are leaves and don't go through this path.
    """
    prefix_int = int(ipaddress.IPv6Address(f"{normalize_prefix(prefix_48, 48)}::"))
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
    site_prefix: Optional[str]
    site_prefix_length: Optional[int]
    vvvv: str
    ipv4: str
    warnings: list[str]
    canonical: str  # canonical compressed form of the input address


def _site_matches(site: dict, addr_int: int) -> bool:
    try:
        length = int(site.get("prefix_length", 48))
        prefix = normalize_prefix(site["prefix"], length)
    except (KeyError, ValueError):
        return False
    site_net_int = int(ipaddress.IPv6Address(f"{prefix}::"))
    mask = ((1 << 128) - 1) ^ ((1 << (128 - length)) - 1)
    return (addr_int & mask) == (site_net_int & mask)


def decode(ipv6: str, sites: Iterable[dict]) -> DecodeResult:
    """Reverse direction. Reports the site because IPv4 alone is ambiguous
    across sites; matches longest prefix first so a /56 airport leaf wins
    over its containing /48 state when both are registered.

    For /48 matches we also extract vvvv (hextet 4) and the IPv4 host-tail
    (hextets 7-8). For leaf sites (any other prefix length) those fields are
    populated from the raw bits but flagged as informational only — the
    address may not actually follow the assembler scheme below the site mask.

    `sites` is an iterable of dicts with at least `id`, `name`, `prefix`,
    `prefix_length` (rows from clients.ipv6_registry.list_sites()).
    """
    addr = ipaddress.IPv6Address(ipv6.strip())
    addr_int = int(addr)

    warnings: list[str] = []

    site_list = list(sites)
    # Longest prefix wins (a /56 leaf beats a containing /48)
    matches = [s for s in site_list if _site_matches(s, addr_int)]
    matches.sort(key=lambda s: int(s.get("prefix_length", 48)), reverse=True)
    site = matches[0] if matches else None

    site_id = site_name = site_prefix = None
    site_prefix_length: Optional[int] = None
    if site is not None:
        site_id = site.get("id")
        site_name = site.get("name")
        site_prefix = site.get("prefix")
        site_prefix_length = int(site.get("prefix_length", 48))
    else:
        candidate = ipaddress.IPv6Address((addr_int >> 80) << 80).exploded.split(":")[:3]
        candidate_norm = ":".join(h.lstrip("0") or "0" for h in candidate)
        warnings.append(
            f"No registered site matches /48 prefix {candidate_norm} — "
            "site context cannot be resolved"
        )

    # vvvv + ipv4 recovery assumes the /48 layout. For leaf (non-/48) sites
    # we still report the raw values but mark them as informational.
    is_vvvv_layout = (site_prefix_length is None or site_prefix_length == SITE_PREFIX_FOR_VVVV)
    if is_vvvv_layout:
        mid = (addr_int >> 32) & 0xFFFFFFFF
        if mid != 0:
            warnings.append(
                f"Hextets 5-6 are non-zero (0x{mid:08x}); address does not follow "
                "the standard scheme — host-tail recovery may be unreliable"
            )
    elif site_prefix_length is not None:
        warnings.append(
            f"Matched site is /{site_prefix_length} (leaf) — vvvv and IPv4 fields "
            "are raw bit extracts, not assembler-scheme values"
        )

    vvvv = f"{(addr_int >> 64) & 0xFFFF:04x}"
    v4 = ipaddress.IPv4Address(addr_int & 0xFFFFFFFF)

    return DecodeResult(
        site_id=site_id,
        site_name=site_name,
        site_prefix=site_prefix,
        site_prefix_length=site_prefix_length,
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
