"""routers/ipv6_registry.py — IPv6 hierarchical allocation registry endpoints.

Read paths return JSON, or an HTMX partial when HX-Request is present
(matches the dual-mode pattern in routers/firewall.py). Mutations land in
phase 4; this module currently exposes GETs for sites/allocations plus the
decode/assemble compute endpoints.

Sites can be /32../64. Only /48 sites support vvvv-style allocations;
sites at other prefix lengths are leaf prefixes (used as-is), and the
allocation endpoints reject inserts targeting them.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response

from auth import SessionEntry, require_auth
from clients import ipv6_registry as registry
from templates_module import templates
from utils import ipv6_assembler as ipv6

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Sites ────────────────────────────────────────────────────────────────────

@router.get("/sites")
async def list_sites(request: Request, session: SessionEntry = Depends(require_auth)):
    items = registry.list_sites()
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/ipv6_sites_table.html", {"items": items},
        )
    return {"items": items, "total": len(items)}


@router.get("/sites/{site_id}")
async def get_site(site_id: int, session: SessionEntry = Depends(require_auth)):
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    return site


def _normalize_site_prefix(value: str, length: int) -> str:
    """Reject anything that isn't parseable as a network of `length` bits."""
    try:
        return ipv6.normalize_prefix(value, length)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Invalid /{length} prefix '{value}': {e}")


def _validate_site_length(length: int) -> None:
    try:
        ipv6.validate_site_prefix_length(length)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/sites", status_code=201)
async def create_site_endpoint(
    name: str = Form(..., min_length=1, max_length=128),
    prefix: str = Form(..., min_length=2, max_length=64),
    prefix_length: int = Form(48),
    role: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    _validate_site_length(prefix_length)
    canonical = _normalize_site_prefix(prefix, prefix_length)
    try:
        return registry.create_site(
            name=name, prefix=canonical, prefix_length=prefix_length,
            role=role or None, description=description or None,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"A site with that prefix already exists: {e}")


@router.put("/sites/{site_id}")
async def update_site_endpoint(
    site_id: int,
    name: Optional[str] = Form(None),
    prefix: Optional[str] = Form(None),
    prefix_length: Optional[int] = Form(None),
    role: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    existing = registry.get_site(site_id)
    if not existing:
        raise HTTPException(404, f"Site {site_id} not found")
    effective_length = prefix_length if prefix_length is not None else existing["prefix_length"]
    if prefix_length is not None:
        _validate_site_length(prefix_length)
    canonical_prefix: Optional[str] = None
    if prefix is not None:
        canonical_prefix = _normalize_site_prefix(prefix, effective_length)
    try:
        return registry.update_site(
            site_id, name=name, prefix=canonical_prefix,
            prefix_length=prefix_length, role=role, description=description,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Update would violate uniqueness: {e}")


@router.delete("/sites/{site_id}", status_code=204)
async def delete_site_endpoint(site_id: int, session: SessionEntry = Depends(require_auth)):
    if registry.delete_site(site_id) == 0:
        raise HTTPException(404, f"Site {site_id} not found")
    return None


# ── Allocations ──────────────────────────────────────────────────────────────

def _require_carvable_site(site: dict) -> None:
    """vvvv-style allocations only live under /48 sites — everything else is
    a leaf prefix and rejects allocations entirely."""
    if int(site.get("prefix_length", 48)) != ipv6.SITE_PREFIX_FOR_VVVV:
        raise HTTPException(
            400,
            f"Site '{site['name']}' is /{site['prefix_length']} (leaf) — "
            "only /48 sites carry vvvv-style allocations.",
        )


@router.get("/allocations")
async def list_allocations(
    request: Request,
    site_id: Optional[int] = None,
    session: SessionEntry = Depends(require_auth),
):
    items = registry.list_allocations(site_id=site_id)
    if request.headers.get("HX-Request"):
        sites = registry.list_sites()
        return templates.TemplateResponse(
            request, "partials/ipv6_allocations_table.html",
            {"items": items, "sites": sites, "selected_site_id": site_id},
        )
    return {"items": items, "total": len(items)}


@router.get("/allocations/next")
async def next_allocation(
    site_id: int,
    prefix_length: int,
    session: SessionEntry = Depends(require_auth),
):
    """Suggestion-only: return the next free vvvv at the requested mask.
    Does not insert anything — caller submits a separate POST /allocations
    to commit, which avoids leaked reservations from abandoned forms."""
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    _require_carvable_site(site)
    try:
        ipv6.validate_prefix_length(prefix_length)
    except ValueError as e:
        raise HTTPException(400, str(e))

    existing = registry.list_allocations(site_id=site_id)
    suggested = ipv6.next_block(prefix_length, existing)
    if suggested is None:
        raise HTTPException(409, f"No free /{prefix_length} block available in this site")
    return {"site_id": site_id, "prefix_length": prefix_length, "vvvv": suggested}


@router.get("/allocations/{alloc_id}")
async def get_allocation(alloc_id: int, session: SessionEntry = Depends(require_auth)):
    a = registry.get_allocation(alloc_id)
    if not a:
        raise HTTPException(404, f"Allocation {alloc_id} not found")
    return a


def _check_conflicts(site_id: int, vvvv: str, prefix_length: int,
                     ipv4_subnet: Optional[str],
                     exclude_alloc_id: Optional[int] = None) -> list[dict]:
    """Run both conflict checks. Hard-block on vvvv overlap (raises 409);
    return the soft-warn list of ipv4_subnet collisions for the caller."""
    existing = registry.list_allocations(site_id=site_id)
    overlaps = ipv6.find_overlap(vvvv, prefix_length, existing,
                                 exclude_alloc_id=exclude_alloc_id)
    if overlaps:
        descr = ", ".join(
            f"#{o['id']}({o['vvvv']}/{o['prefix_length']})" for o in overlaps
        )
        raise HTTPException(
            409,
            f"vvvv {vvvv}/{prefix_length} overlaps existing allocation(s): {descr}",
        )
    if ipv4_subnet:
        return registry.find_ipv4_collision(site_id, ipv4_subnet,
                                            exclude_alloc_id=exclude_alloc_id)
    return []


def _parse_ipv4_subnet(value: Optional[str]) -> Optional[str]:
    if value is None or value.strip() == "":
        return None
    try:
        return str(ipaddress.IPv4Network(value.strip(), strict=False))
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Invalid IPv4 subnet '{value}': {e}")


@router.post("/allocations", status_code=201)
async def create_allocation_endpoint(
    site_id: int = Form(...),
    vvvv: str = Form(..., min_length=1, max_length=4),
    prefix_length: int = Form(...),
    ipv4_subnet: Optional[str] = Form(None),
    purpose: Optional[str] = Form(None),
    status: str = Form("allocated"),
    owner: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    confirm_ipv4_dup: bool = Form(False),
    session: SessionEntry = Depends(require_auth),
):
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    _require_carvable_site(site)
    try:
        norm_vvvv = ipv6.normalize_vvvv(vvvv)
        ipv6.validate_prefix_length(prefix_length)
    except ValueError as e:
        raise HTTPException(400, str(e))
    norm_subnet = _parse_ipv4_subnet(ipv4_subnet)

    v4_warnings = _check_conflicts(site_id, norm_vvvv, prefix_length, norm_subnet)
    if v4_warnings and not confirm_ipv4_dup:
        raise HTTPException(
            409,
            {
                "detail": (
                    f"IPv4 subnet {norm_subnet} is already mapped in this site. "
                    "Pass confirm_ipv4_dup=true to allow."
                ),
                "ipv4_collisions": v4_warnings,
            },
        )

    try:
        row = registry.create_allocation(
            site_id=site_id, vvvv=norm_vvvv, prefix_length=prefix_length,
            ipv4_subnet=norm_subnet, purpose=purpose or None,
            status=status, owner=owner or None, description=description or None,
        )
    except sqlite3.IntegrityError as e:
        # Falls through here if the DB-level UNIQUE(site_id, vvvv) trips —
        # _check_conflicts should have caught it first, but stay defensive.
        raise HTTPException(409, f"Allocation conflict: {e}")

    return {"allocation": row, "ipv4_warnings": v4_warnings}


@router.put("/allocations/{alloc_id}")
async def update_allocation_endpoint(
    alloc_id: int,
    vvvv: Optional[str] = Form(None),
    prefix_length: Optional[int] = Form(None),
    ipv4_subnet: Optional[str] = Form(None),
    purpose: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
    owner: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    confirm_ipv4_dup: bool = Form(False),
    session: SessionEntry = Depends(require_auth),
):
    existing = registry.get_allocation(alloc_id)
    if not existing:
        raise HTTPException(404, f"Allocation {alloc_id} not found")

    new_vvvv = ipv6.normalize_vvvv(vvvv) if vvvv else existing["vvvv"]
    new_len = prefix_length if prefix_length is not None else existing["prefix_length"]
    try:
        ipv6.validate_prefix_length(new_len)
    except ValueError as e:
        raise HTTPException(400, str(e))
    new_subnet = (_parse_ipv4_subnet(ipv4_subnet)
                  if ipv4_subnet is not None else existing["ipv4_subnet"])

    v4_warnings = _check_conflicts(existing["site_id"], new_vvvv, new_len,
                                   new_subnet, exclude_alloc_id=alloc_id)
    if v4_warnings and not confirm_ipv4_dup:
        raise HTTPException(
            409,
            {
                "detail": f"IPv4 subnet {new_subnet} is already mapped in this site.",
                "ipv4_collisions": v4_warnings,
            },
        )

    try:
        row = registry.update_allocation(
            alloc_id, vvvv=new_vvvv if vvvv else None,
            prefix_length=prefix_length, ipv4_subnet=new_subnet,
            purpose=purpose, status=status, owner=owner, description=description,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Allocation conflict: {e}")
    return {"allocation": row, "ipv4_warnings": v4_warnings}


@router.delete("/allocations/{alloc_id}", status_code=204)
async def delete_allocation_endpoint(alloc_id: int, session: SessionEntry = Depends(require_auth)):
    if registry.delete_allocation(alloc_id) == 0:
        raise HTTPException(404, f"Allocation {alloc_id} not found")
    return None


_IPV4_SPLIT_CHARS = (",", ";", "\t")


def _split_ipv4_list(raw: str) -> list[str]:
    """Tolerant parser: accepts newlines, commas, semicolons, tabs, whitespace.
    Strips '# comments', drops blanks, dedupes preserving first-seen order."""
    tokens: list[str] = []
    for line in raw.splitlines():
        clean = line.split("#", 1)[0]
        for ch in _IPV4_SPLIT_CHARS:
            clean = clean.replace(ch, " ")
        for tok in clean.split():
            tokens.append(tok.strip())
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


@router.post("/assemble/bulk")
async def assemble_bulk(
    request: Request,
    site_id: int = Form(...),
    ipv4_list: str = Form(..., min_length=1),
    session: SessionEntry = Depends(require_auth),
):
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    _require_carvable_site(site)

    hosts = _split_ipv4_list(ipv4_list)
    allocations = registry.list_allocations(site_id=site_id)

    rows: list[dict] = []
    counts = {"ok": 0, "no_match": 0, "invalid": 0}

    for raw in hosts:
        row: dict = {
            "site_name": site["name"], "ipv4": raw,
            "ipv6": "", "vvvv": "", "status": "", "detail": "",
        }
        try:
            ipaddress.IPv4Address(raw)
        except (ipaddress.AddressValueError, ValueError) as e:
            row["status"] = "invalid"
            row["detail"] = str(e)
            counts["invalid"] += 1
            rows.append(row)
            continue

        match = _find_vvvv_for_ipv4(site_id, raw, allocations=allocations)
        if match is None:
            row["status"] = "no_match"
            row["detail"] = "no allocation covers this IPv4 in this site"
            counts["no_match"] += 1
            rows.append(row)
            continue

        try:
            addr = ipv6.assemble(site["prefix"], match["vvvv"], raw)
        except (ipaddress.AddressValueError, ValueError) as e:
            row["status"] = "invalid"
            row["detail"] = str(e)
            counts["invalid"] += 1
            rows.append(row)
            continue

        row["status"] = "ok"
        row["vvvv"] = match["vvvv"]
        row["ipv6"] = addr.compressed
        row["allocation_id"] = match["id"]
        row["matched_subnet"] = match["ipv4_subnet"]
        counts["ok"] += 1
        rows.append(row)

    payload = {
        "site": {
            "id": site["id"], "name": site["name"],
            "prefix": site["prefix"], "prefix_length": site["prefix_length"],
        },
        "rows": rows,
        "counts": counts,
        "total": len(rows),
    }
    if request.headers.get("HX-Request"):
        # TSV body for the copy-paste textarea: site, ipv4, ipv6 (skip failures)
        tsv_lines = [f"{r['site_name']}\t{r['ipv4']}\t{r['ipv6']}"
                     for r in rows if r["status"] == "ok"]
        payload["tsv"] = "\n".join(tsv_lines)
        return templates.TemplateResponse(
            request, "partials/ipv6_bulk_assemble_result.html", {"result": payload},
        )
    return payload


# ── Export ───────────────────────────────────────────────────────────────────

@router.get("/export.csv")
async def export_csv(session: SessionEntry = Depends(require_auth)):
    """Single CSV of all allocations, joined with their site row, plus the
    assembled IPv6 prefix for documentation."""
    rows = registry.list_allocations()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "site_name", "site_prefix", "site_prefix_length", "vvvv", "prefix_length",
        "assembled_prefix", "ipv4_subnet", "purpose", "status",
        "owner", "description", "created_at", "updated_at",
    ])
    for r in rows:
        assembled = f"{r['site_prefix']}:{r['vvvv']}::/{r['prefix_length']}"
        writer.writerow([
            r["site_name"], r["site_prefix"], r["site_prefix_length"],
            r["vvvv"], r["prefix_length"],
            assembled, r["ipv4_subnet"] or "", r["purpose"] or "",
            r["status"], r["owner"] or "", r["description"] or "",
            r["created_at"], r["updated_at"],
        ])
    # utf-8-sig prepends the UTF-8 BOM so Excel auto-detects the encoding
    # (matches the existing pattern in routers/ipam.py for SolarWinds export).
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=ipv6_registry.csv"},
    )


# ── Decode / Assemble (compute-only, no DB writes) ───────────────────────────

@router.post("/decode")
async def decode(
    request: Request,
    ipv6_addr: str = Form(..., alias="ipv6", min_length=2, max_length=64),
    session: SessionEntry = Depends(require_auth),
):
    try:
        result = ipv6.decode(ipv6_addr, registry.list_sites())
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Invalid IPv6 address: {e}")
    payload = {
        "site_id": result.site_id,
        "site_name": result.site_name,
        "site_prefix": result.site_prefix,
        "site_prefix_length": result.site_prefix_length,
        "vvvv": result.vvvv,
        "ipv4": result.ipv4,
        "canonical": result.canonical,
        "warnings": result.warnings,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/ipv6_decode_result.html", {"result": payload},
        )
    return payload


def _find_vvvv_for_ipv4(site_id: int, ipv4: str,
                        allocations: Optional[list[dict]] = None) -> Optional[dict]:
    """Walk this site's allocations and return the row whose ipv4_subnet
    contains the host. Longest-prefix match wins (a /27 inside a /24 takes
    precedence over the /24). Pass `allocations` to skip the DB roundtrip
    when looping over many hosts in the same site."""
    try:
        host = ipaddress.IPv4Address(ipv4.strip())
    except (ipaddress.AddressValueError, ValueError):
        return None
    if allocations is None:
        allocations = registry.list_allocations(site_id=site_id)
    best: tuple[int, dict] | None = None
    for a in allocations:
        subnet = a.get("ipv4_subnet")
        if not subnet:
            continue
        try:
            net = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError:
            continue
        if host in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, a)
    return best[1] if best else None


@router.post("/assemble")
async def assemble(
    request: Request,
    site_id: int = Form(...),
    ipv4: str = Form(..., min_length=7, max_length=15),
    vvvv: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    _require_carvable_site(site)

    matched_allocation: Optional[dict] = None
    vvvv_value = (vvvv or "").strip() or None

    if vvvv_value is None:
        matched_allocation = _find_vvvv_for_ipv4(site_id, ipv4)
        if matched_allocation is None:
            raise HTTPException(
                422,
                f"No allocation in site '{site['name']}' contains IPv4 {ipv4}. "
                "Either register the subnet first or pass vvvv explicitly.",
            )
        vvvv_value = matched_allocation["vvvv"]

    try:
        addr = ipv6.assemble(site["prefix"], vvvv_value, ipv4)
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Cannot assemble: {e}")

    payload = {
        "ipv6": addr.compressed,
        "ipv6_exploded": addr.exploded,
        "site": {
            "id": site["id"], "name": site["name"],
            "prefix": site["prefix"], "prefix_length": site["prefix_length"],
        },
        "vvvv": vvvv_value,
        "ipv4": ipv4,
        "matched_allocation": matched_allocation,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/ipv6_assemble_result.html", {"result": payload},
        )
    return payload
