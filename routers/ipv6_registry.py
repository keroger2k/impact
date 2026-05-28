"""routers/ipv6_registry.py — IPv6 hierarchical allocation registry endpoints.

Read paths return JSON, or an HTMX partial when HX-Request is present
(matches the dual-mode pattern in routers/firewall.py). Mutations land in
phase 4; this module currently exposes GETs for sites/allocations plus the
decode/assemble compute endpoints.

Sites can be /32../64 and may all carry vvvv-style /49..../64 allocations.
For non-/48 sites the vvvv is constrained: its high bits must match the
bits the site prefix already commits (e.g. a /56 site at
2600:0400:3028:2d00 allows vvvvs in the 0x2d00..0x2dff range).
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
from cache import IPAM_TREE_CACHE_KEY, cache
from clients import ipv6_registry as registry
from templates_module import templates
from utils import ipv6_assembler as ipv6
from utils import ipv6_audit

_AUDIT_CACHE_KEY = "ipv6_audit_v1"
_AUDIT_TTL = 60  # short — both inputs (registry SQLite + IPAM tree) churn slowly

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


def _validate_status(status: str) -> None:
    if status not in registry.SITE_STATUSES:
        raise HTTPException(
            400,
            f"status must be one of {list(registry.SITE_STATUSES)}, got {status!r}",
        )


def _parse_ipv4_supernet(value: Optional[str]) -> Optional[str]:
    """Accept one or more comma-separated IPv4 CIDRs; return them normalized
    and joined by ', '. None / empty input → None. Each CIDR is validated
    individually so the user sees a precise error for the bad token."""
    if value is None or value.strip() == "":
        return None
    parts: list[str] = []
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            parts.append(str(ipaddress.IPv4Network(token, strict=False)))
        except (ipaddress.AddressValueError, ValueError) as e:
            raise HTTPException(400, f"Invalid IPv4 supernet '{token}': {e}")
    return ", ".join(parts) if parts else None


@router.post("/sites", status_code=201)
async def create_site_endpoint(
    name: str = Form(..., min_length=1, max_length=128),
    prefix: str = Form(..., min_length=2, max_length=64),
    prefix_length: int = Form(48),
    role: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    status: str = Form("active"),
    ipv4_supernet: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    _validate_site_length(prefix_length)
    _validate_status(status)
    canonical = _normalize_site_prefix(prefix, prefix_length)
    canonical_v4 = _parse_ipv4_supernet(ipv4_supernet)
    try:
        site = registry.create_site(
            name=name, prefix=canonical, prefix_length=prefix_length,
            role=role or None, description=description or None,
            status=status, ipv4_supernet=canonical_v4,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"A site with that prefix already exists: {e}")
    cache.invalidate(_AUDIT_CACHE_KEY)
    return site


@router.put("/sites/{site_id}")
async def update_site_endpoint(
    site_id: int,
    name: Optional[str] = Form(None),
    prefix: Optional[str] = Form(None),
    prefix_length: Optional[int] = Form(None),
    role: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
    ipv4_supernet: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    existing = registry.get_site(site_id)
    if not existing:
        raise HTTPException(404, f"Site {site_id} not found")
    effective_length = prefix_length if prefix_length is not None else existing["prefix_length"]
    if prefix_length is not None:
        _validate_site_length(prefix_length)
    if status is not None:
        _validate_status(status)
    canonical_prefix: Optional[str] = None
    if prefix is not None:
        canonical_prefix = _normalize_site_prefix(prefix, effective_length)
    canonical_v4 = _parse_ipv4_supernet(ipv4_supernet) if ipv4_supernet is not None else None
    try:
        updated = registry.update_site(
            site_id, name=name, prefix=canonical_prefix,
            prefix_length=prefix_length, role=role, description=description,
            status=status, ipv4_supernet=canonical_v4,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Update would violate uniqueness: {e}")
    cache.invalidate(_AUDIT_CACHE_KEY)
    return updated


# Standard VLAN preset for the /56 (or other carvable) site provisioner.
# Mirrors the TSA fleet's standard build sheet — see screenshot for T573:
# vvvv offset 4 is intentionally skipped (VLAN500 / STIP lives in a separate
# /48 aggregate, not under the site's /56).
STANDARD_VLAN_PRESET: list[dict] = [
    {"key": "l3",   "offset": 0, "purpose": "L3 Interconnect", "description": "Routed Interface"},
    {"key": "mgmt", "offset": 1, "purpose": "MGMT",            "description": "VLAN3 — Management"},
    {"key": "data", "offset": 2, "purpose": "Data",            "description": "VLAN100 — Data"},
    {"key": "voip", "offset": 3, "purpose": "VoIP",            "description": "VLAN600 — VoIP"},
    {"key": "etas", "offset": 5, "purpose": "ETAS",            "description": "VLAN800 — ETAS"},
    {"key": "hsdn", "offset": 6, "purpose": "HSDN",            "description": "VLAN700 — HSDN"},
]


@router.post("/sites/provision-standard", status_code=201)
async def provision_standard_site(
    name: str = Form(..., min_length=1, max_length=128),
    prefix: str = Form(..., min_length=2, max_length=64),
    prefix_length: int = Form(56),
    role: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    status: str = Form("active"),
    vlans: str = Form("l3,mgmt,data,voip,etas,hsdn"),
    session: SessionEntry = Depends(require_auth),
):
    """Create a carvable site (default /56) plus the standard set of VLAN
    /64 allocations under it. The site is rolled back if any allocation
    creation fails, so partial state never leaks."""
    _validate_site_length(prefix_length)
    _validate_status(status)
    if prefix_length >= 64:
        raise HTTPException(
            400, f"Provisioned site must be /< 64 (got /{prefix_length}) so it can carry /64 allocations.",
        )
    canonical = _normalize_site_prefix(prefix, prefix_length)

    requested_keys = {k.strip().lower() for k in vlans.split(",") if k.strip()}
    preset_by_key = {p["key"]: p for p in STANDARD_VLAN_PRESET}
    unknown = requested_keys - set(preset_by_key)
    if unknown:
        raise HTTPException(
            400, f"Unknown VLAN keys: {sorted(unknown)}. Known: {sorted(preset_by_key)}",
        )
    if not requested_keys:
        raise HTTPException(400, "At least one VLAN must be selected.")
    # Preserve preset order so the resulting allocations are stable and
    # easy to read in the table.
    selected = [p for p in STANDARD_VLAN_PRESET if p["key"] in requested_keys]

    site_fixed = ipv6.site_vvvv_fixed_value(canonical, prefix_length)
    site_mask = ipv6.site_vvvv_mask(prefix_length)
    free_span = (~site_mask) & 0xFFFF
    over_budget = [p for p in selected if p["offset"] > free_span]
    if over_budget:
        bad = ", ".join(f"{p['key']}(offset={p['offset']})" for p in over_budget)
        raise HTTPException(
            400,
            f"VLAN offsets exceed the site's free vvvv space ({free_span + 1} slots): {bad}",
        )

    try:
        site_row = registry.create_site(
            name=name, prefix=canonical, prefix_length=prefix_length,
            role=role or None, description=description or None, status=status,
        )
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"A site with that prefix already exists: {e}")

    created_allocations: list[dict] = []
    try:
        for p in selected:
            vvvv = f"{site_fixed + p['offset']:04x}"
            alloc = registry.create_allocation(
                site_id=site_row["id"], vvvv=vvvv, prefix_length=64,
                purpose=p["purpose"], description=p["description"], status="allocated",
            )
            created_allocations.append(alloc)
    except Exception as e:
        # Roll back the site so the user can retry without leftover state.
        registry.delete_site(site_row["id"])
        raise HTTPException(500, f"Allocation creation failed; site rolled back: {e}")

    cache.invalidate(_AUDIT_CACHE_KEY)
    return {
        "site": site_row,
        "allocations": created_allocations,
        "preset": [p["key"] for p in selected],
    }


@router.post("/sites/{site_id}/status")
async def set_site_status_endpoint(
    site_id: int,
    status: str = Form(...),
    session: SessionEntry = Depends(require_auth),
):
    """Set a single site's lifecycle status. When transitioning to
    `decommissioned`, also cascades the same status to every site whose
    prefix is contained within this one (computed in the registry layer)."""
    _validate_status(status)
    result = registry.set_status_cascade(site_id, status)
    if result["site"] is None:
        raise HTTPException(404, f"Site {site_id} not found")
    cache.invalidate(_AUDIT_CACHE_KEY)
    return {
        "site": result["site"],
        "affected_children": result["affected_children"],
        "affected_count": len(result["affected_children"]),
    }


@router.delete("/sites/{site_id}", status_code=204)
async def delete_site_endpoint(site_id: int, session: SessionEntry = Depends(require_auth)):
    if registry.delete_site(site_id) == 0:
        raise HTTPException(404, f"Site {site_id} not found")
    cache.invalidate(_AUDIT_CACHE_KEY)
    return None


# ── Allocations ──────────────────────────────────────────────────────────────

def _require_carvable_site(site: dict) -> None:
    """Allocation parents must be /32../63 — /64 sites are atomic and can't
    carve a more-specific subnet."""
    site_len = int(site.get("prefix_length", 48))
    if site_len >= 64:
        raise HTTPException(
            400,
            f"Site '{site['name']}' is /{site_len} — only sites with "
            "prefix_length < 64 can carry sub-allocations.",
        )


def _require_vvvv_conforms(vvvv: str, site: dict) -> None:
    """vvvv's high bits must match the bits the site prefix already commits
    (no-op for /48 sites, where the whole 4th hextet is free)."""
    site_len = int(site.get("prefix_length", 48))
    if site_len <= 48:
        return
    if not ipv6.vvvv_conforms_to_site(vvvv, site["prefix"], site_len):
        fixed = ipv6.site_vvvv_fixed_value(site["prefix"], site_len)
        mask = ipv6.site_vvvv_mask(site_len)
        raise HTTPException(
            400,
            f"vvvv {vvvv} does not match site '{site['name']}' (/{site_len}); "
            f"its high bits must equal 0x{fixed:04x} under mask 0x{mask:04x}.",
        )


def _require_alloc_length_for_site(prefix_length: int, site: dict) -> None:
    """Allocation prefix_length must be strictly more specific than the
    site's, and at most /64."""
    site_len = int(site.get("prefix_length", 48))
    try:
        ipv6.validate_prefix_length(prefix_length, site_prefix_length=site_len)
    except ValueError as e:
        raise HTTPException(400, str(e))


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
    _require_alloc_length_for_site(prefix_length, site)

    existing = registry.list_allocations(site_id=site_id)
    suggested = ipv6.next_block(prefix_length, existing, site=site)
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


def _parse_vlan_id(value: Optional[str]) -> Optional[int]:
    """Accept 1..4094 (the usable IEEE 802.1Q range). Blank → None."""
    if value is None:
        return None
    s = str(value).strip()
    if s == "":
        return None
    try:
        n = int(s)
    except ValueError:
        raise HTTPException(400, f"Invalid VLAN ID '{value}': not an integer")
    if not (1 <= n <= 4094):
        raise HTTPException(400, f"VLAN ID {n} out of range (1..4094)")
    return n


@router.post("/allocations", status_code=201)
async def create_allocation_endpoint(
    site_id: int = Form(...),
    vvvv: str = Form(..., min_length=1, max_length=4),
    prefix_length: int = Form(...),
    ipv4_subnet: Optional[str] = Form(None),
    vlan_id: Optional[str] = Form(None),
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
    except ValueError as e:
        raise HTTPException(400, str(e))
    _require_alloc_length_for_site(prefix_length, site)
    _require_vvvv_conforms(norm_vvvv, site)
    norm_subnet = _parse_ipv4_subnet(ipv4_subnet)
    norm_vlan = _parse_vlan_id(vlan_id)

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
            ipv4_subnet=norm_subnet, vlan_id=norm_vlan, purpose=purpose or None,
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
    vlan_id: Optional[str] = Form(None),
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
    parent_site = registry.get_site(existing["site_id"])
    if parent_site is None:
        raise HTTPException(500, "Parent site for allocation has vanished")
    _require_alloc_length_for_site(new_len, parent_site)
    _require_vvvv_conforms(new_vvvv, parent_site)
    new_subnet = (_parse_ipv4_subnet(ipv4_subnet)
                  if ipv4_subnet is not None else existing["ipv4_subnet"])
    new_vlan = (_parse_vlan_id(vlan_id)
                if vlan_id is not None else existing.get("vlan_id"))

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
            vlan_id=new_vlan,
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
            addr = ipv6.assemble(site["prefix"], match["vvvv"], raw,
                                 site_prefix_length=int(site["prefix_length"]))
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


# ── Audit ────────────────────────────────────────────────────────────────────

def _compute_audit() -> dict:
    return ipv6_audit.run_audit(registry.list_sites(), cache.get(IPAM_TREE_CACHE_KEY))


@router.get("/audit")
async def audit(
    request: Request,
    refresh: bool = False,
    session: SessionEntry = Depends(require_auth),
):
    """Cross-check the Registry against live IPv6 from the IPAM tree.

    Returns three lists — coverage_gaps, off_book, site_mismatches —
    plus counts. Cached briefly (60s) so the tab stays snappy across
    clicks; `?refresh=1` forces a recompute."""
    if refresh:
        cache.invalidate(_AUDIT_CACHE_KEY)
    report = cache.get_or_set(_AUDIT_CACHE_KEY, _compute_audit, _AUDIT_TTL)
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/ipv6_audit_results.html", {"report": report},
        )
    return report


# ── Export ───────────────────────────────────────────────────────────────────

@router.get("/export.csv")
async def export_csv(session: SessionEntry = Depends(require_auth)):
    """Single CSV of all allocations, joined with their site row, plus the
    assembled IPv6 prefix for documentation."""
    rows = registry.list_allocations()
    buf = io.StringIO()
    writer = csv.writer(buf)
    sites_by_id = {s["id"]: s for s in registry.list_sites()}
    writer.writerow([
        "site_name", "site_prefix", "site_prefix_length", "site_ipv4_supernet",
        "vvvv", "prefix_length",
        "assembled_prefix", "ipv4_subnet", "vlan_id", "purpose", "status",
        "owner", "description", "created_at", "updated_at",
    ])
    for r in rows:
        assembled = f"{r['site_prefix']}:{r['vvvv']}::/{r['prefix_length']}"
        site = sites_by_id.get(r["site_id"]) or {}
        writer.writerow([
            r["site_name"], r["site_prefix"], r["site_prefix_length"],
            site.get("ipv4_supernet") or "",
            r["vvvv"], r["prefix_length"],
            assembled, r["ipv4_subnet"] or "", r["vlan_id"] or "",
            r["purpose"] or "",
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
        addr = ipv6.assemble(site["prefix"], vvvv_value, ipv4,
                             site_prefix_length=int(site["prefix_length"]))
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
