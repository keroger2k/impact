"""routers/ip_registry.py — Dual-stack IP Address Registry endpoints.

The rebuilt, site-centric registry (replaces routers/ipv6_registry.py). A site
is the first-class entity (keyed by ``site_code``); IPv4 and IPv6 networks are
``prefixes`` rows beneath it. Read paths return JSON, or an htmx partial when
``HX-Request`` is present (the dual-mode pattern used across the app).

Beyond CRUD, this exposes the **audit** (reconcile the registry against the live
network via ``utils.ip_audit``) and **bulk-accept** — the operator multi-selects
discovered drift items (undocumented network-only subnets, whole new sites) and
commits them into the registry in one shot. The kept TSA tools (vvvv
decode / IPv4→IPv6 assemble) operate on the registry's IPv6 prefixes.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response

from auth import SessionEntry, require_auth
from cache import cache
from clients import ip_registry as registry
from templates_module import templates
from utils import ip_audit, ipam_net
from utils import ipv6_assembler as ipv6

router = APIRouter()
logger = logging.getLogger(__name__)

_AUDIT_TTL = 60  # short — registry SQLite + warmed caches both churn slowly


def _invalidate_audit() -> None:
    for key in cache.keys_for_prefix("ip_audit:"):
        cache.invalidate(key)


# ── small parsers ────────────────────────────────────────────────────────────

def _norm_cidr(value: str) -> tuple[int, str]:
    """(family, canonical cidr) or HTTP 400."""
    try:
        fam, _, _, canon = ipam_net.canonical(value)
        return fam, canon
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Invalid network '{value}': {e}")


def _parse_vlan(value: Optional[str]) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    try:
        n = int(str(value).strip())
    except ValueError:
        raise HTTPException(400, f"Invalid VLAN ID '{value}'")
    if not (1 <= n <= 4094):
        raise HTTPException(400, f"VLAN ID {n} out of range (1..4094)")
    return n


def _check_status(value: Optional[str], allowed: tuple, kind: str) -> None:
    if value is not None and value not in allowed:
        raise HTTPException(400, f"{kind} must be one of {list(allowed)}, got {value!r}")


# ── Sites ──────────────────────────────────────────────────────────────────────

def _site_rollup(site: dict, prefixes: list[dict]) -> dict:
    """Augment a site row with a per-family prefix summary for list views."""
    mine = [p for p in prefixes if p["site_id"] == site["id"]]
    return {
        **site,
        "v4_count": sum(1 for p in mine if p["family"] == 4),
        "v6_count": sum(1 for p in mine if p["family"] == 6),
        "prefix_count": len(mine),
    }


@router.get("/sites")
async def list_sites(request: Request, session: SessionEntry = Depends(require_auth)):
    sites = registry.list_sites()
    prefixes = registry.list_prefixes()
    items = [_site_rollup(s, prefixes) for s in sites]
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_sites_table.html", {"items": items})
    return {"items": items, "total": len(items)}


@router.get("/sites/{site_id}")
async def get_site(request: Request, site_id: int,
                   session: SessionEntry = Depends(require_auth)):
    site = registry.get_site(site_id)
    if not site:
        raise HTTPException(404, f"Site {site_id} not found")
    prefixes = registry.list_prefixes(site_id=site_id)
    v4 = [p for p in prefixes if p["family"] == 4]
    v6 = [p for p in prefixes if p["family"] == 6]
    payload = {"site": site, "prefixes": prefixes, "v4": v4, "v6": v6}
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_site_detail.html", payload)
    return payload


@router.post("/sites", status_code=201)
async def create_site(
    site_code: str = Form(..., min_length=1, max_length=32),
    name: Optional[str] = Form(None),
    region: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    status: str = Form("active"),
    description: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    _check_status(status, registry.SITE_STATUSES, "status")
    try:
        site = registry.create_site(
            site_code.strip().upper(), name=name or None, region=region or None,
            role=role or None, status=status, description=description or None)
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"A site with code '{site_code}' already exists")
    _invalidate_audit()
    return site


@router.put("/sites/{site_id}")
async def update_site(
    site_id: int,
    site_code: Optional[str] = Form(None),
    name: Optional[str] = Form(None),
    region: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    if not registry.get_site(site_id):
        raise HTTPException(404, f"Site {site_id} not found")
    _check_status(status, registry.SITE_STATUSES, "status")
    try:
        updated = registry.update_site(
            site_id, site_code=(site_code.strip().upper() if site_code else None),
            name=name, region=region, role=role, status=status,
            description=description)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Update would collide with an existing site_code")
    _invalidate_audit()
    return updated


@router.delete("/sites/{site_id}", status_code=204)
async def delete_site(site_id: int, session: SessionEntry = Depends(require_auth)):
    if registry.delete_site(site_id) == 0:
        raise HTTPException(404, f"Site {site_id} not found")
    _invalidate_audit()
    return None


# ── Prefixes ─────────────────────────────────────────────────────────────────

@router.get("/prefixes")
async def list_prefixes(
    request: Request,
    site_id: Optional[int] = None,
    family: Optional[int] = None,
    containers: bool = False,
    session: SessionEntry = Depends(require_auth),
):
    items = registry.list_prefixes(site_id=site_id, family=family,
                                   containers_only=containers)
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_prefixes_table.html",
            {"items": items, "selected_site_id": site_id})
    return {"items": items, "total": len(items)}


@router.post("/prefixes", status_code=201)
async def create_prefix(
    cidr: str = Form(..., min_length=2),
    site_id: Optional[int] = Form(None),
    parent_id: Optional[int] = Form(None),
    role: Optional[str] = Form(None),
    vlan_id: Optional[str] = Form(None),
    label: Optional[str] = Form(None),
    status: str = Form("allocated"),
    source: str = Form("manual"),
    owner: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    confirm_overlap: bool = Form(False),
    session: SessionEntry = Depends(require_auth),
):
    _, canon = _norm_cidr(cidr)
    if site_id is not None and not registry.get_site(site_id):
        raise HTTPException(404, f"Site {site_id} not found")
    _check_status(status, registry.PREFIX_STATUSES, "status")

    overlaps = registry.find_overlapping_prefixes(canon, site_id=site_id)
    if overlaps and not confirm_overlap:
        descr = ", ".join(f"#{o['id']}({o['cidr']})" for o in overlaps[:5])
        raise HTTPException(409, {
            "detail": f"{canon} overlaps existing prefix(es): {descr}. "
                      "Resubmit with confirm_overlap=true to allow.",
            "overlaps": overlaps,
        })
    try:
        row = registry.create_prefix(
            canon, site_id=site_id, parent_id=parent_id, role=role or None,
            vlan_id=_parse_vlan(vlan_id), label=label or None, status=status,
            source=source, owner=owner or None, description=description or None)
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Prefix already exists for this site: {e}")
    _invalidate_audit()
    return {"prefix": row, "overlaps": overlaps}


@router.put("/prefixes/{prefix_id}")
async def update_prefix(
    prefix_id: int,
    cidr: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    vlan_id: Optional[str] = Form(None),
    label: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
    owner: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    if not registry.get_prefix(prefix_id):
        raise HTTPException(404, f"Prefix {prefix_id} not found")
    _check_status(status, registry.PREFIX_STATUSES, "status")
    canon = None
    if cidr is not None:
        _, canon = _norm_cidr(cidr)
    try:
        row = registry.update_prefix(
            prefix_id, cidr=canon, role=role, vlan_id=_parse_vlan(vlan_id),
            label=label, status=status, owner=owner, description=description)
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Prefix conflict: {e}")
    _invalidate_audit()
    return row


@router.delete("/prefixes/{prefix_id}", status_code=204)
async def delete_prefix(prefix_id: int, session: SessionEntry = Depends(require_auth)):
    if registry.delete_prefix(prefix_id) == 0:
        raise HTTPException(404, f"Prefix {prefix_id} not found")
    _invalidate_audit()
    return None


# ── Audit + bulk accept ────────────────────────────────────────────────────────

def _parse_sources(raw: Optional[str]) -> list[str]:
    if not raw:
        return list(ip_audit.ALL_SOURCES)
    wanted = [s.strip().lower() for s in raw.split(",") if s.strip()]
    return [s for s in ip_audit.ALL_SOURCES if s in wanted] or list(ip_audit.ALL_SOURCES)


@router.get("/audit")
async def audit(
    request: Request,
    sources: Optional[str] = None,
    refresh: bool = False,
    session: SessionEntry = Depends(require_auth),
):
    """Reconcile the registry against the warmed platform caches. Cached briefly
    per source-set; ``?refresh=1`` recomputes. Pass ``?sources=dnac,nexus`` to
    scope which live sources contribute."""
    src = _parse_sources(sources)
    key = "ip_audit:" + ",".join(src)
    if refresh:
        cache.invalidate(key)

    def _loader():
        return ip_audit.run_audit(cache, registry.list_sites(),
                                  registry.list_prefixes(), sources=src)

    report = cache.get_or_set(key, _loader, _AUDIT_TTL)
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_audit_results.html", {"report": report})
    return report


@router.post("/audit/accept")
async def audit_accept(
    items: str = Form(...),
    session: SessionEntry = Depends(require_auth),
):
    """Commit selected drift items into the registry.

    ``items`` is a JSON array of objects, each:
        {"cidr": "...", "site_id": 3}                  # into an existing site
        {"cidr": "...", "site_code": "K099"}           # auto-create the site
    Optional per-item: ``role``, ``family``, ``vlan_id``, ``label``.
    Discovered prefixes are written with source='audit', status='deployed'
    (they were observed live). Already-present prefixes are skipped, not errored.
    """
    try:
        parsed = json.loads(items)
        if not isinstance(parsed, list):
            raise ValueError("expected a JSON array")
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(400, f"Invalid items payload: {e}")

    created, skipped, errors = 0, 0, []
    sites_created: list[str] = []
    for it in parsed:
        cidr = (it.get("cidr") or "").strip()
        if not cidr:
            errors.append({"item": it, "error": "missing cidr"})
            continue
        try:
            fam, _, _, canon = ipam_net.canonical(cidr)
        except ValueError as e:
            errors.append({"item": it, "error": f"bad cidr: {e}"})
            continue

        # Shared aggregate (DMVPN overlay, STIP /48, …) — no owning site.
        if it.get("container"):
            try:
                _, was_new = registry.get_or_create_container(
                    canon, role=it.get("role") or "container",
                    label=it.get("label") or None, source="audit")
            except (ValueError, TypeError) as e:
                errors.append({"item": it, "error": str(e)})
                continue
            created += 1 if was_new else 0
            skipped += 0 if was_new else 1
            continue

        site_id = it.get("site_id")
        if site_id is None and it.get("site_code"):
            site, was_new = registry.upsert_site(str(it["site_code"]).strip().upper())
            site_id = site["id"]
            if was_new:
                sites_created.append(site["site_code"])
        if site_id is None:
            errors.append({"item": it, "error": "no site_id or site_code"})
            continue

        role = it.get("role") or ("site-aggregate" if fam == 4 else "subnet")
        try:
            registry.create_prefix(
                canon, site_id=int(site_id), role=role,
                vlan_id=it.get("vlan_id"), label=it.get("label") or None,
                status="deployed", source="audit", audit_state="in-sync")
            created += 1
        except sqlite3.IntegrityError:
            skipped += 1
        except (ValueError, TypeError) as e:
            errors.append({"item": it, "error": str(e)})

    _invalidate_audit()
    return {"created": created, "skipped": skipped,
            "sites_created": sites_created, "errors": errors}


# ── Export ──────────────────────────────────────────────────────────────────────

@router.get("/export.csv")
async def export_csv(session: SessionEntry = Depends(require_auth)):
    """Flat CSV of every prefix joined to its site. Containers (shared
    aggregates) export with a blank site_code."""
    rows = registry.list_prefixes()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["site_code", "site_name", "family", "cidr", "role", "vlan_id",
                "vvvv", "label", "status", "source", "audit_state",
                "last_seen_at", "last_seen_source", "owner", "description"])
    for r in rows:
        w.writerow([
            r.get("site_code") or "", r.get("site_name") or "", r["family"],
            r["cidr"], r.get("role") or "", r.get("vlan_id") or "",
            r.get("vvvv") or "", r.get("label") or "", r["status"], r["source"],
            r.get("audit_state") or "", r.get("last_seen_at") or "",
            r.get("last_seen_source") or "", r.get("owner") or "",
            r.get("description") or "",
        ])
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=ip_registry.csv"})


# ── TSA tools: vvvv decode / IPv4→IPv6 assemble (compute-only) ───────────────────

def _v6_site_view() -> list[dict]:
    """Shape the registry's IPv6 prefixes as the {id,name,prefix,prefix_length}
    dicts the vvvv assembler expects. ``network`` (leading hextets) doubles as
    the assembler's ``prefix`` input."""
    view = []
    for p in registry.list_prefixes(family=6):
        if p.get("site_id") is None and p.get("role") == "container":
            continue
        view.append({
            "id": p["id"],
            "name": p.get("site_code") or p.get("label") or p["cidr"],
            "prefix": p["network"],
            "prefix_length": p["prefix_length"],
        })
    return view


@router.post("/decode")
async def decode(
    request: Request,
    ipv6_addr: str = Form(..., alias="ipv6", min_length=2, max_length=64),
    session: SessionEntry = Depends(require_auth),
):
    try:
        result = ipv6.decode(ipv6_addr, _v6_site_view())
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Invalid IPv6 address: {e}")
    payload = {
        "site_name": result.site_name, "site_prefix": result.site_prefix,
        "site_prefix_length": result.site_prefix_length, "vvvv": result.vvvv,
        "ipv4": result.ipv4, "canonical": result.canonical,
        "warnings": result.warnings,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_decode_result.html", {"result": payload})
    return payload


@router.post("/assemble")
async def assemble(
    request: Request,
    prefix_id: int = Form(...),
    ipv4: str = Form(..., min_length=7, max_length=18),
    vvvv: Optional[str] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    p = registry.get_prefix(prefix_id)
    if not p or p["family"] != 6:
        raise HTTPException(404, f"IPv6 prefix {prefix_id} not found")
    if p["prefix_length"] >= 64:
        raise HTTPException(400, f"Prefix {p['cidr']} is /{p['prefix_length']} — "
                                 "too specific to assemble a host under.")
    vvvv_value = (vvvv or "").strip() or (p.get("vvvv") or "0")
    try:
        addr = ipv6.assemble(p["network"], vvvv_value, ipv4,
                             site_prefix_length=int(p["prefix_length"]))
    except (ipaddress.AddressValueError, ValueError) as e:
        raise HTTPException(400, f"Cannot assemble: {e}")
    payload = {"ipv6": addr.compressed, "ipv6_exploded": addr.exploded,
               "prefix": p, "vvvv": vvvv_value, "ipv4": ipv4}
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_assemble_result.html", {"result": payload})
    return payload
