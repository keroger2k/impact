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

import asyncio
import csv
import io
import ipaddress
import json
import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from auth import SessionEntry, require_auth
from cache import cache
from clients import ip_registry as registry
from logger_config import run_with_context
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


@router.get("/containers")
async def list_containers(request: Request, session: SessionEntry = Depends(require_auth)):
    """Shared aggregates — prefixes with no owning site (DMVPN overlays, STIP
    /48s, org/regional supernets). Each is annotated with the distinct child
    sites whose registered blocks fall **within** it.

    Child sites are attributed by CIDR *containment*, not the stored
    ``parent_id`` — most rows (seeded/imported, or accepted before parent
    linkage existed) have no ``parent_id``, so a link-only rollup would show
    almost nothing. A STIP /48 therefore lists every site whose /64 carves out
    of it. DMVPN overlays still show none here: sites don't register a prefix
    inside the shared tunnel subnet, so registry containment can't see
    participation (it's known only live, in the Audit)."""
    all_prefixes = registry.list_prefixes()
    site_prefixes = [p for p in all_prefixes
                     if p["site_id"] is not None and p.get("site_code")]

    def _contained(outer: str, inner: str) -> bool:
        try:
            return ipam_net.contains(outer, inner)
        except ValueError:
            return False

    items = []
    for c in (p for p in all_prefixes if p["site_id"] is None):
        # Sites whose registered blocks fall inside this aggregate…
        child_sites = {
            sp["site_code"] for sp in site_prefixes
            if sp["family"] == c["family"] and _contained(c["cidr"], sp["cidr"])
        }
        # …plus persisted DMVPN participants (sites don't register a prefix in
        # the overlay subnet, so containment alone can't see them).
        child_sites |= {s for s in (c.get("participants") or "").split(",") if s}
        child_sites = sorted(child_sites)
        items.append({
            **c,
            "child_count": len(child_sites),
            "child_sites": child_sites,
        })
    items.sort(key=lambda x: (x["family"], x.get("role") or "", x["cidr"]))
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/registry_containers_table.html", {"items": items})
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


def _render_audit_html(report: dict) -> str:
    """Render the audit results partial to a string for embedding in an SSE
    event (no Request needed — the partial only consumes ``report``)."""
    return templates.get_template("partials/registry_audit_results.html").render(report=report)


@router.get("/audit/stream")
async def audit_stream(
    request: Request,
    sources: Optional[str] = None,
    refresh: bool = False,
    session: SessionEntry = Depends(require_auth),
):
    """SSE variant of ``/audit`` that streams progress while reconciling.

    The reconciliation is CPU-bound (it can run for minutes on a large estate),
    so a plain request just spins a spinner with no feedback. This runs the audit
    on a worker thread and emits ``data:`` events as each phase advances —
    ``{"type":"progress", ...}`` ticks, then a terminal ``{"type":"done","html":…}``
    carrying the rendered results partial (or ``{"type":"error"}``).

    A cached report (same source-set, not ``refresh``) is returned immediately as a
    single ``done`` event. The frontend swaps ``html`` straight into the pane."""
    src = _parse_sources(sources)
    key = "ip_audit:" + ",".join(src)
    cached = None if refresh else cache.get(key)
    loop = asyncio.get_event_loop()

    async def generate():
        def sse(payload: dict) -> str:
            return f"data: {json.dumps(payload)}\n\n"

        if cached is not None:
            yield sse({"type": "done", "cached": True, "html": _render_audit_html(cached)})
            return

        aq: asyncio.Queue = asyncio.Queue()
        _END = object()

        def push(item):
            # progress callback fires on the worker thread → hop back to the loop
            loop.call_soon_threadsafe(aq.put_nowait, item)

        def work():
            try:
                report = ip_audit.run_audit(
                    cache, registry.list_sites(), registry.list_prefixes(),
                    sources=src, progress=lambda ev: push(("progress", ev)))
                cache.set(key, report, _AUDIT_TTL)
                push(("done", report))
            except Exception as e:  # pragma: no cover - defensive
                logger.exception("audit stream failed")
                push(("error", str(e)))
            finally:
                push((_END, None))

        loop.run_in_executor(None, run_with_context(work))
        yield sse({"type": "progress", "phase": "start", "message": "Starting audit…"})
        while True:
            kind, payload = await aq.get()
            if kind is _END:
                break
            if kind == "progress":
                yield sse({"type": "progress", **payload})
            elif kind == "done":
                yield sse({"type": "done", "html": _render_audit_html(payload)})
            elif kind == "error":
                yield sse({"type": "error", "message": str(payload)})

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@router.post("/audit/accept")
async def audit_accept(
    items: str = Form(...),
    session: SessionEntry = Depends(require_auth),
):
    """Commit selected drift items into the registry.

    ``items`` is a JSON array of objects, each:
        {"cidr": "...", "site_id": 3}                  # into an existing site
        {"cidr": "...", "site_code": "K099"}           # auto-create the site
        {"cidr": "...", "container": true}             # shared aggregate
    Optional per-item: ``role``, ``vlan_id``, ``label``.
    Discovered prefixes are written with source='audit', status='deployed'
    (they were observed live) and linked to their enclosing parent. The whole
    batch commits in one transaction; already-present items are skipped, not
    errored. NOTE: accept intentionally bypasses the soft overlap check that the
    manual POST /prefixes path applies — you are recording observed reality.
    """
    try:
        parsed = json.loads(items)
        if not isinstance(parsed, list):
            raise ValueError("expected a JSON array")
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(400, f"Invalid items payload: {e}")

    result = registry.bulk_accept(parsed)
    _invalidate_audit()
    return result


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
    # Default vvvv must carry the site's fixed 4th-hextet bits. assemble() keeps
    # only the top 48 bits of the prefix and writes the full 16-bit vvvv into
    # hextet 4 — so for a non-/48 site (e.g. a /56 at …:1200::) a "0" default
    # would zero those bits and emit an address *outside* the site's own prefix.
    # site_vvvv_fixed_value is 0 for /48, so this is a no-op there.
    fixed = ipv6.site_vvvv_fixed_value(p["network"], int(p["prefix_length"]))
    vvvv_value = (vvvv or "").strip() or (p.get("vvvv") or "").strip() or f"{fixed:04x}"
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


_IPV4_SPLIT_CHARS = (",", ";", "\t")


def _split_ipv4_list(raw: str) -> list[str]:
    """Tolerant parser: accepts newlines, commas, semicolons, tabs, whitespace.
    Strips '# comments', drops blanks, dedupes preserving first-seen order."""
    tokens: list[str] = []
    for line in raw.splitlines():
        clean = line.split("#", 1)[0]
        for ch in _IPV4_SPLIT_CHARS:
            clean = clean.replace(ch, " ")
        tokens.extend(tok.strip() for tok in clean.split())
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _hextet4(network: str) -> str:
    """The 4th hextet of an IPv6 leading-hextets string — the vvvv of a /64
    carved under a site. Falls back through ipaddress for short forms."""
    return ipaddress.IPv6Address(f"{network.rstrip(':')}::").exploded.split(":")[3]


@router.post("/assemble/bulk")
async def assemble_bulk(
    request: Request,
    prefix_id: int = Form(...),
    ipv4_list: str = Form(..., min_length=1),
    session: SessionEntry = Depends(require_auth),
):
    """Assemble many IPv4 hosts under a site's IPv6 prefix in one shot.

    Unlike the single tool, the vvvv is resolved *per host* from the registry
    rather than typed: the host is matched to the site's most-specific IPv4
    prefix that carries a VLAN, then to the site's IPv6 /64 carrying that same
    VLAN (whose 4th hextet is the vvvv). Hosts with no VLAN linkage are reported
    'no match' rather than guessed. VLAN tags on both families are populated by
    audit-accept of SVIs.
    """
    p = registry.get_prefix(prefix_id)
    if not p or p["family"] != 6:
        raise HTTPException(404, f"IPv6 prefix {prefix_id} not found")
    if p["prefix_length"] >= 64:
        raise HTTPException(400, f"Prefix {p['cidr']} is /{p['prefix_length']} — "
                                 "too specific to assemble hosts under.")
    site_id = p.get("site_id")
    if site_id is None:
        raise HTTPException(400, "Bulk assemble needs a site-owned IPv6 prefix so "
                                 "VLANs can be resolved; this prefix has no site.")

    # host → VLAN: the site's VLAN-tagged IPv4 prefixes (longest match wins).
    v4_nets: list[tuple[ipaddress.IPv4Network, int]] = []
    for q in registry.list_prefixes(site_id=site_id, family=4):
        if q.get("vlan_id") is None:
            continue
        try:
            v4_nets.append((ipaddress.IPv4Network(q["cidr"], strict=False), int(q["vlan_id"])))
        except (ValueError, TypeError):
            continue

    # VLAN → vvvv: the site's /64s carrying a VLAN.
    vlan_to_v6: dict[int, dict] = {}
    for q in registry.list_prefixes(site_id=site_id, family=6):
        if q.get("vlan_id") is None or q["prefix_length"] < 64:
            continue
        vlan_to_v6.setdefault(int(q["vlan_id"]), q)

    site_label = p.get("site_code") or p.get("label") or p["cidr"]
    rows: list[dict] = []
    counts = {"ok": 0, "no_match": 0, "invalid": 0}

    for raw in _split_ipv4_list(ipv4_list):
        row = {"site_code": site_label, "ipv4": raw, "ipv6": "", "vvvv": "",
               "vlan": "", "matched_subnet": "", "status": "", "detail": ""}
        try:
            host = ipaddress.IPv4Address(raw)
        except (ipaddress.AddressValueError, ValueError) as e:
            row["status"], row["detail"] = "invalid", str(e)
            counts["invalid"] += 1
            rows.append(row)
            continue

        best: tuple[int, ipaddress.IPv4Network, int] | None = None
        for net, vlan in v4_nets:
            if host in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, net, vlan)
        if best is None:
            row["status"] = "no_match"
            row["detail"] = "no VLAN-tagged IPv4 prefix in this site covers the host"
            counts["no_match"] += 1
            rows.append(row)
            continue

        vlan = best[2]
        row["vlan"], row["matched_subnet"] = vlan, str(best[1])
        v6_child = vlan_to_v6.get(vlan)
        if v6_child is None:
            row["status"] = "no_match"
            row["detail"] = f"no IPv6 /64 in this site carries VLAN {vlan}"
            counts["no_match"] += 1
            rows.append(row)
            continue

        vvvv = v6_child.get("vvvv") or _hextet4(v6_child["network"])
        try:
            addr = ipv6.assemble(p["network"], vvvv, raw,
                                 site_prefix_length=int(p["prefix_length"]))
        except (ipaddress.AddressValueError, ValueError) as e:
            row["status"], row["detail"] = "invalid", str(e)
            counts["invalid"] += 1
            rows.append(row)
            continue

        row.update({"status": "ok", "ipv6": addr.compressed,
                    "vvvv": ipv6.normalize_vvvv(vvvv)})
        counts["ok"] += 1
        rows.append(row)

    payload = {
        "prefix": {"id": p["id"], "cidr": p["cidr"], "site_code": p.get("site_code"),
                   "network": p["network"], "prefix_length": p["prefix_length"]},
        "rows": rows, "counts": counts, "total": len(rows),
    }
    if request.headers.get("HX-Request"):
        # TSV body for the copy-paste textarea: site, ipv4, ipv6 (ok rows only).
        payload["tsv"] = "\n".join(
            f"{r['site_code']}\t{r['ipv4']}\t{r['ipv6']}"
            for r in rows if r["status"] == "ok")
        return templates.TemplateResponse(
            request, "partials/registry_bulk_assemble_result.html", {"result": payload})
    return payload
