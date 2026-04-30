# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

IMPACT II is a **TSA Network Operations Platform** — a unified web dashboard for three network infrastructure systems:
- **Cisco Catalyst Center (DNA Center)** — device inventory, topology, discovery
- **Cisco ISE** — network access, endpoint management, authentication policies
- **Palo Alto Panorama** — firewall security policies
- **Cisco ACI** — multi-fabric SDN (leaf/spine), BGP visibility, port-level detail

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and fill in environment variables
cp .env.template .env

# Run development server (auto-reload)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Run production server
uvicorn main:app --host 0.0.0.0 --port 8000
```

No test framework or linter is configured. No CSS build step is required — the project uses Bootstrap v5 (vendored at `static/bootstrap/`) with custom overrides in `static/app.css`.

## Architecture

The app is structured in three layers:

**Client layer** (`clients/`) wraps vendor SDKs and APIs:
- `clients/dnac.py` — wraps `dnacentersdk`; handles pagination, config fetching, IP lookup
- `clients/ise.py` — wraps `ciscoisesdk`; custom URL-based query builder for ERS + OpenAPI endpoints
- `clients/panorama.py` — direct XML API via `requests`; generates API keys, parses security policies
- `clients/aci.py` — direct REST API wrapper for APIC; handles login tokens and tree queries
- `clients/aci_registry.py` — singleton registry managing multi-fabric configurations from environment variables

**Cache layer** (`cache.py`) is a singleton TTL cache backed by `diskcache` (SQLite at `data/cache/diskcache/cache.db`); persists across restarts.

Default TTLs are defined as constants in `cache.py:21-30` and each is overridable via an `IMPACT_TTL_*` env var:

| Constant | Default | Env override | Used by |
|---|---|---|---|
| `TTL_DEFAULT` | 48h | `IMPACT_TTL_DEFAULT` | fallback for `cache.set(...)` with no TTL |
| `TTL_DEVICES` | 4h | `IMPACT_TTL_DEVICES` | DNAC `devices` cache |
| `TTL_SITES` | 4h | `IMPACT_TTL_SITES` | DNAC `sites`, `device_site_map` |
| `TTL_ISE_POLICIES` | 1h | `IMPACT_TTL_ISE_POLICIES` | all ISE stable lists (NADs, SGTs, policy sets, auth rules per policy set, etc.) |
| `TTL_ACI_STATUS` | 15m | `IMPACT_TTL_ACI_STATUS` | every ACI call going through `_cached(...)` with no explicit TTL — nodes, L3Outs, BGP/OSPF peers, BGP DOMs, BGP capability probes, BGP/OSPF maps |
| `TTL_ACI_ROUTE_TABLE` | 5m | `IMPACT_TTL_ACI_ROUTE_TABLE` | per-L3Out route table (`/api/aci/l3outs/route-table`) |
| `TTL_STATUS` | 5m | `IMPACT_TTL_STATUS` | system connectivity probes (`status_dnac`, `status_ise`, `status_panorama`) |
| `TTL_PAN_INTERFACES` | 48h | `IMPACT_TTL_PAN_INTERFACES` | Panorama firewall interface inventory (`pan_interfaces`) |
| `TTL_PAN_POLICY` | 1h | `IMPACT_TTL_PAN_POLICY` | Panorama policy/inventory data: `pan_rules`, `pan_device_groups`, `pan_managed_devices`, `pan_addr`, `pan_svc` (re-exported as `PAN_TTL` from `routers/firewall.py`) |
| `TTL_DNAC_INTERFACES` | 4h | `IMPACT_TTL_DNAC_INTERFACES` | DNAC per-device interface inventory |

Naming conventions for cache keys:
- `devices` / `sites` / `device_site_map` — DNAC top-level, pre-warmed at startup
- `pan_*` — Panorama (rules, device_groups, address_objects, services, interfaces, firewalls)
- `ise_*` — ISE (stable lists, plus `ise_auth_rules_{policy_set_id}` per policy set)
- `aci_{fabric_id}_{suffix}` — ACI, namespaced per fabric (`_fkey(fabric_id, suffix)` in `routers/aci.py`). Per-L3Out route-table entries are stored under `aci_{fabric_id}_l3out_route_table:{quoted_dn}`.
- `status_*` — system connectivity probes

Other notes:
- **Stale-while-revalidate**: physical disk retention is 30 days regardless of logical TTL — if a loader fails on a logically-expired key, `get_or_set` returns the stale value rather than `None`.
- **Helpers**: `cache.keys_for_prefix(prefix)` and `cache.invalidate_prefix(prefix)` scan all keys.
- **DEV_MODE**: `dev.seed_cache(cache)` runs on every startup when `DEV_MODE=true`, *unconditionally overwriting* every mock key with a 1-year TTL. Real cached data is replaced by mock fixtures on every dev restart — this is intentional for deterministic dev sessions.

**Router layer** (`routers/`) contains FastAPI request handlers:
- `routers/dnac.py` — 9 endpoints under `/api/dnac/` including `GET /cache/info`
- `routers/ise.py` — 19 endpoints under `/api/ise/` including `GET /cache/info` and `POST /cache/refresh`
- `routers/firewall.py` — 4 endpoints under `/api/firewall/` including `GET /cache/info` and `POST /cache/refresh`
- `routers/aci.py` — 17 endpoints under `/api/aci/` including multi-fabric aggregation (`?fabric=all`), node interface drill-down, and BGP diagnostics
- `routers/commands.py` — SSH command execution streamed via SSE (`/api/commands/run`)
- `routers/import_.py` — device discovery workflow streamed via SSE (`/api/import/run`)

**Frontend** (`static/`) is a vanilla JS SPA with hash-based routing (`#/dashboard`, `#/devices`, etc.). All logic is in `static/app.js` (~1900 lines).

CSS uses **Bootstrap v5** (vendored, no CDN dependency) with a custom override layer:
- `static/bootstrap/css/bootstrap.min.css` — Bootstrap v5 base (do not edit)
- `static/bootstrap/js/bootstrap.bundle.min.js` — Bootstrap JS + Popper (do not edit)
- `static/app.css` — all custom styles; loaded after Bootstrap so it overrides freely. Contains `:root` CSS variables (Cisco color tokens), layout shell (`#sidebar`, `#main`, `#topbar`), sidebar/nav, table overrides, component classes (`.btn`, `.card`, `.kpi-card`, `.badge`, `.modal`, `.tabs`, etc.), keyframe animations, and code block dark theme.

### Key Patterns

- **Blocking SDK calls** run in a `ThreadPoolExecutor` via `asyncio.get_event_loop().run_in_executor(...)` to avoid blocking async handlers.
- **SSE streaming** is used for long-running operations (command execution, device import). The router yields `data: ...\n\n` chunks; the frontend uses `EventSource`.
- **SSL verification is disabled** across all clients — the infrastructure uses self-signed certificates.
- **All credentials** come from environment variables (`.env`). No credentials in request payloads.
- **ISE stable-list caching**: `routers/ise.py` has a `_cached(key, loader, ttl)` helper that wraps any synchronous loader. All stable list endpoints (NADs, endpoint groups, SGTs, policy sets, etc.) go through it. Auth rules are cached per policy set ID as `ise_auth_rules_{id}`.
- **Panorama rule structure**: `pan_rules` cache key holds `{"dg_order": [...], "by_dg": {dg_name: [rules]}}` for all device groups. `_flatten_rules(rules_cache, target_dgs)` reconstructs policy evaluation order (shared pre → DG pre → DG post → shared post) and filters to requested DGs at query time.
- **Cache UI**: `fmtAge(ts)` and `initCacheBar(barEl, infoUrl, refreshUrl, onRefresh)` in `app.js` drive the "Cached X ago ↻ Refresh" bars shown in the Devices, ISE, and Firewall sections.

## Environment Variables

See `.env.template`. Required vars:
- `DOMAIN_USERNAME` / `DOMAIN_PASSWORD` — shared AD credentials used by all three clients
- `DNA_CENTER_BASE_URL`, `DNA_CENTER_VERSION` — Catalyst Center
- `ISE_HOST` — Cisco ISE hostname
- `PANORAMA_HOST` — Palo Alto Panorama hostname
- `ACI_FABRICS` — Comma-separated fabric IDs (e.g., `dc1,dc2`)
- `ACI_{ID}_URL` / `ACI_{ID}_DOMAIN` / `ACI_{ID}_LABEL` — per-fabric settings

Optional cache TTL overrides (seconds — see the Cache layer table above for defaults and which keys each one governs): `IMPACT_TTL_DEFAULT`, `IMPACT_TTL_DEVICES`, `IMPACT_TTL_SITES`, `IMPACT_TTL_ISE_POLICIES`, `IMPACT_TTL_ACI_STATUS`, `IMPACT_TTL_ACI_ROUTE_TABLE`, `IMPACT_TTL_STATUS`, `IMPACT_TTL_PAN_INTERFACES`, `IMPACT_TTL_PAN_POLICY`, `IMPACT_TTL_DNAC_INTERFACES`.

Other optional vars:
- `DEV_MODE` — when `true`, seeds mock fixtures into cache on every startup (deterministic dev mode). Disables LDAP and APIC/DNAC/ISE/Panorama calls.
- `IMPACT_VERIFY_SSL` — defaults to `false` (the infrastructure uses self-signed certs). Set `true` to enforce verification.

## CLI Mode

The `collectors/` directory contains Netmiko-based SSH collectors (`nxos.py`, `paloalto.py`) for a secondary CLI workflow that reads `devices.txt` and outputs interface inventory to terminal and CSV. This is separate from the web API and uses `utils/loader.py` and `utils/output.py`.
