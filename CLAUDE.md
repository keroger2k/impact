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

**Cache layer** (`cache.py`) is a singleton in-memory TTL cache with disk persistence:
- `devices` and `sites`: 24-hour TTL, pre-warmed at startup (skipped if valid disk cache exists)
- `pan_*` keys (Panorama): device groups, rules, address objects, services — 1-hour TTL
- `ise_*` keys (ISE): all stable list endpoints — 1-hour TTL
- `aci_{fabric_id}_*` keys (ACI): namespaced by fabric ID (e.g., `aci_dc1_nodes`); 1-hour for static lists, 5-minute for operational data (interfaces, BGP RIB)
- System status checks (`status_*`): 5-minute TTL, memory-only
- Persistent keys survive server restarts — written as JSON to `data/cache/` (gitignored)
- `cache.keys_for_prefix(prefix)` scans both memory and disk; `cache.invalidate_prefix(prefix)` clears both

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

## CLI Mode

The `collectors/` directory contains Netmiko-based SSH collectors (`nxos.py`, `paloalto.py`) for a secondary CLI workflow that reads `devices.txt` and outputs interface inventory to terminal and CSV. This is separate from the web API and uses `utils/loader.py` and `utils/output.py`.
