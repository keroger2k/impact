# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

IMPACT II is a **TSA Network Operations Platform** — a unified web dashboard for three network infrastructure systems:
- **Cisco Catalyst Center (DNA Center)** — device inventory, topology, discovery
- **Cisco ISE** — network access, endpoint management, authentication policies
- **Palo Alto Panorama** — firewall security policies

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

No test framework or linter is configured. The frontend has no build step — edit `static/` files directly.

## Architecture

The app is structured in three layers:

**Client layer** (`clients/`) wraps vendor SDKs and APIs:
- `clients/dnac.py` — wraps `dnacentersdk`; handles pagination, config fetching, IP lookup
- `clients/ise.py` — wraps `ciscoisesdk`; custom URL-based query builder for ERS + OpenAPI endpoints
- `clients/panorama.py` — direct XML API via `requests`; generates API keys, parses security policies

**Cache layer** (`cache.py`) is a singleton in-memory TTL cache:
- Devices/sites: 1-hour TTL; system status: 5-minute TTL
- Pre-warmed at startup via the FastAPI lifespan context manager in `main.py`
- All routers import and use the singleton `cache` instance

**Router layer** (`routers/`) contains FastAPI request handlers that call clients through the cache:
- `routers/dnac.py` — 8 endpoints under `/api/dnac/`
- `routers/ise.py` — 14 endpoints under `/api/ise/`
- `routers/firewall.py` — 3 endpoints under `/api/firewall/`
- `routers/commands.py` — SSH command execution streamed via SSE (`/api/commands/run`)
- `routers/import_.py` — device discovery workflow streamed via SSE (`/api/import/run`)

**Frontend** (`static/`) is a vanilla JS SPA with hash-based routing (`#/dashboard`, `#/devices`, etc.). All logic is in `static/app.js` (~1900 lines). No framework, no build step.

### Key Patterns

- **Blocking SDK calls** run in a `ThreadPoolExecutor` via `asyncio.get_event_loop().run_in_executor(...)` to avoid blocking async handlers.
- **SSE streaming** is used for long-running operations (command execution, device import). The router yields `data: ...\n\n` chunks; the frontend uses `EventSource`.
- **SSL verification is disabled** across all clients — the infrastructure uses self-signed certificates.
- **All credentials** come from environment variables (`.env`). No credentials in request payloads.

## Environment Variables

See `.env.template`. Required vars:
- `DOMAIN_USERNAME` / `DOMAIN_PASSWORD` — shared AD credentials used by all three clients
- `DNA_CENTER_BASE_URL`, `DNA_CENTER_VERSION` — Catalyst Center
- `ISE_HOST` — Cisco ISE hostname
- `PANORAMA_HOST` — Palo Alto Panorama hostname

## CLI Mode

The `collectors/` directory contains Netmiko-based SSH collectors (`nxos.py`, `paloalto.py`) for a secondary CLI workflow that reads `devices.txt` and outputs interface inventory to terminal and CSV. This is separate from the web API and uses `utils/loader.py` and `utils/output.py`.
