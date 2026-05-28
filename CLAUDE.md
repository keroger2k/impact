# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

IMPACT II is a **TSA Network Operations Platform** — a unified web dashboard for the following network infrastructure systems:
- **Cisco Catalyst Center (DNA Center)** — device inventory, sites, config search, IP lookup, path trace, device tagging
- **Cisco ISE** — NADs, endpoints, sessions, users, SGTs/SGACLs/egress matrix, policy sets, auth/authz rules, deployment nodes
- **Palo Alto Panorama** — firewall device groups, security policies, address/service objects, interface inventory
- **Cisco ACI** — multi-fabric SDN (leaf/spine); nodes, interfaces, tenants/VRFs/BDs/EPGs/contracts, L3Outs, BGP/OSPF maps and peers, route tables, access policies, health, faults
- **Cisco Nexus** — SSH-based collection (Netmiko) of inventory, interfaces, VLANs, port-channels, vPCs
- **IPAM** — DNAC-sourced address pools rendered as an aggregated tree with stats and export
- **VPN Tunnels** — enterprise IPsec tunnel inventory; normalizes IOS (DMVPN, sVTI, dVTI, policy-based) + Palo IPsec from cached DNAC running-configs and Panorama IKE/IPsec objects, plus live counters
- **IPv6 Registry** — hierarchical IPv4-to-IPv6 allocation registry; per-site prefixes (/32–/64) carry vvvv-style sub-allocations whose high bits conform to the parent site's mask (full 16-bit vvvv space at /48; narrower windows at /56, /60, …). CRUD UI with searchable site picker, two-way decode/assemble, bulk-assemble, CSV export, one-click "Provision Standard Site" for the /56 + 6-VLAN fleet build pattern. Local SQLite — not derived from any upstream system

The dashboard is mostly read-only. Mutating actions: the **Command Runner** (gated by `COMMANDS_ENABLED`), the **Device Import** workflow, and the **IPv6 Registry** (its writes are local-only to the SQLite registry, not pushed to any platform).

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

# Run tests
pytest tests/
```

Tests live in `tests/` and use `pytest` + `pytest-asyncio` (declared in `requirements.txt`). No linter is configured. No CSS build step is required — the project uses Bootstrap v5 (vendored at `static/bootstrap/`) with custom overrides in `static/app.css`.

## Architecture

The app is structured in three layers:

**Client layer** (`clients/`) wraps vendor SDKs and APIs:
- `clients/dnac.py` — wraps `dnacentersdk`; pagination, config fetching, IP lookup, path trace, global IP pools, tagging
- `clients/ise.py` — wraps `ciscoisesdk`; custom URL-based query builder for ERS + OpenAPI endpoints, plus MNT XML for sessions/auth events
- `clients/panorama.py` — direct XML API via `requests`; generates API keys, parses security policies and rules
- `clients/aci.py` — direct REST API wrapper for APIC; handles login tokens, class queries, and DN tree queries
- `clients/aci_registry.py` — singleton registry managing multi-fabric configurations from environment variables

Nexus collection lives in `collectors/nxos.py` (Netmiko SSH) rather than `clients/`, since it is interactive CLI-driven rather than API-driven.

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
| `TTL_CONFIG_SEARCH_RESULT` | 5m | `IMPACT_TTL_CONFIG_SEARCH_RESULT` | DNAC `dnac_config_search_result:*` — cached search results so the CSV download endpoint doesn't re-run the search |
| `TTL_DNAC_ROUTER_CONFIGS` | 24h | `IMPACT_TTL_DNAC_ROUTER_CONFIGS` | DNAC running-config snapshots used by routing diagnostics |
| `TTL_DNAC_IP_POOLS` | 24h | `IMPACT_TTL_DNAC_IP_POOLS` | DNAC global IP pools + reserve subpools (IPAM source data) |
| `TTL_TUNNEL_INVENTORY` | 24h | `IMPACT_TTL_TUNNEL_INVENTORY` | normalized tunnel inventory (`tunnel_inventory_v1` — bump the key version on a structural change) |

The IPAM tree is cached under a fixed, versioned key (`IPAM_TREE_CACHE_KEY = "ipam_tree_v4"` in `cache.py`) — bump the suffix to invalidate the tree shape on a structural change rather than relying on TTL.

Naming conventions for cache keys:
- `devices` / `sites` / `device_site_map` — DNAC top-level, pre-warmed at startup
- `dnac_config_search_result:{sha256}` — cached config-search results, keyed by hash of the request payload (excluding `context_lines` / `max_devices`)
- `pan_*` — Panorama (rules, device_groups, address_objects, services, interfaces, firewalls)
- `ise_*` — ISE (stable lists, plus `ise_auth_rules_{policy_set_id}` per policy set)
- `aci_{fabric_id}_{suffix}` — ACI, namespaced per fabric (`_fkey(fabric_id, suffix)` in `routers/aci.py`). Per-L3Out route-table entries are stored under `aci_{fabric_id}_l3out_route_table:{quoted_dn}`.
- `tunnel_inventory_v1` — normalized IPsec tunnel inventory (versioned key; bump suffix on schema change). Live counters are fetched on-demand, not cached.
- `status_*` — system connectivity probes

Other notes:
- **Stale-while-revalidate**: physical disk retention is 30 days regardless of logical TTL — if a loader fails on a logically-expired key, `get_or_set` returns the stale value rather than `None`.
- **Helpers**: `cache.keys_for_prefix(prefix)` and `cache.invalidate_prefix(prefix)` scan all keys.
- **DEV_MODE**: `dev.seed_cache(cache)` runs on every startup when `DEV_MODE=true`, *unconditionally overwriting* every mock key with a 1-year TTL. Real cached data is replaced by mock fixtures on every dev restart — this is intentional for deterministic dev sessions.

**Registry layer** (separate from the cache): `clients/ipv6_registry.py` is a thin `sqlite3` wrapper over `data/ipv6_registry.db` for the IPv6 hierarchical allocation registry. Two tables (`sites`, `allocations`) with FK cascade and `UNIQUE(site_id, vvvv)`. No ORM. Schema bootstrap runs from `main.py`'s `lifespan` via `ipv6_registry.init_schema()`. Use this pattern — *not* diskcache — for any future feature that needs durable user-edited rows with relational integrity. diskcache stays for ephemeral, TTL'd platform reads.

**Router layer** (`routers/`) contains FastAPI request handlers. All API routers are wired in `main.py` behind `require_auth`; `pages.py` is the only public router (it serves the login page itself).

- `routers/dnac.py` — `/api/dnac/`: devices (list/stats/detail/config/select-partial), sites, ip-lookup (JSON + UI partial), config-search (JSON + UI + CSV download), path-trace (UI + result partial), tag-devices, cache info/refresh
- `routers/ise.py` — `/api/ise/`: NADs, device-groups, endpoints, endpoint-groups, sessions (active/history/recent), identity-groups, users, SGTs, SGACLs, egress-matrix, policy-sets + per-set auth/authz rules, authz-profiles, allowed-protocols, profiling-policies, deployment-nodes, cache info/refresh
- `routers/firewall.py` — `/api/firewall/`: device-groups, policy lookup, policies by DG, rules export, interfaces (list/refresh/search), devices, templates, cache info/refresh
- `routers/aci.py` — `/api/aci/`: fabrics, fabric/nodes, nodes/{id}/interfaces, L3Outs (list/detail/routes/route-table), BGP map/peers/diagnose, OSPF map/peers, traffic/EPGs, traffic/faults, health/summary, tenants (+detail), VRFs, bridge-domains, app-profiles, EPGs/detail, contracts (+detail), filters, access (policy-groups, AAEPs, domains, VLAN pools, interface policies). All cache keys are namespaced per fabric and most endpoints accept `?fabric=<id>` or `?fabric=all` for cross-fabric aggregation.
- `routers/nexus.py` — `/api/nexus/`: SSH-driven inventory refresh (SSE), inventory, devices (HTML), per-device detail (HTML), interfaces, port-channels, vPCs, VLANs, cache info/refresh
- `routers/routing.py` — `/api/routing/`: BGP summary, EIGRP topology, OSPF neighbors — all driven by parsing cached DNAC running-configs
- `routers/ipam.py` — `/api/ipam/`: refresh (SSE), stats, tree, debug, export
- `routers/tunnels.py` — `/api/tunnels/`: list/detail of normalized IPsec tunnels (DMVPN, sVTI, dVTI, policy-based, Palo IPsec), live counters via SSE refresh. Parsers in `utils/ipsec_parser.py` + `utils/tunnel_inventory.py`; site-code resolution via `utils/site_code.py`.
- `routers/ipv6_registry.py` — `/api/ipv6/`: sites CRUD, allocations CRUD, `/allocations/next` suggestion, `/decode`, `/assemble`, `/assemble/bulk`, `/export.csv`, `/sites/provision-standard` (atomic /56 site + standard VLAN /64s — `STANDARD_VLAN_PRESET` near the top of the file is the source of truth for offsets and labels). Hard 409 on vvvv overlap, soft warn on IPv4-subnet dup (caller can resubmit with `confirm_ipv4_dup=true`). For non-/48 sites the allocator enforces vvvv conformance (high bits must match the site's mask). Reads/writes the SQLite registry — *not* the cache.
- `routers/commands.py` — `/api/commands/run`: SSH command execution streamed via SSE; gated by `COMMANDS_ENABLED`
- `routers/import_.py` — `/api/import/run`: device discovery workflow streamed via SSE
- `routers/cache_mgmt.py` — `/api/cache/`: cross-cutting cache status, sidebar widget, per-category refresh (`POST /api/cache/refresh/{category}`), and global clear (`clear_all`)
- `routers/auth.py` — `/api/auth/`: login, logout, session refresh
- `routers/pages.py` — top-level HTML pages: `/login`, `/dashboard`, `/devices`, `/ise`, `/firewall`, `/aci`, `/nexus`, `/nexus/{hostname}`, `/path-trace`, `/routing/bgp`, `/config-search`, `/ip-lookup`, `/ipam`, `/tunnels`, `/ipv6-registry`, `/command-runner`, `/import`, `/cache-mgmt`

App-level (in `main.py`, not under a router prefix):
- `POST /api/warm` — SSE stream that warms DNAC/ISE/Panorama/ACI/Nexus on demand
- `GET /api/status` — combined connectivity snapshot
- `GET /partials/status` — same data rendered as a Jinja partial (used by the top health bar)

**Frontend** is **htmx + server-rendered Jinja partials**, not a SPA. There is no `static/app.js`. Navigation is driven by `hx-get` on sidebar links targeting `#main-content`, with `hx-push-url="true"` keeping the URL bar in sync. The page shell is `templates/base.html`; full-page routes live in `templates/*.html`, the htmx-swapped page bodies live in `templates/pages/*_content.html`, and reusable fragments live in `templates/partials/*.html`.

JS modules (`static/js/`) are intentionally small:
- `htmx.min.js` — htmx runtime
- `data-table.js` — client-side sort/filter/paginate for tables marked `.data-table`
- `debug-console.js` — in-page debug overlay
- `api.js` / `router.js` / `utils.js` — legacy ES modules retained for a few pages still using the older hash-router pattern; new pages should be htmx + server partials

CSS uses **Bootstrap v5** (vendored, no CDN dependency) with a custom override layer:
- `static/bootstrap/css/bootstrap.min.css` — Bootstrap v5 base (do not edit)
- `static/bootstrap/js/bootstrap.bundle.min.js` — Bootstrap JS + Popper (do not edit)
- `static/app.css` — all custom styles; loaded after Bootstrap so it overrides freely. Contains `:root` CSS variables (Cisco color tokens), layout shell (`#sidebar`, `#main`, `#topbar`), sidebar/nav, table overrides, component classes (`.btn`, `.card`, `.kpi-card`, `.badge`, `.modal`, `.tabs`, etc.), keyframe animations, and code block dark theme.

### Key Patterns

- **Blocking SDK calls** run in a `ThreadPoolExecutor` via `asyncio.get_event_loop().run_in_executor(...)` to avoid blocking async handlers. `logger_config.run_with_context(fn)` is the wrapper that propagates the request correlation ID into the worker thread.
- **Correlation IDs**: every request gets an `X-Correlation-ID` (echoed in the response header and stamped on every log line via `logger_config.set_correlation_id`). Use this to trace a single request across DNAC/ISE/ACI calls in `logs/`.
- **SSE streaming** is used for long-running operations (`/api/warm`, `/api/commands/run`, `/api/commands/config-run`, `/api/import/run`, `/api/ipam/refresh`, `/api/nexus/refresh`, `/api/tunnels/refresh-stream`). Routers yield `data: ...\n\n` chunks; the frontend uses `EventSource`. A middleware in `main.py` caps these to **2 concurrent streams per (session, path)** to prevent runaway tabs.
- **CSRF**: `utils.csrf.CSRFMiddleware` issues a `csrf_token` cookie at login and enforces `X-CSRF-Token` on mutating requests. htmx is wired to forward the cookie via the `htmx:configRequest` listener in `base.html`.
- **Auth & sessions**: cookie-based sessions (`impact_token`) backed by `auth.py`. When `SESSION_PERSIST=true`, sessions are persisted across restarts via `auth_persist.py` using Fernet (key from `SESSION_ENC_KEY`); `auth_module.restore_sessions()` runs on startup and `auth_module.session_gc_task()` reaps expired sessions in the background.
- **SSL verification is disabled** across all clients — the infrastructure uses self-signed certificates. Override with `IMPACT_VERIFY_SSL=true`.
- **All credentials** come from environment variables (`.env`). No credentials in request payloads.
- **ISE stable-list caching**: `routers/ise.py` has a `_cached(key, loader, ttl)` helper that wraps any synchronous loader. All stable list endpoints (NADs, endpoint groups, SGTs, policy sets, etc.) go through it. Auth rules are cached per policy set ID as `ise_auth_rules_{id}`.
- **Panorama: prefer the pan-os-python SDK** over hand-rolled XML. New op-cmd calls must go through `clients.panorama.op_via_sdk(cmd, api_key, target=...)` with a plain CLI string (e.g. `show vpn flow name "foo"`) — let the SDK tokenize and build the XML so we don't ship f-string XML literals that interpolate untrusted names. Only fall back to raw XML (`_op` / `_op_targeted` / `_config_get*`) when the SDK genuinely has no equivalent for what you need (most often xpath-driven `config get` reads). When you do, leave a comment naming the SDK gap.
- **Panorama rule structure**: `pan_rules` cache key holds `{"dg_order": [...], "by_dg": {dg_name: [rules]}}` for all device groups. `_flatten_rules(rules_cache, target_dgs)` reconstructs policy evaluation order (shared pre → DG pre → DG post → shared post) and filters to requested DGs at query time.
- **ACI fabric scoping**: `_fkey(fabric_id, suffix)` in `routers/aci.py` namespaces every cache key. `?fabric=all` triggers per-fabric calls in parallel and merges results; individual fabric IDs route to a single APIC client from `aci_registry`.
- **Cache UI**: the persistent sidebar widget polls `GET /api/cache/widget` every 30s; the Cache Management page (`/cache-mgmt`) lists every category with per-category refresh buttons (`POST /api/cache/refresh/{category}`).
- **Never put real IP addresses in source code.** Tests, docstrings, comments, template placeholders, sample data, fixtures, and example values must use fake addresses only — never real customer/site addressing. Conventions:
  - **IPv4 hosts**: `1.2.3.4`, `5.6.7.8`, or `1.1.1.1` / `2.2.2.2` for distinct examples.
  - **IPv4 subnets**: `1.2.3.0/24`, `1.2.0.0/16`, `5.5.5.0/24`.
  - **IPv6 /48 prefixes**: `1000:2000:3000` (site A), `4000:5000:6000` (site B). Avoid anything resembling a real allocation block (no `2600:…`, `2001:…`, etc.).
  - **Generic edge-case octets** (`0.0.0.1`, `255.255.255.255`, `0.0.0.0`) are fine — they're not site-identifying. Same for vvvv values like `0100`, `0200`, `ffff`.
  - Applies retroactively: if you edit a file that still has stale real-looking IPs in test data or examples, swap them while you're there.

## Environment Variables

See `.env.template`. Required vars:
- `DOMAIN_USERNAME` / `DOMAIN_PASSWORD` — shared AD credentials used by all platform clients
- `AD_LDAP_URL` — must use `ldaps://` in non-dev mode (enforced at startup)
- `AD_DOMAIN` — AD domain used for login
- `DNA_CENTER_BASE_URL`, `DNA_CENTER_VERSION` — Catalyst Center
- `ISE_HOST` — Cisco ISE hostname
- `PANORAMA_HOST` — Palo Alto Panorama hostname
- `ACI_FABRICS` — Comma-separated fabric IDs (e.g., `dc1,dc2,dc3`)
- `ACI_{ID}_URL` / `ACI_{ID}_DOMAIN` / `ACI_{ID}_LABEL` — per-fabric settings

Optional cache TTL overrides (seconds — see the Cache layer table above for defaults and which keys each one governs): `IMPACT_TTL_DEFAULT`, `IMPACT_TTL_DEVICES`, `IMPACT_TTL_SITES`, `IMPACT_TTL_ISE_POLICIES`, `IMPACT_TTL_ACI_STATUS`, `IMPACT_TTL_ACI_ROUTE_TABLE`, `IMPACT_TTL_STATUS`, `IMPACT_TTL_PAN_INTERFACES`, `IMPACT_TTL_PAN_POLICY`, `IMPACT_TTL_DNAC_INTERFACES`, `IMPACT_TTL_CONFIG_SEARCH_RESULT`, `IMPACT_TTL_DNAC_ROUTER_CONFIGS`, `IMPACT_TTL_DNAC_IP_POOLS`.

Other optional vars:
- `DEV_MODE` — when `true`, seeds mock fixtures into cache on every startup (deterministic dev mode). Disables LDAP and APIC/DNAC/ISE/Panorama calls. Also enables `/api/docs`, `/api/redoc`, and `/openapi.json`.
- `IMPACT_VERIFY_SSL` — defaults to `false` (the infrastructure uses self-signed certs). Set `true` to enforce verification.
- `SESSION_TTL_HOURS` — session lifetime (default 8h)
- `SESSION_PERSIST` — when `true`, sessions are encrypted at rest and survive restarts
- `SESSION_ENC_KEY` — Fernet key for `SESSION_PERSIST` (generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
- `COMMANDS_ENABLED` — when `true`, exposes the ad-hoc SSH command runner UI and `/api/commands/run` endpoint
- `IMPACT_ALLOWED_ORIGINS` — comma-separated CORS origins (empty by default = no cross-origin)

## CLI Mode

The `collectors/` directory contains Netmiko-based SSH collectors (`nxos.py`, `paloalto.py`) for a secondary CLI workflow that reads `devices.txt` and outputs interface inventory to terminal and CSV. This is separate from the web API and uses `utils/loader.py` and `utils/output.py`. `collectors/nxos.py` is *also* used by `routers/nexus.py` for the in-app Nexus Insights page.

## Utility scripts

The `scripts/` directory holds standalone admin/maintenance utilities — invoke as modules from the repo root so project imports resolve:

- `scripts/import_ipv6_sites.py` — bulk-load IPv6 registry sites from a CSV (`<name>,<prefix>[,<prefix_length>[,<role>[,<description>]]]`). `prefix_length` defaults to 48; quoted fields supported for descriptions with commas. Dry-run by default; `--apply` to commit. Skips name/prefix conflicts (both vs. the DB and within the same file).
  ```bash
  .venv/bin/python -m scripts.import_ipv6_sites                   # dry-run, default file
  .venv/bin/python -m scripts.import_ipv6_sites --apply           # commit
  ```
- `scripts/import_ipv6_allocations.py` — bulk-load IPv6 allocations from a flat file (`<site>,<ipv4_subnet>,<ipv4_mask>,<vvvv>[,<prefix_length>]`). Defaults to `/64`, dry-run by default; `--apply` to commit; `--skip-ipv4-dup` to skip the soft-warn rows. Talks to SQLite directly via `clients.ipv6_registry` (no HTTP/CSRF). Sites must already exist; any prefix length < 64 is accepted, but vvvv values must conform to the site's mask (e.g. a /56 site at `2600:400:3028:2d00` only accepts vvvvs in `2d00..2dff`).
  ```bash
  .venv/bin/python -m scripts.import_ipv6_allocations              # dry-run, default file
  .venv/bin/python -m scripts.import_ipv6_allocations --apply      # commit
  ```
- `scripts/import_ipv6_stip_allocations.py` — bulk-load per-site STIP `/64` allocations from a CSV (`Site Code,STIP Prefix,STIP VLAN`). Resolves each row's IPv4 VLAN500 subnet from the warmed `dnac_interfaces` cache (matching devices via site-code → `device_site_map`) and creates the allocation under the matching STIP `/48` aggregate site. If the IPv4 lookup fails the allocation is still created without one. Dry-run by default.
  ```bash
  .venv/bin/python -m scripts.import_ipv6_stip_allocations stip.csv              # dry-run
  .venv/bin/python -m scripts.import_ipv6_stip_allocations stip.csv --apply      # commit
  ```
- `scripts/discover_site_ipv4.py` — for each IPv6 registry site, scans the warmed DNAC caches enterprise-wide (`dnac_interfaces`, `dnac_reserve_subpools`) and suggests an IPv4 supernet covering everything discovered for that site. Matches registry-site → DNAC by site code (via `utils.site_code.site_code_strict`) with a name-substring fallback. Dry-run by default; `--apply` writes the suggestion to `sites.ipv4_supernet` (only when empty unless `--force`).
  ```bash
  .venv/bin/python -m scripts.discover_site_ipv4                  # dry-run all sites
  .venv/bin/python -m scripts.discover_site_ipv4 --site K024      # one site only
  .venv/bin/python -m scripts.discover_site_ipv4 --apply          # write suggestions
  ```

## Roadmap & gaps

See `docs/ROADMAP.md` for the prioritized list of capability gaps across DNAC, ISE, and ACI (cross-platform endpoint search, DNAC assurance/compliance, ISE operational state, ACI capacity & history), plus cross-cutting items (history snapshots, alerting, RBAC, audit log). Treat that file as the source of truth for "what's next" rather than ad-hoc lists in chat.
