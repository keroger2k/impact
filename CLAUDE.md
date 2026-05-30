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
- **IP Registry** (`/registry`) — site-centric **dual-stack** IPAM. A *site* (keyed by `site_code`) owns any number of IPv4 *and* IPv6 `prefixes`; shared aggregates (e.g. the STIP /48) are containers, per-site /64s hang off them. Stores *intent* (what each site should own) and reconciles it against the live network via the **audit** (DNAC/IPAM tree, Nexus, Panorama, ACI) → in-sync / registry-only / network-only / mismatch, with **bulk-accept** of discovered drift into the registry. Keeps the TSA vvvv decode/IPv4→IPv6 assemble tools. Local SQLite (`data/ip_registry.db`). **This supersedes the older IPv6-only "IPv6 Registry"** (`/ipv6-registry`, `clients/ipv6_registry.py`), which is still wired but deprecated — the `/site` page now reads this dual-stack registry (via `site_aggregator.registry_for_site`), so the old one remains only for the IPAM dashboard's "Add to Registry" cross-links and the standalone `/ipv6-registry` page. Follow-up: repoint those too, then delete the old one. The `/registry` page surfaces shared aggregates (DMVPN overlays / STIP /48s / supernets) under its **Shared** tab via `GET /api/registry/containers`.

The dashboard is mostly read-only. Mutating actions: the **Command Runner** (gated by `COMMANDS_ENABLED`), the **Device Import** workflow, and the **IP Registry** (its writes — including audit bulk-accept — are local-only to the SQLite registry, not pushed to any platform).

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

Default TTLs are defined as constants in `cache.py` and each is overridable via an `IMPACT_TTL_*` env var. Defaults are tuned for a slow-changing network (config/topology lives hours-to-a-day; only true telemetry stays short):

| Constant | Default | Env override | Used by |
|---|---|---|---|
| `TTL_DEFAULT` | 48h | `IMPACT_TTL_DEFAULT` | fallback for `cache.set(...)` with no TTL |
| `TTL_DEVICES` | 24h | `IMPACT_TTL_DEVICES` | DNAC `devices` cache |
| `TTL_SITES` | 24h | `IMPACT_TTL_SITES` | DNAC `sites`, `device_site_map` |
| `TTL_ISE_POLICIES` | 12h | `IMPACT_TTL_ISE_POLICIES` | all ISE stable lists (NADs, SGTs, policy sets, auth rules per policy set, etc.) |
| `TTL_ACI_STATUS` | 2h | `IMPACT_TTL_ACI_STATUS` | every ACI call going through `_cached(...)` with no explicit TTL — nodes, L3Outs, BGP/OSPF peers, BGP DOMs, BGP capability probes, BGP/OSPF maps |
| `TTL_ACI_ROUTE_TABLE` | 30m | `IMPACT_TTL_ACI_ROUTE_TABLE` | per-L3Out route table (`/api/aci/l3outs/route-table`) |
| `TTL_STATUS` | 5m | `IMPACT_TTL_STATUS` | system connectivity probes (`status_*_live` keys in `utils/system_status.py`) |
| `TTL_PAN_INTERFACES` | 48h | `IMPACT_TTL_PAN_INTERFACES` | Panorama firewall interface inventory (`pan_interfaces`) |
| `TTL_PAN_POLICY` | 12h | `IMPACT_TTL_PAN_POLICY` | Panorama policy/inventory data: `pan_rules`, `pan_device_groups`, `pan_managed_devices`, `pan_addr`, `pan_svc` (re-exported as `PAN_TTL` from `routers/firewall.py`) |
| `TTL_DNAC_INTERFACES` | 24h | `IMPACT_TTL_DNAC_INTERFACES` | DNAC per-device interface inventory |
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
- **Stale-while-revalidate**: physical disk retention is 30 days regardless of logical TTL. On logical expiry `get_or_set` (with the default `background=True`) returns the stale value *immediately* and refreshes it on a background thread pool (`_refresh_pool`, deduped per key so concurrent readers don't stampede the upstream) — callers never block just because a TTL rolled over. Pass `background=False` to revalidate synchronously (for keys where stale is misleading). A true cache *miss* still loads synchronously (nothing to serve). `cache.get_stale(key)` returns a physically-present value even past its logical TTL, for read-only display paths (IPAM tree, tunnel inventory) that prefer last-known data over a blank page.
- **Helpers**: `cache.keys_for_prefix(prefix)` and `cache.invalidate_prefix(prefix)` scan all keys.
- **DEV_MODE**: `dev.seed_cache(cache)` runs on every startup when `DEV_MODE=true`, *unconditionally overwriting* every mock key with a 1-year TTL. Real cached data is replaced by mock fixtures on every dev restart — this is intentional for deterministic dev sessions.

**Registry layer** (separate from the cache): thin `sqlite3` wrappers (no ORM) for durable, user-edited rows with relational integrity. Use this pattern — *not* diskcache — for any future feature needing the same; diskcache stays for ephemeral, TTL'd platform reads. Schema bootstrap runs from `main.py`'s `lifespan`.
- `clients/ip_registry.py` over `data/ip_registry.db` — the current **dual-stack** registry. Tables: `sites` (`site_code` UNIQUE join key) and `prefixes` (one row per IPv4/IPv6 network: `family`, `cidr`, `role`, `parent_id` self-FK for the tree, `vvvv` derived-only, `status`/`source`, plus audit columns `audit_state`/`last_seen_at`/`last_seen_source`, plus `participants` — a CSV of site codes, set only on shared **DMVPN overlay** containers to record which sites have a tunnel in that overlay). Shared aggregates are `prefixes` rows with `site_id IS NULL`, role `container` (or `dmvpn`/`supernet`). `UNIQUE(site_id, cidr)` **plus a partial unique index `ON prefixes(cidr) WHERE site_id IS NULL`** (NULL site_id is distinct under plain UNIQUE, so this is what actually stops duplicate shared containers); overlap is a soft audit signal, not a hard constraint. Family-agnostic CIDR math lives in `utils/ipam_net.py`; the vvvv assemble/decode math stays in `utils/ipv6_assembler.py`; the reconciliation engine is `utils/ip_audit.py` (cache-only, pluggable per-source extractors + a pure `reconcile` classifier). It de-dupes observations by `(cidr, source, site_code)`, then before per-site drift it lifts **tunnel-interface subnets** (`Tunnel*`/`Virtual-Template*`) into a shared **DMVPN overlay** group (one shared container per overlay subnet, deduped across sites with a participant count) and buckets **host routes** (loopback/p2p/mgmt, `/30`+ v4, `/126`+ v6 — thresholds `HOST_V4_MIN_PREFIX`/`HOST_V6_MIN_PREFIX`) as collapsed infrastructure. `/audit/accept` takes `{"container": true}` items to commit a shared overlay (and stores its `participant_sites` into `prefixes.participants` when present, so the `/site` page can show which DMVPN overlays a site is on via `site_aggregator.dmvpn_overlays_for_site`); accepts run through `ip_registry.bulk_accept` (one transaction, parent-linked, vlan-validated). Default routes (`/0`) and anything **out of scope** are dropped — the audit only tracks the in-scope allowlist (`_IN_SCOPE` in `utils/ip_audit.py`: RFC1918 + the org IPv6 block configured in `_DEFAULT_SCOPE_V6`, overridable per family via `IMPACT_AUDIT_SCOPE_V4` / `IMPACT_AUDIT_SCOPE_V6` as comma-separated CIDRs), so public/CGNAT/link-local addresses and ACL object-group references never appear as drift (a `0.0.0.0/0` in the registry would also "cover" everything and silence the audit); the accept role is suggested from interface type (SVI → `vlan`, parsed summary/aggregate → `site-aggregate`, else `subnet`) with the VLAN id carried along. Only *multipoint* tunnels (broader than /30) are overlays — /30-/31 tunnels are p2p infrastructure. Attribution uses `site_code_strict` (which treats `SOHO` and similar DNAC tags as non-codes — see its stopword list — falling back to the device hostname) plus **bidirectional containment**: an observed prefix that contains *exactly one* site's registered prefix attributes to it (the /48-vs-/56 case, flagged as a mismatch), while one that spans *2+* sites' prefixes is surfaced as a shared **supernet** container candidate (an org/regional /48), not a per-site mismatch. Observed networks inside a shared **container** (STIP /48) are credited to it (reported under `containers`) rather than left unattributed.
- `clients/ipv6_registry.py` over `data/ipv6_registry.db` — **deprecated** IPv6-only predecessor (`sites`/`allocations`, `UNIQUE(site_id, vvvv)`). Still bootstrapped for the IPAM "Add to Registry" cross-links and the `/ipv6-registry` page; `utils/site_aggregator.py` now reads the new `ip_registry` instead. Do not build new features on it.

**Router layer** (`routers/`) contains FastAPI request handlers. All API routers are wired in `main.py` behind `require_auth`; `pages.py` is the only public router (it serves the login page itself).

- `routers/dnac.py` — `/api/dnac/`: devices (list/stats/detail/config/select-partial), sites, ip-lookup (JSON + UI partial), config-search (JSON + UI + CSV download), path-trace (UI + result partial), tag-devices, cache info/refresh
- `routers/ise.py` — `/api/ise/`: NADs, device-groups, endpoints, endpoint-groups, sessions (active/history/recent), identity-groups, users, SGTs, SGACLs, egress-matrix, policy-sets + per-set auth/authz rules, authz-profiles, allowed-protocols, profiling-policies, deployment-nodes, cache info/refresh
- `routers/firewall.py` — `/api/firewall/`: device-groups, policy lookup, policies by DG, rules export, interfaces (list/refresh/search), devices, templates, cache info/refresh
- `routers/aci.py` — `/api/aci/`: fabrics, fabric/nodes, nodes/{id}/interfaces, L3Outs (list/detail/routes/route-table), BGP map/peers/diagnose, OSPF map/peers, traffic/EPGs, traffic/faults, health/summary, tenants (+detail), VRFs, bridge-domains, app-profiles, EPGs/detail, contracts (+detail), filters, access (policy-groups, AAEPs, domains, VLAN pools, interface policies). All cache keys are namespaced per fabric and most endpoints accept `?fabric=<id>` or `?fabric=all` for cross-fabric aggregation.
- `routers/nexus.py` — `/api/nexus/`: SSH-driven inventory refresh (SSE), inventory, devices (HTML), per-device detail (HTML), interfaces, port-channels, vPCs, VLANs, cache info/refresh
- `routers/routing.py` — `/api/routing/`: BGP summary, EIGRP topology, OSPF neighbors — all driven by parsing cached DNAC running-configs
- `routers/ipam.py` — `/api/ipam/`: refresh (SSE), stats, tree, debug, export
- `routers/tunnels.py` — `/api/tunnels/`: list/detail of normalized IPsec tunnels (DMVPN, sVTI, dVTI, policy-based, Palo IPsec), live counters via SSE refresh. Parsers in `utils/ipsec_parser.py` + `utils/tunnel_inventory.py`; site-code resolution via `utils/site_code.py`.
- `routers/ip_registry.py` — `/api/registry/` (current): sites CRUD, prefixes CRUD (both families; soft-409 on overlap unless `confirm_overlap=true`), `/audit` (reconcile vs. live caches; `?sources=dnac,nexus,panorama,aci`, cached per source-set under `ip_audit:*`), `/audit/accept` (bulk-commit selected drift items as JSON — auto-creates sites by `site_code`), `/export.csv`, plus `/decode` + `/assemble` + `/assemble/bulk` over the registry's IPv6 prefixes (the IPv6 Tools tab exposes Decode, single Assemble, and Bulk Assemble. Single takes a typed/`auto` vvvv — `auto` defaults to the site's fixed 4th-hextet bits via `site_vvvv_fixed_value`, so non-/48 sites assemble inside their own prefix instead of zeroing those bits. Bulk resolves each host's vvvv from the registry by joining the host's VLAN-tagged IPv4 prefix to the site's IPv6 /64 carrying that same VLAN, and reports `no match` where no VLAN linkage exists). Reads/writes the SQLite registry — *not* the cache.
- `routers/ipv6_registry.py` — `/api/ipv6/` (**deprecated**, superseded by `/api/registry`): sites/allocations CRUD, `/decode`, `/assemble`, `/assemble/bulk`, `/export.csv`, `/sites/provision-standard` (`STANDARD_VLAN_PRESET`). Hard 409 on vvvv overlap, soft warn on IPv4-subnet dup.
- `routers/commands.py` — `/api/commands/run`: SSH command execution streamed via SSE; gated by `COMMANDS_ENABLED`
- `routers/import_.py` — `/api/import/run`: device discovery workflow streamed via SSE
- `routers/cache_mgmt.py` — `/api/cache/`: cross-cutting cache status, sidebar widget, per-category refresh (`POST /api/cache/refresh/{category}`), and global clear (`clear_all`)
- `routers/auth.py` — `/api/auth/`: login, logout, session refresh
- `routers/pages.py` — top-level HTML pages: `/login`, `/dashboard`, `/devices`, `/ise`, `/firewall`, `/aci`, `/nexus`, `/nexus/{hostname}`, `/path-trace`, `/routing/bgp`, `/config-search`, `/ip-lookup`, `/ipam`, `/tunnels`, `/registry` (IP Registry; sidebar links here), `/ipv6-registry` (deprecated), `/command-runner`, `/import`, `/cache-mgmt`

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
- **🚫 NEVER put real IP addresses in source code — this is a hard rule. See [docs/IP_ADDRESS_POLICY.md](docs/IP_ADDRESS_POLICY.md), enforced by `tests/test_no_real_ips.py`.** Tests, docstrings, comments, template placeholders, sample data, fixtures, and example values must use fake addresses only — never real customer/site addressing.
  - **Any IP address, prefix, hostname, or interface the user pastes, screenshots, or shows in logs is REAL PRODUCTION DATA. NEVER copy it into tests, fixtures, placeholders, comments, mock data, or examples.** When a user's content gives you a value to work from, *substitute* an approved fake value below before it lands in the repo. This is the rule that's been broken before — treat user-supplied addressing as radioactive.
  - **IPv4 hosts**: `1.2.3.4`, `5.6.7.8`, or `1.1.1.1` / `2.2.2.2` for distinct examples.
  - **IPv4 subnets**: `1.2.3.0/24`, `1.2.0.0/16`, `5.5.5.0/24`. RFC1918 example blocks are fine *as long as they're invented* (`10.0.0.0/8`, `10.45.0.0/16`) — but the org's real RFC1918 ranges (e.g. anything you saw in a screenshot) are off-limits.
  - **IPv6 /48 prefixes**: `1000:2000:3000` (site A), `4000:5000:6000` (site B). Avoid anything resembling a real allocation block (no `2600:…`, `2001:…` except `2001:db8::/32`, etc.).
  - **Generic edge-case octets** (`0.0.0.1`, `255.255.255.255`, `0.0.0.0`) are fine — they're not site-identifying. Same for vvvv values like `0100`, `0200`, `ffff`, and link-local `fe80::1`.
  - Applies retroactively: if you edit a file that still has stale real-looking IPs in test data or examples, swap them while you're there.
  - **One known exception**: `_DEFAULT_SCOPE_V6` in `utils/ip_audit.py` carries the org's real IPv6 block as the functional default audit scope (overridable via `IMPACT_AUDIT_SCOPE_V6`). It's operational config, not sample data; the guard does not scan functional source. Do not copy that value into tests/examples.

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

- `scripts/import_registry.py` — seed the **dual-stack** registry (`data/ip_registry.db`) from the three TSA exports joined on Site Code: IPv4 blocks (`Site Code, Site IP Block(s), Subnet Mask`), IPv6 site /56 (`Site Code, IPv6 Address Space, Slash`), and STIP /64 (`Site Code, STIP Prefix, STIP VLAN[, MASK]` → a shared /48 container + per-site /64 children with the VLAN as `vvvv`). Sites auto-create by code. Headers are matched case-insensitively and column order doesn't matter; IPv6 prefixes are read **high-aligned** (`…:19` at /56 → `…:1900::/56`). Default seed dir `data/seed/`; dry-run by default (prints every resulting canonical CIDR), `--apply` to commit.
  ```bash
  .venv/bin/python -m scripts.import_registry                 # dry-run, data/seed/*.csv
  .venv/bin/python -m scripts.import_registry --apply         # commit
  ```

The IPv6-only import scripts below (`import_ipv6_sites`, `import_ipv6_allocations`, `import_ipv6_stip_allocations`, `discover_site_ipv4`, `fix_ipv6_site_roles`) target the **deprecated** `data/ipv6_registry.db` and are superseded by `import_registry.py`:

- `scripts/import_ipv6_sites.py` — bulk-load IPv6 registry sites from a CSV (`<name>,<prefix>[,<prefix_length>[,<role>[,<description>]]]`). `prefix_length` defaults to 48; quoted fields supported for descriptions with commas. Dry-run by default; `--apply` to commit. Skips name/prefix conflicts (both vs. the DB and within the same file).
  ```bash
  .venv/bin/python -m scripts.import_ipv6_sites                   # dry-run, default file
  .venv/bin/python -m scripts.import_ipv6_sites --apply           # commit
  ```
- `scripts/import_ipv6_allocations.py` — bulk-load IPv6 allocations from a flat file (`<site>,<ipv4_subnet>,<ipv4_mask>,<vvvv>[,<prefix_length>]`). Defaults to `/64`, dry-run by default; `--apply` to commit; `--skip-ipv4-dup` to skip the soft-warn rows. Talks to SQLite directly via `clients.ipv6_registry` (no HTTP/CSRF). Sites must already exist; any prefix length < 64 is accepted, but vvvv values must conform to the site's mask (e.g. a /56 site at `1000:2000:3000:2d00` only accepts vvvvs in `2d00..2dff`).
  ```bash
  .venv/bin/python -m scripts.import_ipv6_allocations              # dry-run, default file
  .venv/bin/python -m scripts.import_ipv6_allocations --apply      # commit
  ```
- `scripts/import_ipv6_stip_allocations.py` — bulk-load per-site STIP `/64` allocations from a CSV (`Site Code,STIP Prefix,STIP VLAN`). Resolves each row's IPv4 VLAN500 subnet from the warmed `dnac_interfaces` cache (matching devices via site-code → `device_site_map`) and creates the allocation under the matching STIP `/48` aggregate site. If the IPv4 lookup fails the allocation is still created without one. Dry-run by default.
  ```bash
  .venv/bin/python -m scripts.import_ipv6_stip_allocations stip.csv              # dry-run
  .venv/bin/python -m scripts.import_ipv6_stip_allocations stip.csv --apply      # commit
  ```
- `scripts/discover_site_ipv4.py` — for each IPv6 registry site, reads the **IPAM tree** (`IPAM_TREE_CACHE_KEY`, requires an IPAM refresh first) and suggests the real summary/aggregate the site's subnets roll up into. Candidate summaries are the tree's configured-summary / per-site-pool aggregate nodes (source `DNAC-Config` / `DNAC-Pool`) that are attributed to the site or contain its member subnets, reduced to the maximal disjoint set; DNAC global pools and synthesized RFC1918 roots are excluded so the suggestion isn't a useless `10.0.0.0/8`. Members not under any real summary are rolled up into a heuristic covering CIDR (only used as the suggestion if the site has no real summary at all). Multiple disjoint summaries are stored comma-separated (`sites.ipv4_supernet` accepts a list). Matches registry-site → DNAC by site code (via `utils.site_code.site_code_strict`) with a name-substring fallback. Dry-run by default; `--apply` writes the suggestion to `sites.ipv4_supernet` (only when empty unless `--force`).
  ```bash
  .venv/bin/python -m scripts.discover_site_ipv4                  # dry-run all sites
  .venv/bin/python -m scripts.discover_site_ipv4 --site K024      # one site only
  .venv/bin/python -m scripts.discover_site_ipv4 --apply          # write suggestions
  ```

## Roadmap & gaps

See `docs/ROADMAP.md` for the prioritized list of capability gaps across DNAC, ISE, and ACI (cross-platform endpoint search, DNAC assurance/compliance, ISE operational state, ACI capacity & history), plus cross-cutting items (history snapshots, alerting, RBAC, audit log). Treat that file as the source of truth for "what's next" rather than ad-hoc lists in chat.
