# IMPACT II — Roadmap & Capability Gaps

This document captures the **big missing pieces** identified from a review of the current DNAC, ISE, and ACI implementations, plus cross-cutting items. It is intended as a working backlog — when we pick something up, add notes inline rather than tracking elsewhere.

The dashboard currently does breadth very well. These items are where it can do **depth** — turning the tool from "vendor UI aggregator" into something the NOC opens *first*.

---

## P0 — Highest impact

### 1. Cross-platform endpoint search ("Where is this MAC / IP / user?")
**The one thing a unified dashboard can do that none of the vendor UIs can.** Today each section lives in isolation; the data to join them already exists in cache.

A single query that returns, for one MAC/IP/user:
- **ISE** — last auth, policy set, authz profile, SGT, NAD, NAS-Port
- **DNAC** — switch hostname + port + interface description + site (already partially in `ip-lookup`)
- **ACI** — `fvCEp` location: leaf node + interface + EPG + VRF + BD + encap
- **Firewall** — matching security zone / interface (from `pan_interfaces`)

Implementation sketch:
- New router `routers/search.py` with `GET /api/search/endpoint?q=<mac|ip|user>`
- Parallel fan-out to existing client functions (`ise.get_endpoints`, `ise.get_active_session`, `dnac.get_interface_by_ip`, an ACI `fvCEp` lookup we'd need to add, `pan_interfaces` scan)
- Single Jinja partial that renders the four columns side by side

ACI `fvCEp` lookup is the only net-new client work; everything else is wiring.

---

## P1 — DNAC: Assurance & Compliance

Today DNAC is mostly inventory + config search + IP lookup + `get_recent_issues`. The Assurance and Compliance APIs are the largest untapped surface.

### 2. Health scores
- Device health, client health, site health endpoints
- Add a DNAC health KPI strip on the dashboard (mirror what's already done for ACI)

### 3. Clients (wired/wireless)
- Client list + per-device client count + top talkers
- Feeds the cross-platform search above on the DNAC side

### 4. Compliance
- Config drift, PSIRT advisories, EoX, image-compliance, golden-image gaps
- This is Cisco-only data that's operationally huge and hard to get anywhere else

### 5. SWIM (software image management)
- Image inventory across the fleet, upgrade staging

### 6. Audit / event log
- DNAC `/dna/intent/api/v1/event/...` — who changed what, when

---

## P2 — ISE: Operational state (not just config)

The config side (policy sets, SGTs, profiles) is well covered. What's thin is **runtime state**.

### 7. Failed-auth aggregation
- `get_recent_auth_events` already exists; build a rollup: top failure reasons / NADs / users in the last hour
- This is the single highest-value ops view ISE can give us

### 8. Posture
- Endpoint compliance state — currently invisible in the dashboard

### 9. Certificate inventory
- System and trusted certs with expiration dates
- Zero-effort win that has prevented real outages

### 10. Deployment health
- Replication status, sync state across PAN/MnT/PSN nodes
- We list nodes today but not their sync state

### 11. Licensing
- Sessions vs entitled, evaluation countdown

### 12. AD/LDAP join status
- Silent breaker for authentication — should be on the dashboard

---

## P3 — ACI: Fabric scale, history, and change

ACI is the deepest section, but everything is current state.

### 13. Endpoint tracker
- Search `fvCEp` by MAC/IP across the whole fabric
- Feeds the cross-platform search (item #1)

### 14. vPC state
- `vpcDom` / `vpcIf` peer status
- vPC issues are a top operational pain and currently invisible

### 15. Capacity dashboard
- TCAM, MAC table, route scale per leaf
- Silent ceilings — we should be alerting before they're hit

### 16. Audit log
- `aaaModLR` showing who changed what
- Multi-admin fabrics need this

### 17. Config snapshots
- List snapshots + show diffs between them

### 18. Firmware
- Controller / switch firmware versions and upgrade state

### 19. VMM domain sync health
- vCenter integration sync state (if used)

---

## Cross-cutting

### 20. History / trending
**Everything today is "now."** A small SQLite table snapshotting BGP peer counts, route-table size, ACI fault counts, ISE session counts every 5–15 min would unlock:
- "What changed today?" page
- Trend charts on the dashboard
- Diff views (route table size vs yesterday, peer churn)

Implementation is small: a periodic asyncio task + one table per metric + a `/api/history/<metric>` endpoint.

### 21. Alerting
The tool is passive. A simple watcher loop that posts to Slack/Teams when:
- ACI fault count spikes
- ISE session count drops sharply
- BGP peers go down
- A certificate is < 30 days from expiry
…would change who opens the page first.

### 22. RBAC
`require_auth` is binary. `tag-devices`, the command runner, and the import workflows write to production — they should be behind a separate role gate (LDAP group membership is the cleanest source).

### 23. IMPACT audit log
If users can tag devices or run commands, log who did what locally (separate from server logs — a queryable table on the Cache/Admin page).

### 24. Documentation hygiene
- Keep this file and `CLAUDE.md` updated as items move from "planned" → "done"
- Endpoint counts in `CLAUDE.md` should reflect reality (they previously drifted significantly)

---

## Suggested first slice

If we want one focused chunk that delivers visible value end-to-end:

1. **Cross-platform endpoint search** (#1) — small per-platform work, huge user-visible payoff
2. **DNAC health + clients** (#2, #3) — fills out the dashboard's "DNAC side"
3. **ISE failed-auth rollup** (#7) — the single most-asked-for view from the ISE side

Together those three turn the dashboard from "shows what each platform shows" into "shows what *operating the network* looks like."
