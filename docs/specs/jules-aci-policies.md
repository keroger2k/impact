# Spec: ACI Policy & Policy Group Visibility

**Audience:** Google Jules (autonomous coding agent)
**Repo:** `impact-ii` — TSA Network Operations Platform (FastAPI + vanilla-JS/HTMX SPA)
**Branch you'll work on:** create a new branch off `main`, e.g. `jules/aci-policy-visibility`
**Mode:** read-only visibility into APIC config — **never write/modify/POST to APIC**.

---

## 0. Read this first

Before writing any code, read these files end-to-end:

1. `CLAUDE.md` — project conventions (cache TTLs, naming, frontend stack).
2. `clients/aci.py` — ACI REST client (DEV_MODE branch, `get()`, `_quote_dn()`).
3. `clients/aci_registry.py` — multi-fabric configuration.
4. `routers/aci.py` — every existing endpoint, especially `_cached`, `_fkey`, `_get_aci_async`, `_aggregate_per_fabric`, `_parse_l3out_from_dn`, `get_fabric_id`. **Your new endpoints must follow these patterns exactly.**
5. `templates/pages/aci_content.html` — the ACI page shell. You will add sidebar items here.
6. `templates/partials/aci_l3outs.html`, `aci_bgp_peers.html`, `aci_l3out_detail.html` — your new partials must match this style (Bootstrap v5, Phosphor icons, `data-table` class for sortable/filterable tables, `showRawData()` button).
7. `dev.py` — see the `MOCK_ACI_*` blocks (~line 550 onward) and `seed_cache()` (~line 1450). All new mock fixtures go here.

**Frontend stack:** Bootstrap v5 (vendored at `static/bootstrap/`) + HTMX (`static/js/htmx.min.js`) + Phosphor icons (`static/phosphor/`) + a small `data-table.js` helper for client-side sort/filter on `<table class="data-table">`. **No build step. No new JS frameworks. No new dependencies.**

**Permission model:** every endpoint uses `Depends(require_auth)` and `Depends(get_fabric_id)` — see existing endpoints. Don't invent your own auth plumbing.

**SSL:** controlled by `IMPACT_VERIFY_SSL` env var (defaults to false — self-signed certs).

---

## 1. What you are building

Read-only browser views into ACI configuration ("policies"). Two parallel hierarchies:

### Tenant model (the "app team's view" — *what talks to what*)
| Resource | APIC class | Drill-down? |
|---|---|---|
| Tenant | `fvTenant` | summary tiles |
| VRF (routing instance) | `fvCtx` | flat |
| Bridge Domain | `fvBD` (with `fvSubnet`) | flat with inline subnets |
| Application Profile | `fvAp` | yes — list its EPGs |
| EPG (extend existing) | `fvAEPg` | yes — provided/consumed contracts, static paths, domains |
| **Contract** | `vzBrCP` | **yes — subjects → filters → entries + provider/consumer EPGs** |
| Filter | `vzFilter` (with `vzEntry`) | flat with inline entries |

### Access model (the "network team's view" — *how a port is configured*)
| Resource | APIC class | Drill-down? |
|---|---|---|
| **Interface Policy Group** | `infraAccPortGrp` (access), `infraAccBndlGrp` (PC/vPC) | **yes — bound interface policies, AAEP, every (node, port) using it** |
| AAEP | `infraAttEntityP` | yes — domains it links, EPG static bindings |
| Domain | `physDomP`, `l3extDomP`, `vmmDomP` | flat with VLAN-pool ref |
| VLAN Pool | `fvnsVlanInstP` (with `fvnsEncapBlk`) | flat with inline blocks |
| Interface Policies | `cdpIfPol`, `lldpIfPol`, `lacpLagPol`, `fabricHIfPol`, `mcpIfPol`, `stpIfPol`, `l2IfPol`, `stormctrlIfPol` | flat (combined table, type filter) |

**Out of scope** (do NOT build): QoS, monitoring policies, fabric-wide NTP/DNS/SNMP, Taboo contracts, route-control profiles, service graphs, configuration backup policies.

---

## 2. Patterns you MUST follow

### 2.1 Multi-fabric

Every endpoint accepts the fabric via the existing `get_fabric_id` dependency (precedence: `X-ACI-Fabric` header > `?fabric=` query > `impact_aci_fabric` cookie > first configured fabric). When `?fabric=all`, aggregate across every configured fabric and tag rows with `fabric_id` and `fabric_label` so the partial template can render a "Fabric" column.

For aggregation, use the existing `_aggregate_per_fabric()` helper in `routers/aci.py` when the data shape fits (it expects `{lists..., stats: {counts}}`). For simple list endpoints (Tenants, VRFs, etc.) replicate the explicit pattern from `list_bgp_peers` (lines ~964–1007 in `routers/aci.py`):

```python
if request.query_params.get("fabric") == "all":
    async def _fetch_single(f):
        try:
            aci = await _get_aci_async(session, f.id)
            items, raw = await _process_for_fabric(aci, loop, f.id)
            for x in items:
                x.update({"fabric_id": f.id, "fabric_label": f.label})
            return items, raw
        except Exception:
            return [], {"imdata": []}
    results = await asyncio.gather(*[_fetch_single(f) for f in reg.list_fabrics()])
    # merge ...
else:
    aci = await _get_aci_async(session, fabric_id)
    items, raw = await _process_for_fabric(aci, loop, fabric_id)
```

### 2.2 Caching

Use `_cached(key, loader, ttl=ACI_TTL)` from `routers/aci.py`. Keys are namespaced per-fabric via `_fkey(fabric_id, suffix)` → `aci_{fabric_id}_{suffix}`.

**TTL:** all new keys reuse `TTL_ACI_STATUS` (env var `IMPACT_TTL_ACI_STATUS`, default 900s / 15min). No new TTL constants.

**New cache suffixes** (add to the `ACI_CACHE_KEYS` list at `routers/aci.py:114` so the cache widget surfaces them):

```
"tenants", "vrfs", "bridge_domains", "subnets_bd",
"app_profiles", "contracts", "filters",
"epg_relations",            # fvRsProv + fvRsCons map for all EPGs
"access_pgs",               # infraAccPortGrp + infraAccBndlGrp combined
"aaeps", "domains", "vlan_pools",
"if_pol_cdp", "if_pol_lldp", "if_pol_lacp", "if_pol_link",
"if_pol_mcp", "if_pol_stp", "if_pol_l2", "if_pol_stormctrl",
"access_topology",          # the cross-reference: PG → [(node, port)]
```

Detail-view caches (per-DN) follow the L3Out route-table pattern — `aci_{fabric}_contract_detail:{quoted_dn}`, `aci_{fabric}_pg_detail:{quoted_dn}`, etc. Use `urllib.parse.quote(dn)` to build the suffix.

### 2.3 Async / blocking I/O

Every APIC call goes through `loop.run_in_executor(None, run_with_context(_cached), ...)`. Never call `aci.get(...)` directly in an async function — wrap it. See every existing endpoint for examples.

### 2.4 HTMX partials

Each endpoint detects `if request.headers.get("HX-Request"):` and returns a Jinja partial; otherwise returns JSON for API consumers. Partials live in `templates/partials/` and follow this skeleton:

```html
<div class="card shadow-sm border-0 animate-fade-in">
    <script id="aci-<name>-raw" type="application/json">{{ raw_json|tojson }}</script>
    <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <div class="d-flex align-items-center gap-3">
            <span class="fw-bold text-navy"><i class="ph ph-<icon> me-1"></i><Title></span>
            <button class="btn btn-xs btn-outline-navy" onclick="showRawData('aci-<name>-raw')">
                <i class="ph ph-code me-1"></i>Raw
            </button>
        </div>
        <span class="badge bg-secondary">{{ items|length }} <thing></span>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive sticky-header" style="max-height: calc(100vh - 250px);">
            <table class="table table-hover align-middle mb-0 data-table">
                ...
            </table>
        </div>
    </div>
</div>
```

`data-table` class enables built-in client-side sort + filter (see `static/js/data-table.js`). Use `data-no-sort` / `data-no-filter` on action columns.

For drill-down rows, add an action button:

```html
<button class="btn btn-xs btn-outline-navy"
        hx-get="/api/aci/contracts/detail?dn={{ c.dn|urlencode }}"
        hx-vals='js:{fabric: "{{ c.fabric_id if c.fabric_id else "" }}" || window.currentFabric}'
        hx-target="#aci-results"
        hx-indicator="#aci-loading"
        title="Contract details">
    <i class="ph ph-info"></i>
</button>
```

### 2.5 DN parsing

Use `_parse_l3out_from_dn()` (already in `routers/aci.py`) where applicable. For DN segments not covered by it, write a small helper following the same pattern (split on `/`, find prefix, strip prefix). Common ACI DN prefixes:

| Prefix | Meaning |
|---|---|
| `tn-<name>` | Tenant |
| `ctx-<name>` | VRF |
| `BD-<name>` | Bridge Domain |
| `ap-<name>` | Application Profile |
| `epg-<name>` | EPG |
| `brc-<name>` | Contract |
| `subj-<name>` | Subject (under contract) |
| `flt-<name>` | Filter |
| `e-<name>` | Filter Entry |
| `out-<name>` | L3Out |
| `accportgrp-<name>` | Access Port Policy Group |
| `accbundle-<name>` | Bundle (PC/vPC) Policy Group |
| `attentp-<name>` | AAEP |
| `phys-<name>` / `l3dom-<name>` / `vmmp-<vendor>/dom-<name>` | Domains |
| `vlanns-[<name>]-<allocMode>` | VLAN namespace pool |
| `from-[<vlan>]-to-[<vlan>]` | Encap block |
| `cdpIfP-<name>`, `lldpIfP-<name>`, `lacpLagP-<name>`, `hintfpol-<name>`, `mcpIfP-<name>`, `stpIfPol-<name>`, `l2IfP-<name>` | Interface policies |

### 2.6 Validation

For any endpoint accepting a `dn` query param, call `_validate_dn(dn)` (already exists in `routers/aci.py`). Don't loosen this regex.

### 2.7 Logging

The ACI client logs every GET via the `extra={...}` dict — don't bypass this. New client methods just call `self.get(path, action="FETCH_ACI_<NAME>")`.

---

## 3. Sidebar additions

Edit `templates/pages/aci_content.html`. The current sidebar has 8 buttons. Group new buttons into two visual sections by inserting `<div class="px-4 py-2 small text-muted text-uppercase fw-bold">Tenant Policies</div>` headers between groups (Bootstrap-aligned).

**New layout (in order):**

```
— Operational —
  Fabric Nodes
  L3Out Visibility
  BGP Peers
  BGP Map
  OSPF Peers
  OSPF Map
  Traffic Analysis (EPGs)
  Operational Faults

— Tenant Policies —
  Tenants                  ph ph-buildings
  VRFs                     ph ph-tree-structure
  Bridge Domains           ph ph-bridge
  Application Profiles     ph ph-stack
  Contracts                ph ph-handshake
  Filters                  ph ph-funnel

— Access Policies —
  Policy Groups            ph ph-package
  AAEPs                    ph ph-link
  Domains                  ph ph-globe
  VLAN Pools               ph ph-list-numbers
  Interface Policies       ph ph-sliders
```

Each new button uses the same `hx-get` / `hx-vals` / `hx-target="#aci-results"` / `hx-indicator="#aci-loading"` pattern as existing buttons — copy the structure exactly.

---

## 4. Backend: `clients/aci.py` additions

Add these methods to `ACIClient`. All return raw `{"imdata": [...]}` dicts (same shape as existing methods). Place them in the same area as the other `get_*` methods.

```python
# ── Tenant Model ──────────────────────────────────────────────────────────

def get_tenants(self):
    """List all fvTenant objects."""
    return self.get("api/node/class/fvTenant.json", action="FETCH_ACI_TENANTS")

def get_vrfs(self, tenant=None):
    """List VRFs (fvCtx). Optionally scoped to a tenant."""
    if tenant:
        path = f"api/node/mo/uni/tn-{_quote_dn(tenant)}.json?query-target=subtree&target-subtree-class=fvCtx"
    else:
        path = "api/node/class/fvCtx.json"
    return self.get(path, action="FETCH_ACI_VRFS")

def get_bridge_domains(self):
    """List Bridge Domains with subnets, VRF binding, and L3Out bindings."""
    path = ("api/node/class/fvBD.json"
            "?rsp-subtree=children&rsp-subtree-class=fvSubnet,fvRsCtx,fvRsBDToOut")
    return self.get(path, action="FETCH_ACI_BDS")

def get_app_profiles(self):
    """List Application Profiles with their EPG count via subtree count."""
    path = "api/node/class/fvAp.json?rsp-subtree-include=count"
    return self.get(path, action="FETCH_ACI_APP_PROFILES")

def get_contracts(self):
    """List Contracts with full subject+filter tree.

    rsp-subtree=full pulls vzSubj children, including vzRsSubjFiltAtt
    (filter binding). We separately resolve filter contents via
    get_filters() — APIC won't follow the relation cross-MO.
    """
    path = "api/node/class/vzBrCP.json?rsp-subtree=full"
    return self.get(path, action="FETCH_ACI_CONTRACTS")

def get_filters(self):
    """List all Filters with their entries (vzEntry) inline."""
    path = "api/node/class/vzFilter.json?rsp-subtree=children&rsp-subtree-class=vzEntry"
    return self.get(path, action="FETCH_ACI_FILTERS")

def get_epg_relations(self):
    """Fetch every fvRsProv + fvRsCons in the fabric so we can build a
    contract-to-EPG (provider/consumer) map without per-EPG fan-out.

    Each fvRsProv/fvRsCons attribute has:
      dn: .../tn-X/ap-Y/epg-Z/rsprov-W   (or rscons-W)
      tDn: uni/tn-X/brc-W                (the contract being prov'd/cons'd)
      tnVzBrCPName: W
    """
    prov = self.get("api/node/class/fvRsProv.json", action="FETCH_ACI_EPG_PROV")
    cons = self.get("api/node/class/fvRsCons.json", action="FETCH_ACI_EPG_CONS")
    return {"prov": prov, "cons": cons}

def get_epg_detail(self, dn):
    """Drill-down for a single EPG: provided/consumed contracts,
    static path bindings, domain associations."""
    classes = "fvRsProv,fvRsCons,fvRsPathAtt,fvRsDomAtt,fvSubnet"
    path = f"api/node/mo/{_quote_dn(dn)}.json?query-target=subtree&target-subtree-class={classes}"
    return self.get(path, action="FETCH_ACI_EPG_DETAIL")

# ── Access Model ──────────────────────────────────────────────────────────

def get_access_policy_groups(self):
    """List both Access (single-port) and Bundle (PC/vPC) policy groups,
    plus their child relation MOs in one call so the response can be
    flattened by the router without further fan-out."""
    children = ("infraRsAttEntP,infraRsCdpIfPol,infraRsLldpIfPol,"
                "infraRsLacpPol,infraRsHIfPol,infraRsMcpIfPol,"
                "infraRsStpIfPol,infraRsL2IfPol,infraRsStormctrlIfPol")
    access = self.get(
        f"api/node/class/infraAccPortGrp.json?rsp-subtree=children&rsp-subtree-class={children}",
        action="FETCH_ACI_ACCESS_PG")
    bundle = self.get(
        f"api/node/class/infraAccBndlGrp.json?rsp-subtree=children&rsp-subtree-class={children}",
        action="FETCH_ACI_BUNDLE_PG")
    return {"access": access, "bundle": bundle}

def get_aaeps(self):
    """List AAEPs (infraAttEntityP) with domain links and per-EPG
    static-bind generic config."""
    path = ("api/node/class/infraAttEntityP.json"
            "?rsp-subtree=children&rsp-subtree-class=infraRsDomP,infraGeneric")
    return self.get(path, action="FETCH_ACI_AAEPS")

def get_physical_domains(self):
    return self.get(
        "api/node/class/physDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
        action="FETCH_ACI_PHYS_DOMAINS")

def get_l3_domains(self):
    return self.get(
        "api/node/class/l3extDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
        action="FETCH_ACI_L3_DOMAINS")

def get_vmm_domains(self):
    return self.get(
        "api/node/class/vmmDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
        action="FETCH_ACI_VMM_DOMAINS")

def get_vlan_pools(self):
    """fvnsVlanInstP with their fvnsEncapBlk children (the actual ranges)."""
    path = ("api/node/class/fvnsVlanInstP.json"
            "?rsp-subtree=children&rsp-subtree-class=fvnsEncapBlk")
    return self.get(path, action="FETCH_ACI_VLAN_POOLS")

def get_interface_policy_class(self, cls):
    """Generic fetch for one interface-policy class. cls in:
    cdpIfPol, lldpIfPol, lacpLagPol, fabricHIfPol, mcpIfPol,
    stpIfPol, l2IfPol, stormctrlIfPol.
    """
    return self.get(f"api/node/class/{cls}.json", action=f"FETCH_ACI_{cls.upper()}")

def get_access_topology(self):
    """Pull every MO needed to build the policy-group → (node, port) map
    in one fan-out call. The router joins these.

    - infraNodeP        (Switch Profile)
    - infraLeafS        (leaf selector, with fromCard/fromPort)
    - infraNodeBlk      (range of node IDs)
    - infraRsAccPortP   (Switch Profile → Interface Profile)
    - infraAccPortP     (Interface Profile)
    - infraHPortS       (port selector)
    - infraPortBlk      (range of port IDs)
    - infraRsAccBaseGrp (Port selector → Policy Group)
    """
    classes = ("infraNodeP,infraLeafS,infraNodeBlk,infraRsAccPortP,"
               "infraAccPortP,infraHPortS,infraPortBlk,infraRsAccBaseGrp")
    path = f"api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class={classes}"
    return self.get(path, action="FETCH_ACI_ACCESS_TOPOLOGY")
```

---

## 5. Backend: `routers/aci.py` additions

All endpoints follow the existing async-executor + `_cached` + HTMX-or-JSON pattern. Add a new section header near the bottom of the file:

```python
# ── Tenant Policies ───────────────────────────────────────────────────────
# ── Access Policies ───────────────────────────────────────────────────────
```

### 5.1 Tenant model endpoints

#### `GET /api/aci/tenants`

Lists tenants with summary counts. Counts come from one extra fan-out: query `fvCtx`, `fvBD`, `fvAp`, `fvAEPg`, `vzBrCP`, `vzFilter` once each fabric-wide, group by tenant from the DN.

**Response shape:**
```python
{
  "items": [
    {
      "name": "PROD",
      "descr": "...",
      "dn": "uni/tn-PROD",
      "vrf_count": 3, "bd_count": 12, "ap_count": 4, "epg_count": 27,
      "contract_count": 18, "filter_count": 22,
      "fabric_id": "...", "fabric_label": "..."  # only on ?fabric=all
    }
  ],
  "raw": { "imdata": [...] }   # raw fvTenant response
}
```

**Partial:** `templates/partials/aci_tenants.html`. Each row has a button that calls `/api/aci/tenants/{name}/detail`.

#### `GET /api/aci/tenants/{tenant}/detail`

Drill-down. Inline panels for VRFs, BDs, App Profiles, Contracts, Filters scoped to this tenant. Use the same client methods with `tenant=` param.

**Partial:** `templates/partials/aci_tenant_detail.html` — Bootstrap nav-tabs (`<ul class="nav nav-tabs">`) for VRFs / BDs / App Profiles / Contracts / Filters.

#### `GET /api/aci/vrfs`

Flat list of all VRFs across the fabric (or aggregated). Query param `?tenant=X` filters server-side.

**Per-row processing:**
```python
attr = item.get("fvCtx", {}).get("attributes", {})
{
  "name": attr.get("name"),
  "tenant": _parse_dn(dn)["tenant"],
  "dn": attr.get("dn"),
  "policy_enforcement": attr.get("pcEnfPref"),  # "enforced" | "unenforced"
  "enforcement_direction": attr.get("pcEnfDir"),  # "ingress" | "egress"
  "bd_enforce": attr.get("bdEnforcedEnable"),
  "descr": attr.get("descr") or "",
}
```

**Partial:** `templates/partials/aci_vrfs.html`.

#### `GET /api/aci/bridge-domains`

Lists BDs with inline subnets, VRF, and L3Out bindings (parsed from the `rsp-subtree=children` payload).

**Per-row processing:**
```python
bd = item["fvBD"]
attr = bd["attributes"]
subnets = []
vrf = None
l3outs = []
for c in bd.get("children", []):
    if "fvSubnet" in c:
        s = c["fvSubnet"]["attributes"]
        subnets.append({"ip": s.get("ip"), "scope": s.get("scope"), "descr": s.get("descr")})
    elif "fvRsCtx" in c:
        vrf = c["fvRsCtx"]["attributes"].get("tnFvCtxName")
    elif "fvRsBDToOut" in c:
        l3outs.append(c["fvRsBDToOut"]["attributes"].get("tnL3extOutName"))

{
  "name": attr.get("name"),
  "tenant": _parse_dn(dn)["tenant"],
  "dn": attr.get("dn"),
  "vrf": vrf,
  "subnets": subnets,                  # inline rendered
  "l3outs": l3outs,
  "unicast_routing": attr.get("unicastRoute"),  # "yes" | "no"
  "arp_flood": attr.get("arpFlood"),
  "unk_mac_action": attr.get("unkMacUcastAct"),  # "proxy" | "flood"
  "ip_learning": attr.get("ipLearning"),
  "type": attr.get("type"),  # "regular" | "fc"
  "mac": attr.get("mac"),
  "descr": attr.get("descr") or "",
}
```

**Partial:** `templates/partials/aci_bridge_domains.html`. Render subnets as `<span class="d-block">{{ s.ip }}</span>` stacked inside the cell.

#### `GET /api/aci/app-profiles`

Flat list. Each row has a "Show EPGs" action that points to the **existing** `/api/aci/traffic/epgs` endpoint with a new query param — *NO*, simpler: existing `traffic/epgs` already lists everything; instead, make this row link to a new `GET /api/aci/app-profiles/{tenant}/{name}/epgs` partial that filters EPGs by `ap-` segment in DN.

**Partial:** `templates/partials/aci_app_profiles.html`.

#### `GET /api/aci/epgs/detail?dn=...`

Drill-down on one EPG. Use `aci.get_epg_detail(dn)`. Build:

```python
{
  "epg": { "name": ..., "tenant": ..., "ap": ..., "dn": dn },
  "provided_contracts": [{"name": ..., "tenant": ...}],
  "consumed_contracts": [{"name": ..., "tenant": ...}],
  "static_paths":       [{"path": ..., "encap": ..., "mode": ...}],
  "domains":            [{"tdn": ..., "type": ...}],   # from fvRsDomAtt
  "subnets":            [{"ip": ..., "scope": ...}],   # from fvSubnet
}
```

**fvRsPathAtt** attributes: `tDn` (e.g. `topology/pod-1/paths-101/pathep-[eth1/15]`), `encap` (e.g. `vlan-100`), `mode` (`regular` | `untagged` | `native`), `instrImedcy`.

**fvRsDomAtt** attributes: `tDn` (e.g. `uni/phys-PHYS-DOM` or `uni/vmmp-VMware/dom-VC1`), `instrImedcy`, `resImedcy`.

**Partial:** `templates/partials/aci_epg_detail.html` — tab layout (Contracts / Static Paths / Domains / Subnets).

**Wire it up:** modify the existing `aci_epgs.html` partial so each EPG row has a new action button that calls this endpoint.

#### `GET /api/aci/contracts`

Lists contracts. Build the provider/consumer count from the `epg_relations` cache (one fabric-wide query of `fvRsProv` + `fvRsCons`).

**Per-row processing:**
```python
# 1. Parse contracts
attr = item["vzBrCP"]["attributes"]
subjects = [c["vzSubj"]["attributes"]["name"]
            for c in item["vzBrCP"].get("children", [])
            if "vzSubj" in c]

# 2. Cross-ref with relations
# Build once outside the loop:
prov_map = {}  # contract_dn -> [epg_dn, ...]
cons_map = {}
for r in epg_relations["prov"]["imdata"]:
    a = r["fvRsProv"]["attributes"]
    prov_map.setdefault(a["tDn"], []).append(_parent_epg_dn(a["dn"]))
for r in epg_relations["cons"]["imdata"]:
    a = r["fvRsCons"]["attributes"]
    cons_map.setdefault(a["tDn"], []).append(_parent_epg_dn(a["dn"]))

{
  "name": attr.get("name"),
  "tenant": _parse_dn(attr["dn"])["tenant"],
  "scope": attr.get("scope"),     # "context" | "tenant" | "global" | "application-profile"
  "dn": attr.get("dn"),
  "subjects": subjects,
  "provider_count": len(prov_map.get(attr["dn"], [])),
  "consumer_count": len(cons_map.get(attr["dn"], [])),
  "descr": attr.get("descr") or "",
}
```

`_parent_epg_dn` strips the trailing `/rsprov-X` or `/rscons-X` segment.

**Partial:** `templates/partials/aci_contracts.html`. Detail button → `/api/aci/contracts/detail?dn=...`.

#### `GET /api/aci/contracts/detail?dn=...`

Killer feature. Show:
- Subjects (`vzSubj` children of the contract) with their attributes (`revFltPorts`, `consMatchT`, `provMatchT`)
- Each Subject's filter bindings (`vzRsSubjFiltAtt` children — has `tnVzFilterName`)
- Each filter's entries (resolve the filter from the cached `filters` list — no extra APIC call)
- Providers (EPGs) — from the prov_map
- Consumers (EPGs) — from the cons_map

**Response shape:**
```python
{
  "contract": {"name": ..., "tenant": ..., "scope": ..., "dn": dn, "descr": ...},
  "subjects": [
    {
      "name": "Web",
      "rev_filter_ports": "yes",
      "filters": [
        {
          "name": "ALLOW_HTTP",
          "tenant": "PROD",
          "entries": [
            {"name": "tcp80", "ether_type": "ip", "protocol": "tcp",
             "dst_from_port": "http", "dst_to_port": "http",
             "src_from_port": "unspecified", "src_to_port": "unspecified",
             "stateful": "yes"}
          ]
        }
      ]
    }
  ],
  "providers": [{"name": "WEB", "tenant": "PROD", "ap": "APP1", "dn": "..."}],
  "consumers": [{"name": "DB",  "tenant": "PROD", "ap": "APP1", "dn": "..."}],
}
```

**Partial:** `templates/partials/aci_contract_detail.html` — three sections: Subjects (accordion or tabs), Providers table, Consumers table.

**Cache:** `aci_{fabric}_contract_detail:{quoted_dn}` with 15-min TTL.

#### `GET /api/aci/filters`

Lists filters with entries inline. Render entries as a list of `<code class="badge">tcp/443</code>` chips per row.

**vzEntry attributes that matter:**
- `etherT` (`ip`, `arp`, `mac-security`, `mpls-ucast`, `unspecified`, ...)
- `prot` (`tcp`, `udp`, `icmp`, `egp`, `igp`, `pim`, `unspecified`, or numeric)
- `dFromPort`, `dToPort`, `sFromPort`, `sToPort` — port ranges, or named (`http`, `https`, `dns`, `unspecified`)
- `applyToFrag` (`yes`/`no`)
- `stateful` (`yes`/`no`)
- `tcpRules` (e.g. `est`, `syn`, `ack`)

Format ports for display: if `from == to`, just show one; else `from-to`.

**Partial:** `templates/partials/aci_filters.html`.

### 5.2 Access model endpoints

#### `GET /api/aci/access/policy-groups`

Lists every `infraAccPortGrp` and `infraAccBndlGrp`. Process the children to surface bound interface policies and AAEP at the table level.

**Per-row processing** (works for both classes — branch on which key is present):
```python
def _process_pg(item, pg_kind):
    obj = item[pg_kind]   # "infraAccPortGrp" or "infraAccBndlGrp"
    attr = obj["attributes"]
    rels = {}
    for c in obj.get("children", []):
        for cls, val in c.items():
            v = val["attributes"]
            rels[cls] = v.get("tDn") or v.get("tnCdpIfPolName") or v.get("tnLldpIfPolName") \
                        or v.get("tnLacpLagPolName") or v.get("tnFabricHIfPolName") \
                        or v.get("tnMcpIfPolName") or v.get("tnStpIfPolName") \
                        or v.get("tnL2IfPolName") or v.get("tnInfraAttEntityPName") \
                        or v.get("tnStormctrlIfPolName")
    return {
        "name": attr.get("name"),
        "kind": "Access" if pg_kind == "infraAccPortGrp" else "Bundle",
        "lag_t": attr.get("lagT") if pg_kind == "infraAccBndlGrp" else None,  # "node" (vPC) | "link" (PC)
        "dn": attr.get("dn"),
        "aaep": rels.get("infraRsAttEntP"),
        "cdp": rels.get("infraRsCdpIfPol"),
        "lldp": rels.get("infraRsLldpIfPol"),
        "lacp": rels.get("infraRsLacpPol"),
        "link": rels.get("infraRsHIfPol"),
        "mcp": rels.get("infraRsMcpIfPol"),
        "stp": rels.get("infraRsStpIfPol"),
        "l2": rels.get("infraRsL2IfPol"),
        "stormctrl": rels.get("infraRsStormctrlIfPol"),
        "descr": attr.get("descr") or "",
    }
```

Render the LAG-type column as a badge: `vPC` / `PC` / `Access`.

**Partial:** `templates/partials/aci_policy_groups.html`. Detail button → `/api/aci/access/policy-groups/detail?dn=...`.

#### `GET /api/aci/access/policy-groups/detail?dn=...`

The killer access-side feature. Three sections:

1. **Bound interface policies** — for each bound policy (cdp/lldp/lacp/etc.), resolve the *contents* of that policy from the cached interface-policy lists and show actual settings (e.g. CDP `adminSt=enabled`). This is a join between the PG row and the `if_pol_*` cache entries.
2. **AAEP** — name, link to AAEP detail.
3. **Where used: every (node, port) using this PG.** Computed from the `access_topology` cache.

**Computing "where used" — this is the hard part.** Algorithm:

```python
def build_pg_to_ports(access_topology_imdata):
    """Returns dict: pg_dn -> [(node_id, port), ...]"""
    # 1. Index everything by parent DN
    by_class = defaultdict(dict)  # cls -> {dn: attrs}
    children_of = defaultdict(list)  # parent_dn -> [(cls, dn, attrs), ...]
    for item in access_topology_imdata:
        cls = next(iter(item))
        attrs = item[cls]["attributes"]
        dn = attrs.get("dn", "")
        by_class[cls][dn] = attrs
        # parent = strip last /segment
        parent = "/".join(dn.split("/")[:-1])
        children_of[parent].append((cls, dn, attrs))

    # 2. For each interface profile, find which port selectors → which PG → which ports
    # infraAccPortP DN: uni/infra/accportprof-<name>
    # infraHPortS  DN: uni/infra/accportprof-<NAME>/hports-<SEL>-typ-<TYPE>
    # infraPortBlk DN: .../hports-X-typ-Y/portblk-<NAME>   (fromCard/fromPort/toCard/toPort)
    # infraRsAccBaseGrp: .../hports-X-typ-Y/rsaccBaseGrp   (tDn = PG)

    # interface_profile_to_ports[ipname] = [(pg_dn, fromCard, fromPort, toCard, toPort), ...]
    iprof_to_blocks = defaultdict(list)
    for hports_dn, hattrs in by_class.get("infraHPortS", {}).items():
        ipname = hports_dn.split("/accportprof-")[1].split("/")[0]
        # Find children of this HPortS
        pg_dn = None
        blocks = []
        for cls, child_dn, child_attrs in children_of.get(hports_dn, []):
            if cls == "infraRsAccBaseGrp":
                pg_dn = child_attrs.get("tDn")
            elif cls == "infraPortBlk":
                blocks.append(child_attrs)
        if not pg_dn or not blocks:
            continue
        for blk in blocks:
            iprof_to_blocks[ipname].append({
                "pg_dn": pg_dn,
                "fromCard": int(blk.get("fromCard", "1")),
                "toCard":   int(blk.get("toCard", blk.get("fromCard", "1"))),
                "fromPort": int(blk.get("fromPort", "0")),
                "toPort":   int(blk.get("toPort", blk.get("fromPort", "0"))),
            })

    # 3. Now map switch profiles → interface profiles → nodes
    # infraNodeP DN: uni/infra/nprof-<name>
    # infraLeafS DN: uni/infra/nprof-X/leaves-Y-typ-Z
    # infraNodeBlk DN: .../leaves-Y-typ-Z/nodeblk-N  (from_, to_)
    # infraRsAccPortP: uni/infra/nprof-X/rsaccPortP-[uni/infra/accportprof-Z] (tDn → IP DN)
    # IMPORTANT: The relation is at the **switch-profile level**, not per-leafS,
    # so all leafS in this nprof use these interface profiles.

    pg_to_ports = defaultdict(list)
    for nprof_dn, nattrs in by_class.get("infraNodeP", {}).items():
        node_ids = []
        ipnames = []
        # walk all descendants of this node profile
        # For nodes:
        for cls, child_dn, child_attrs in children_of.get(nprof_dn, []):
            if cls == "infraLeafS":
                # walk further for nodeblk
                for cls2, dn2, a2 in children_of.get(child_dn, []):
                    if cls2 == "infraNodeBlk":
                        try:
                            f, t = int(a2.get("from_")), int(a2.get("to_"))
                            node_ids.extend(range(f, t + 1))
                        except (TypeError, ValueError):
                            pass
            elif cls == "infraRsAccPortP":
                tdn = child_attrs.get("tDn", "")
                if "/accportprof-" in tdn:
                    ipnames.append(tdn.split("/accportprof-")[-1])

        for ipname in ipnames:
            for blk in iprof_to_blocks.get(ipname, []):
                for nid in node_ids:
                    for card in range(blk["fromCard"], blk["toCard"] + 1):
                        for port in range(blk["fromPort"], blk["toPort"] + 1):
                            pg_to_ports[blk["pg_dn"]].append((str(nid), f"eth{card}/{port}"))

    return pg_to_ports
```

Cache the result in `aci_{fabric}_access_topology` (15min TTL). The detail endpoint just reads it.

**Response shape:**
```python
{
  "policy_group": {"name": ..., "kind": "Bundle", "lag_t": "node", "dn": ..., ...},
  "bound_policies": [
    {"type": "CDP",  "name": "CDP-ON",         "settings": {"adminSt": "enabled"}},
    {"type": "LLDP", "name": "LLDP-ENABLED",   "settings": {"adminRxSt": "enabled", "adminTxSt": "enabled"}},
    {"type": "LACP", "name": "LACP-ACTIVE",    "settings": {"mode": "active"}},
    {"type": "Link", "name": "10G-AUTO",       "settings": {"speed": "10G", "autoNeg": "on"}},
    ...
  ],
  "aaep": {"name": "AAEP-PROD", "dn": "..."},
  "where_used": [
    {"node": "101", "port": "eth1/15"},
    {"node": "101", "port": "eth1/16"},
    ...
  ]
}
```

**Partial:** `templates/partials/aci_policy_group_detail.html` with three card sections.

**Cache key:** `aci_{fabric}_pg_detail:{quoted_dn}` (15min TTL).

#### `GET /api/aci/access/aaeps`

List AAEPs, with `domains` (from `infraRsDomP` children — `tDn` → split to get type+name) and `epg_static_count` (from `infraGeneric` → its `infraRsFuncToEpg` children, but we don't pull those in the list view; use `?rsp-subtree-include=count` instead — or just count `infraGeneric` children whose subtree contains relations. Simpler: omit static-EPG count from the list, surface only on detail.)

Detail-button on each row goes to `GET /api/aci/access/aaeps/detail?dn=...`.

#### `GET /api/aci/access/aaeps/detail?dn=...`

Fetch one AAEP with full subtree. Show:
- Linked domains (table)
- Static EPG bindings (`infraRsFuncToEpg` children of `infraGeneric`): `tDn` → EPG DN, `encap`, `mode`

#### `GET /api/aci/access/domains`

Combined list of all three domain types. One row per domain.

```python
{
  "name": ..., "type": "Physical" | "L3 External" | "VMM",
  "vlan_pool": "<pool_name> (<allocMode>)",  # from infraRsVlanNs.tDn
  "dn": ...,
}
```

#### `GET /api/aci/access/vlan-pools`

VLAN pools with inline encap blocks. Each pool's `name`, `allocMode` (`static` | `dynamic`), and a list of blocks `[{from: vlan-100, to: vlan-200, role: external}]`.

#### `GET /api/aci/access/interface-policies`

Combined table for all 8 policy classes. Query param `?type=cdp|lldp|lacp|link|mcp|stp|l2|stormctrl` filters server-side. Without `?type=`, returns all.

For each row:
```python
{
  "type": "CDP",  # display name
  "name": attr.get("name"),
  "settings": "adminSt=enabled, ...",  # one-line summary
  "dn": attr.get("dn"),
  "raw_attrs": attr,   # dumped via the Raw button
}
```

The summary string is type-specific; produce it with a dispatch dict:

```python
def _summarize_pol(cls, attr):
    if cls == "cdpIfPol":
        return f"adminSt={attr.get('adminSt')}"
    if cls == "lldpIfPol":
        return f"rx={attr.get('adminRxSt')}, tx={attr.get('adminTxSt')}"
    if cls == "lacpLagPol":
        return f"mode={attr.get('mode')}, ctrl={attr.get('ctrl')}"
    if cls == "fabricHIfPol":
        return f"speed={attr.get('speed')}, autoNeg={attr.get('autoNeg')}, fec={attr.get('fecMode')}"
    if cls == "mcpIfPol":
        return f"adminSt={attr.get('adminSt')}"
    if cls == "stpIfPol":
        return f"ctrl={attr.get('ctrl')}"
    if cls == "l2IfPol":
        return f"qinq={attr.get('qinq')}, vlanScope={attr.get('vlanScope')}"
    if cls == "stormctrlIfPol":
        return (f"bcRate={attr.get('bcRate')}, mcRate={attr.get('mcRate')}, "
                f"uucRate={attr.get('uucRate')}")
    return ""
```

---

## 6. Frontend: templates

For each new endpoint, create the corresponding partial in `templates/partials/`. Strict requirements:

- Use the skeleton from §2.4.
- Tables get `class="table table-hover align-middle mb-0 data-table"`.
- Action buttons use `btn btn-xs btn-outline-navy` with Phosphor icons (`ph ph-info`, `ph ph-eye`, etc.).
- For badges: status colors should be `bg-success` (good), `bg-danger` (bad), `bg-warning text-dark` (warn), `bg-secondary` (neutral), `bg-info` (info).
- `fabric_id`/`fabric_label` columns appear only when present (use `{% if items[0].fabric_label %}...{% endif %}` like `aci_l3outs.html`).
- Drill-down buttons must propagate the fabric:
  ```
  hx-vals='js:{fabric: "{{ row.fabric_id if row.fabric_id else "" }}" || window.currentFabric}'
  ```
- Empty-state block:
  ```html
  {% if not items %}
  <div class="p-5 text-center text-muted">
      <i class="ph ph-empty display-4 d-block mb-3"></i>
      <div>No <thing> found on this fabric.</div>
  </div>
  {% endif %}
  ```

**Files to add:**

```
templates/partials/aci_tenants.html
templates/partials/aci_tenant_detail.html
templates/partials/aci_vrfs.html
templates/partials/aci_bridge_domains.html
templates/partials/aci_app_profiles.html
templates/partials/aci_epg_detail.html
templates/partials/aci_contracts.html
templates/partials/aci_contract_detail.html
templates/partials/aci_filters.html
templates/partials/aci_policy_groups.html
templates/partials/aci_policy_group_detail.html
templates/partials/aci_aaeps.html
templates/partials/aci_aaep_detail.html
templates/partials/aci_domains.html
templates/partials/aci_vlan_pools.html
templates/partials/aci_interface_policies.html
```

**Modify:** `templates/partials/aci_epgs.html` — add an "info" action button per row pointing to `/api/aci/epgs/detail?dn=...`.

---

## 7. Mock fixtures (`dev.py`)

This is mandatory — the entire app runs against `DEV_MODE=true` for development. Without mocks, your endpoints will return empty results in dev.

### 7.1 Add to `clients/aci.py` DEV_MODE branch

In `clients/aci.py:115` (the `if DEV_MODE:` block in `get()`), add path-matching branches that return new mocks. Example:

```python
if "fvTenant" in path and "fvCtx" not in path: return {"imdata": MOCK_ACI_TENANTS}
if "fvCtx"      in path: return {"imdata": MOCK_ACI_VRFS}
if "fvBD"       in path: return {"imdata": MOCK_ACI_BDS}
if "fvAp"       in path: return {"imdata": MOCK_ACI_APP_PROFILES}
if "vzBrCP"     in path: return {"imdata": MOCK_ACI_CONTRACTS}
if "vzFilter"   in path: return {"imdata": MOCK_ACI_FILTERS}
if "fvRsProv"   in path: return {"imdata": MOCK_ACI_FV_RSPROV}
if "fvRsCons"   in path: return {"imdata": MOCK_ACI_FV_RSCONS}
if "infraAccPortGrp"  in path: return {"imdata": MOCK_ACI_ACCESS_PG}
if "infraAccBndlGrp"  in path: return {"imdata": MOCK_ACI_BUNDLE_PG}
if "infraAttEntityP"  in path: return {"imdata": MOCK_ACI_AAEPS}
if "physDomP"   in path: return {"imdata": MOCK_ACI_PHYS_DOMAINS}
if "l3extDomP"  in path: return {"imdata": MOCK_ACI_L3_DOMAINS}
if "vmmDomP"    in path: return {"imdata": MOCK_ACI_VMM_DOMAINS}
if "fvnsVlanInstP" in path: return {"imdata": MOCK_ACI_VLAN_POOLS}
if "cdpIfPol"   in path: return {"imdata": MOCK_ACI_CDP_POLS}
if "lldpIfPol"  in path: return {"imdata": MOCK_ACI_LLDP_POLS}
if "lacpLagPol" in path: return {"imdata": MOCK_ACI_LACP_POLS}
if "fabricHIfPol" in path: return {"imdata": MOCK_ACI_LINK_POLS}
if "mcpIfPol"   in path: return {"imdata": MOCK_ACI_MCP_POLS}
if "stpIfPol"   in path: return {"imdata": MOCK_ACI_STP_POLS}
if "l2IfPol"    in path: return {"imdata": MOCK_ACI_L2_POLS}
if "stormctrlIfPol" in path: return {"imdata": MOCK_ACI_STORMCTRL_POLS}
# Access topology subtree (must come before generic infraNodeP/infraAccPortP)
if "uni/infra.json" in path and "infraNodeP" in path:
    return {"imdata": MOCK_ACI_ACCESS_TOPOLOGY}
```

Order matters — put more-specific matches before generic ones.

### 7.2 Add to `dev.py`

Append new fixture blocks to `dev.py` in the same style as `MOCK_ACI_NODES` etc. Keep them minimal but realistic — at least 2 of each, with cross-references that work end-to-end.

**Mandatory cross-referenced minimal dataset:**

- 2 tenants: `PROD`, `DEV`
- VRFs: `PROD/VRF-1`, `PROD/VRF-2`, `DEV/VRF-1`
- BDs: `PROD/BD-WEB` (in VRF-1, subnet 10.10.10.1/24), `PROD/BD-DB` (in VRF-1, subnet 10.10.20.1/24), `DEV/BD-TEST`
- App Profiles: `PROD/APP1`, `DEV/APP1`
- EPGs: `PROD/APP1/WEB`, `PROD/APP1/DB`, `DEV/APP1/TEST`
- Contracts: `PROD/WEB-to-DB` (one subject `Web-Subj`, one filter `ALLOW-HTTPS`)
- Filters: `PROD/ALLOW-HTTPS` (entry `tcp443`: `etherT=ip, prot=tcp, dFromPort=443, dToPort=443`)
- fvRsProv: WEB provides WEB-to-DB
- fvRsCons: DB consumes WEB-to-DB
- Access policy groups: `PG-Server-Access` (Access), `PG-Server-VPC` (Bundle, vPC, lagT=node)
- AAEP: `AAEP-PROD` linked to `PHYS-DOM`
- Domains: `PHYS-DOM` (physical) → VLAN-POOL-PROD; `L3-DOM` (l3); `VMM-VC1` (VMware)
- VLAN pool: `VLAN-POOL-PROD` (static), block 100–200
- One of each interface policy class (`CDP-ON`, `LLDP-ENABLED`, `LACP-ACTIVE`, `10G-AUTO`, `MCP-ENABLED`, `BPDU-GUARD`, `L2-DEFAULT`, `STORM-DEFAULT`)
- Access topology: `PG-Server-VPC` is bound to ports `eth1/15-16` on nodes 101 and 102

### 7.3 Seed into cache

In `dev.py:seed_cache()` (around line 1457), extend the `aci_fabric_data` dict:

```python
aci_fabric_data = {
    # existing ...
    "tenants":         {"imdata": MOCK_ACI_TENANTS},
    "vrfs":            {"imdata": MOCK_ACI_VRFS},
    "bridge_domains":  {"imdata": MOCK_ACI_BDS},
    "app_profiles":    {"imdata": MOCK_ACI_APP_PROFILES},
    "contracts":       {"imdata": MOCK_ACI_CONTRACTS},
    "filters":         {"imdata": MOCK_ACI_FILTERS},
    "epg_relations":   {"prov": {"imdata": MOCK_ACI_FV_RSPROV},
                        "cons": {"imdata": MOCK_ACI_FV_RSCONS}},
    "access_pgs":      {"access": {"imdata": MOCK_ACI_ACCESS_PG},
                        "bundle": {"imdata": MOCK_ACI_BUNDLE_PG}},
    "aaeps":           {"imdata": MOCK_ACI_AAEPS},
    "domains":         {"physical": {"imdata": MOCK_ACI_PHYS_DOMAINS},
                        "l3": {"imdata": MOCK_ACI_L3_DOMAINS},
                        "vmm": {"imdata": MOCK_ACI_VMM_DOMAINS}},
    "vlan_pools":      {"imdata": MOCK_ACI_VLAN_POOLS},
    "if_pol_cdp":       {"imdata": MOCK_ACI_CDP_POLS},
    "if_pol_lldp":      {"imdata": MOCK_ACI_LLDP_POLS},
    "if_pol_lacp":      {"imdata": MOCK_ACI_LACP_POLS},
    "if_pol_link":      {"imdata": MOCK_ACI_LINK_POLS},
    "if_pol_mcp":       {"imdata": MOCK_ACI_MCP_POLS},
    "if_pol_stp":       {"imdata": MOCK_ACI_STP_POLS},
    "if_pol_l2":        {"imdata": MOCK_ACI_L2_POLS},
    "if_pol_stormctrl": {"imdata": MOCK_ACI_STORMCTRL_POLS},
    "access_topology":  {"imdata": MOCK_ACI_ACCESS_TOPOLOGY},
}
```

---

## 8. Tests

Add a new file `tests/test_aci_policies.py` modeled on `tests/test_aci_interfaces.py`. Cover:

1. **Smoke test per endpoint** — `GET /api/aci/<path>` against DEV_MODE returns 200 and a non-empty `items` list (or expected shape).
2. **Drill-down endpoints** — pass the DN of one of the seeded mock items, assert response has expected nested structure.
3. **Multi-fabric** — call with `?fabric=all`, assert `fabric_label` is present on every item and at least 2 distinct fabric_ids appear (when 2+ fabrics are seeded in test fixtures).
4. **Contract provider/consumer correctness** — for `WEB-to-DB`, assert `providers` contains `WEB` and `consumers` contains `DB`.
5. **Policy group "where used"** — for `PG-Server-VPC`, assert `where_used` contains `(101, eth1/15)`, `(101, eth1/16)`, `(102, eth1/15)`, `(102, eth1/16)`.
6. **DN validation** — passing a malformed DN to a detail endpoint returns 400.
7. **Cache key namespacing** — after a fabric-scoped call, `cache.cache_info("aci_<fid>_contracts")` returns a non-None entry.

Run via `pytest tests/test_aci_policies.py -v`. Don't break existing tests — run the full `pytest tests/` before submitting.

---

## 9. CLAUDE.md update

After implementation works, append to the "Architecture → Router layer" section in `CLAUDE.md`:

```
- `routers/aci.py` — 17 endpoints under `/api/aci/`  (BUMP THIS NUMBER)
```

…and append to the cache-key naming list:

```
- `aci_{fabric_id}_{tenants,vrfs,bridge_domains,app_profiles,contracts,filters,epg_relations,access_pgs,aaeps,domains,vlan_pools,if_pol_*,access_topology}` — ACI policy and access-policy fabric-wide caches
- `aci_{fabric_id}_contract_detail:{quoted_dn}` — per-contract detail
- `aci_{fabric_id}_pg_detail:{quoted_dn}` — per-policy-group detail (includes "where used")
- `aci_{fabric_id}_aaep_detail:{quoted_dn}` — per-AAEP detail
- `aci_{fabric_id}_epg_detail:{quoted_dn}` — per-EPG drill-down (contracts + static paths + domains)
```

Update the cache TTL table only if you add new TTL constants — you should NOT (everything reuses `TTL_ACI_STATUS`).

---

## 10. Order of work (commits)

Suggested commit-by-commit order. Each should pass tests independently:

1. **Mock fixtures** — `dev.py` additions + `clients/aci.py` DEV_MODE branches. No router changes yet. Verify by inspecting cache contents on startup.
2. **Tenant model client + endpoints + partials** — Tenants, VRFs, BDs, App Profiles, Filters (the simpler flat ones). Sidebar items.
3. **Contract model + drill-down** — Contracts list, contract detail with provider/consumer resolution.
4. **EPG drill-down** — extend existing EPG view with the detail action.
5. **Access policy groups + drill-down** — Policy groups list, the access-topology helper, policy-group detail with "where used".
6. **AAEPs, Domains, VLAN Pools** — flat lists.
7. **Interface policies combined view** — single endpoint, type-filter param.
8. **CLAUDE.md update + final test pass.**

---

## 11. Constraints / pitfalls

- **APIC URL encoding.** DNs going into URL paths MUST go through `_quote_dn()`. The existing helper handles bracketed segments correctly. **Never** raw-concatenate.
- **`children` vs `imdata`.** When you request `?rsp-subtree=children` or `=full`, children appear under the parent MO's `children` key, not at the top level. Always traverse `item[cls]["children"]`.
- **Disjoint subtree-class lists.** APIC silently drops `target-subtree-class=X,Y,Z` items when X/Y/Z aren't relations of the queried MO. Test against DEV_MODE (which does exact dict-key matches) AND read APIC docs if anything seems missing.
- **`tDn` resolution.** Many relation MOs (`fvRsCtx`, `fvRsBDToOut`, `infraRsVlanNs`, etc.) carry both `tDn` (full DN) and `tn<Class>Name` (just the name). Prefer `tn<Class>Name` for display, `tDn` for cross-references.
- **Tenant scoping.** `common` tenant policies are visible to other tenants. The UI should not hide them. When listing per-tenant, include only items whose DN starts with `uni/tn-{tenant}/` — but for contract resolution (e.g. an EPG in `PROD` consuming a contract in `common`), follow `tDn` literally and don't filter.
- **Empty fabrics.** If the queried APIC has no contracts/filters/etc., return `{"items": [], "raw": {"imdata": []}}` — never a 500. Existing endpoints already do this.
- **Concurrency.** Use the existing `get_apic_sem()` (`asyncio.Semaphore(8)`) for any fan-out gather where node count is potentially large. The access-topology endpoint is a single subtree call — no semaphore needed.
- **Error handling.** Don't catch exceptions to return success. Let `_get_aci_async` 503 propagate.
- **Read-only.** **Never** issue HTTP POST/DELETE/PUT to APIC. Don't add a `client.post()` method. All your queries are GET.

---

## 12. Acceptance criteria

You're done when:

- [ ] `DEV_MODE=true uvicorn main:app --reload` starts cleanly.
- [ ] Browsing to `/aci` shows 13 new sidebar items in two grouped sections.
- [ ] Each list view renders mock data without errors.
- [ ] Contract detail for `WEB-to-DB` shows subject `Web-Subj`, filter `ALLOW-HTTPS`, entry `tcp/443`, provider `WEB`, consumer `DB`.
- [ ] Policy group detail for `PG-Server-VPC` shows bound CDP/LLDP/LACP/Link policies with their settings, AAEP `AAEP-PROD`, and "where used" listing 4 ports across 2 nodes.
- [ ] EPG detail for `PROD/APP1/WEB` lists `WEB-to-DB` under provided contracts.
- [ ] `?fabric=all` works on every list endpoint (when 2+ fabrics configured) and the table includes a Fabric column.
- [ ] Cache widget on the page reflects the new keys with timestamps.
- [ ] `pytest tests/` passes with zero new failures.
- [ ] No new dependencies in `requirements.txt`.
- [ ] No edits to `static/bootstrap/`, `static/phosphor/`, or any vendored asset.

---

## 13. Things the user explicitly asked for / explicitly NOT in scope

**In scope:**
- Both Tenant and Access models.
- Drill-down on Contracts, EPGs, Policy Groups (highest-value views).
- Multi-fabric aggregation (`?fabric=all`).
- 15-min cache TTL via existing `TTL_ACI_STATUS`.
- Mock fixtures for DEV_MODE.

**Not in scope (do not build):**
- CSV export.
- QoS, monitoring, Taboo contracts, route-control profiles, service graphs.
- Fabric-wide policies (NTP, DNS, BGP route-reflector config).
- Anything that writes to APIC.

---

## 14. Quick-reference: key APIC class cheat sheet

| Class | What it is | Key attributes |
|---|---|---|
| `fvTenant` | Tenant | `name`, `descr` |
| `fvCtx` | VRF | `name`, `pcEnfPref`, `pcEnfDir`, `bdEnforcedEnable` |
| `fvBD` | Bridge Domain | `name`, `mac`, `arpFlood`, `unicastRoute`, `unkMacUcastAct`, `ipLearning`, `type` |
| `fvSubnet` | Subnet under BD or EPG | `ip`, `scope`, `descr` |
| `fvRsCtx` | BD → VRF rel | `tnFvCtxName`, `tDn` |
| `fvRsBDToOut` | BD → L3Out rel | `tnL3extOutName` |
| `fvAp` | Application Profile | `name`, `descr` |
| `fvAEPg` | EPG | `name`, `prio` |
| `fvRsProv` | EPG provides Contract | `tnVzBrCPName`, `tDn` |
| `fvRsCons` | EPG consumes Contract | `tnVzBrCPName`, `tDn` |
| `fvRsPathAtt` | EPG → static path bind | `tDn` (path), `encap` (vlan-N), `mode` |
| `fvRsDomAtt` | EPG → domain bind | `tDn`, `instrImedcy`, `resImedcy` |
| `vzBrCP` | Contract | `name`, `scope` |
| `vzSubj` | Contract Subject | `name`, `revFltPorts`, `consMatchT`, `provMatchT` |
| `vzRsSubjFiltAtt` | Subject → Filter | `tnVzFilterName`, `directives` |
| `vzFilter` | Filter | `name` |
| `vzEntry` | Filter Entry | `name`, `etherT`, `prot`, `dFromPort`, `dToPort`, `sFromPort`, `sToPort`, `applyToFrag`, `stateful`, `tcpRules` |
| `infraAccPortGrp` | Access Port Policy Group | `name` |
| `infraAccBndlGrp` | Bundle (PC/vPC) Policy Group | `name`, `lagT` (`node`=vPC, `link`=PC) |
| `infraRsAttEntP` | PG → AAEP | `tDn`, `tnInfraAttEntityPName` |
| `infraRsCdpIfPol` | PG → CDP pol | `tnCdpIfPolName` |
| `infraRsLldpIfPol` | PG → LLDP pol | `tnLldpIfPolName` |
| `infraRsLacpPol` | PG → LACP pol | `tnLacpLagPolName` |
| `infraRsHIfPol` | PG → Link-level pol | `tnFabricHIfPolName` |
| `infraRsMcpIfPol` | PG → MCP pol | `tnMcpIfPolName` |
| `infraRsStpIfPol` | PG → STP pol | `tnStpIfPolName` |
| `infraRsL2IfPol` | PG → L2 pol | `tnL2IfPolName` |
| `infraRsStormctrlIfPol` | PG → Storm-control pol | `tnStormctrlIfPolName` |
| `infraAttEntityP` | AAEP | `name` |
| `infraRsDomP` | AAEP → Domain rel | `tDn` |
| `infraGeneric` | AAEP static-binding container | (children carry `infraRsFuncToEpg`) |
| `physDomP` / `l3extDomP` / `vmmDomP` | Domains | `name` |
| `infraRsVlanNs` | Domain → VLAN pool rel | `tDn` |
| `fvnsVlanInstP` | VLAN Pool | `name`, `allocMode` |
| `fvnsEncapBlk` | VLAN range in pool | `from` (vlan-N), `to`, `role` |
| `cdpIfPol` | CDP IF policy | `adminSt` |
| `lldpIfPol` | LLDP IF policy | `adminRxSt`, `adminTxSt` |
| `lacpLagPol` | LACP policy | `mode`, `ctrl` |
| `fabricHIfPol` | Link-level (speed) | `speed`, `autoNeg`, `fecMode` |
| `mcpIfPol` | MCP policy | `adminSt` |
| `stpIfPol` | STP IF policy | `ctrl` (e.g. `bpdu-guard`) |
| `l2IfPol` | L2 IF policy | `qinq`, `vlanScope` |
| `stormctrlIfPol` | Storm-control | `bcRate`, `mcRate`, `uucRate` |
| `infraNodeP` | Switch Profile | `name` |
| `infraLeafS` | Leaf Selector | `name`, `type` |
| `infraNodeBlk` | Node range | `from_`, `to_` |
| `infraRsAccPortP` | Switch Profile → Interface Profile | `tDn` |
| `infraAccPortP` | Interface Profile | `name` |
| `infraHPortS` | Port Selector | `name`, `type` |
| `infraPortBlk` | Port range | `fromCard`, `toCard`, `fromPort`, `toPort` |
| `infraRsAccBaseGrp` | Port selector → Policy Group | `tDn`, `fexId` |

---

When you finish, open a PR titled `feat(aci): policy and access-policy visibility` against `main`. The PR body should list the new endpoints, sidebar additions, and a screenshot or two of the contract-detail and policy-group-detail pages running under DEV_MODE.
