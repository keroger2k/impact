# Peer Review — UI, Async Behaviour & Caching

**Scope:** UI/layout, asynchronous calls and how the UI reacts to them, and the
caching layer (the reported pain: data reloads too often for a network that
barely changes).

**How to use this doc:** Each item is self-contained — Problem → Files → Exact
change → Why. Items are ordered by impact. A change agent can work top-to-bottom;
nothing later depends on something earlier unless noted.

Severity legend: 🔴 root-cause / high impact · 🟠 medium · 🟢 polish · 🐞 bug.

---

## Part A — Caching (the main complaint)

### A1 🔴 Logical-expiry revalidation is *blocking* — this is the root cause

**Problem.** `AppCache.get_or_set` (`cache.py:68-104`) only serves stale data
when the loader **throws**. When an entry is merely *logically expired* (TTL
elapsed) but the upstream is healthy, it calls `loader()` **synchronously** and
the user's request blocks for the full upstream fetch (DNAC inventory, ISE
lists, Panorama walk, ACI class queries — seconds to minutes).

So even though the network "isn't changing much," every time a TTL rolls over
the *next* person to open that page eats a cold fetch. That is exactly the
"constantly reloading / causing me issues" symptom. The fix is **stale-while-
revalidate on latency**, not just on error: serve the cached value instantly and
refresh in the background.

**Files.** `cache.py`.

**Change.** Add a background-refresh path to `get_or_set`. Keep the signature
and all call-sites unchanged; add an opt-out for the few keys that must be fresh.

```python
# cache.py — near top of AppCache.__init__
import threading
from concurrent.futures import ThreadPoolExecutor
# ...
        self._refresh_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cache-swr")
        self._refreshing: set[str] = set()
        self._refresh_lock = threading.Lock()

    def _background_refresh(self, key, loader, ttl):
        # Dedupe: only one in-flight refresh per key (avoids stampede when
        # several tabs hit an expired key at once).
        with self._refresh_lock:
            if key in self._refreshing:
                return
            self._refreshing.add(key)
        def _run():
            try:
                data = loader()
                if data is not None:
                    self.set(key, data, ttl)
                    self._last_errors.pop(key, None)
            except Exception as e:
                logger.error(f"Background cache refresh failed for '{key}': {e}")
                self._last_errors[key] = {"at": time.time(), "message": str(e)[:500]}
            finally:
                with self._refresh_lock:
                    self._refreshing.discard(key)
        self._refresh_pool.submit(_run)
```

Then rewrite the "logically expired" branch of `get_or_set` (currently
`cache.py:81-91`) to serve stale and refresh in the background:

```python
        if entry is not None:
            data, expires_at, _ = entry
            if now < expires_at:
                return data
            # Logically expired but physically present: serve stale instantly,
            # refresh in the background (stale-while-revalidate).
            if background:
                self._background_refresh(key, loader, ttl)
                return data
            # Legacy blocking revalidation (kept for callers that opt out).
            try:
                new_data = loader()
                if new_data is not None:
                    self.set(key, new_data, ttl)
                    self._last_errors.pop(key, None)
                    return new_data
            except Exception as e:
                logger.error(f"Cache revalidation failed for key '{key}', returning stale data: {e}")
                self._last_errors[key] = {"at": time.time(), "message": str(e)[:500]}
                return data
```

Add `background: bool = True` to the `get_or_set` signature (`cache.py:68`).
Close the pool on shutdown next to `cache._cache.close()` (`main.py:63`):
`cache._refresh_pool.shutdown(wait=False)`.

**Net effect.** First load of a cold key still blocks (unavoidable). After that,
pages are always instant; freshness arrives a moment later on the *next* poll/
navigation. The user stops feeling the every-TTL stall.

**Don't apply background mode to:** `status_*` connectivity probes and
`dnac_config_search_result:*` (a stale search result is misleading). Pass
`background=False` at those call-sites, or simpler: leave those on `cache.get`/
`cache.set` as they already are. The status checks in `utils/system_status.py`
already use plain `cache.get`/`cache.set`, so no change needed there.

---

### A2 🔴 TTLs are far too short for this network — raise the defaults

**Problem.** Defaults in `cache.py:21-34` assume volatile data. For a TSA
network that "isn't changing much," they cause needless churn (and, combined
with A1's blocking revalidation, needless stalls). Worst offenders:

| Constant | Current | Recommend | Reasoning |
|---|---|---|---|
| `TTL_DEVICES` | 4h | **24h** | Inventory changes are rare and there's an explicit refresh button. |
| `TTL_SITES` | 4h | **24h** | Site hierarchy almost never changes. |
| `TTL_ISE_POLICIES` | 1h | **12h** | NADs/SGTs/policy sets are config, not telemetry. |
| `TTL_ACI_STATUS` | 15m | **2h** | This is the noisiest one — drives most "expired" widget churn. Nodes/L3Outs/BGP-OSPF maps are topology, not live counters. |
| `TTL_ACI_ROUTE_TABLE` | 5m | **30m** | Route tables shift slowly in this fabric. |
| `TTL_DNAC_INTERFACES` | 4h | **24h** | Interface inventory is stable. |
| `TTL_PAN_POLICY` | 1h | **12h** | Firewall policy is change-controlled. |

Leave `TTL_STATUS` (5m — connectivity probe, should stay live-ish),
`TTL_CONFIG_SEARCH_RESULT` (5m — just a download cache), and the already-long
24h/48h ones (`DNAC_ROUTER_CONFIGS`, `DNAC_IP_POOLS`, `PAN_INTERFACES`,
`TUNNEL_INVENTORY`) as-is.

**Files.** `cache.py:22-31` — change the integer defaults only. Every one is
already env-overridable (`IMPACT_TTL_*`), so this is purely a default change.

**Change.** Edit the fallback strings, e.g.:
```python
TTL_DEVICES         = int(os.getenv("IMPACT_TTL_DEVICES",        "86400"))  # 24h (was 4h)
TTL_SITES           = int(os.getenv("IMPACT_TTL_SITES",          "86400"))  # 24h (was 4h)
TTL_ISE_POLICIES    = int(os.getenv("IMPACT_TTL_ISE_POLICIES",   "43200"))  # 12h (was 1h)
TTL_ACI_STATUS      = int(os.getenv("IMPACT_TTL_ACI_STATUS",      "7200"))  # 2h (was 15m)
TTL_ACI_ROUTE_TABLE = int(os.getenv("IMPACT_TTL_ACI_ROUTE_TABLE", "1800"))  # 30m (was 5m)
TTL_DNAC_INTERFACES = int(os.getenv("IMPACT_TTL_DNAC_INTERFACES","86400"))  # 24h (was 4h)
TTL_PAN_POLICY      = int(os.getenv("IMPACT_TTL_PAN_POLICY",     "43200"))  # 12h (was 1h)
```

**Also update `CLAUDE.md`** (the Cache layer table) so the documented defaults
match. Search for the table containing `TTL_DEVICES` / `48h` / `4h`.

---

### A3 🟠 The Cache Health widget makes the cache *look* broken → triggers manual reload storms

**Problem.** Two compounding UX issues turn a healthy cache into a perceived
problem, prompting the user to mash "refresh":

1. **Status is driven by short TTLs.** With ACI at 15m (A2), the widget flips to
   "partial/expired" within minutes of every warm. `_get_system_status`
   (`routers/cache_mgmt.py:118-149`) marks a system non-warm the instant its
   primary key is logically expired — even though the data is physically present
   and perfectly usable for a stable network.
2. **Secondary keys are counted before they're ever populated.** A system shows
   "partial" until the user visits every sub-page (e.g. ACI faults/EPGs, ISE
   authz profiles are only fetched on demand). So the widget shows yellow on a
   perfectly healthy system.

**Files.** `routers/cache_mgmt.py:118-149` (`_get_system_status`),
`templates/partials/cache_widget.html`.

**Change.**
- Base "warm vs stale" on **physical presence**, not logical expiry. Add a
  helper that reads the raw entry age and treats "present but past TTL" as
  `stale` (amber, informational) rather than `empty` (red). Reserve `empty` for
  truly-missing keys. With A1 in place, "stale" is harmless — it auto-refreshes.
- Stop letting un-visited secondary keys downgrade a system to `partial`. Either
  (a) compute status from `count_key` only, or (b) only consider secondary keys
  that have *ever* been set. Simplest: drop the `any_warm`/`partial` tri-state
  and show two states — `warm` (primary present) / `empty` (primary missing) —
  plus an age label.
- In `cache_widget.html`, change the messaging: instead of red "empty" for a
  past-TTL key, show the age ("4h ago") in muted text. Only show red for never-
  loaded.

**Why.** This removes the false "your cache is stale, reload me" signal that is
driving the reload behaviour. Pair with A1+A2 and the widget should sit green.

---

### A4 🟠 Polling cadence is too aggressive for metadata that rarely changes

**Problem.** Several pollers fire on every open tab regardless of whether the
underlying thing changed:

| What | Where | Now | Recommend |
|---|---|---|---|
| Cache Health widget | `templates/base.html:125` | `every 30s` | **every 120s** (it's cache *metadata*, not data) |
| Cache Management cards | `templates/pages/cache_management_content.html:23` | `every 30s` | **every 60s** |
| System health bar | `templates/base.html:157` | `every 60s` | OK (live probes, 5-min cached) — leave |
| Tunnel stats | `templates/pages/tunnels_content.html:13` | `every 60s` | **load only** — inventory only changes on manual refresh (`_get_or_build` never rebuilds, `routers/tunnels.py:130-137`), so polling re-renders identical data |
| ISE live auth | `templates/partials/ise_live_auth.html:4` | `every 30s` | OK (genuinely live) — leave |

**Files / change.** Edit the `hx-trigger` strings in the four rows above.
For tunnel stats, change `hx-trigger="load, every 60s"` → `hx-trigger="load"`.

**Why.** Each poll is an authenticated request + DB reads + a partial re-render
that resets transient DOM state. At 30s the widget alone is ~120 requests/hour
per tab for data that changes maybe once a day.

---

### A5 🟢 Remove dead/duplicated status-check code in `cache.py`

**Problem.** `cache.py` carries a whole second connectivity-check stack that is
never called in production:
- `check_all_systems` (`cache.py:219-234`) — **no callers** (verified by grep).
- `_check_dnac/_check_ise/_check_panorama` + `__check_*_internal`
  (`cache.py:236-270`) and the `status_dnac/status_ise/status_panorama` keys —
  the live path is `utils/system_status.py` using `status_*_live` keys. The
  non-`_live` keys are only ever written by `dev.py` mocks.

This is confusing (two status systems, two key namespaces) and invites bugs.

**Change.** Delete `check_all_systems` and the four `_check_*`/`__check_*`
methods from `cache.py`. Leave `utils/system_status.py` as the single source of
truth. (Keep the `dev.py` mock seeds or drop the now-unread `status_dnac` mock
writes — cosmetic.)

**Why.** Less surface area, one obvious status path.

---

### A6 🟢 `cache.get` hides physically-present data from read-only displays

**Problem.** `cache.get` (`cache.py:49-58`) returns `None` once logically
expired, even though the value lives on disk for 30 days. Pure display readers
that call `cache.get` directly — IPAM page (`routers/pages.py:269`), tunnel
stats/inventory (`routers/tunnels.py:134,220`) — therefore show "empty" the
moment the TTL rolls, until a manual rebuild. For these, stale data beats empty.

**Change.** Add `cache.get_stale(key)` that returns the value regardless of
logical expiry (still respecting the 30-day physical bound), and use it in the
read-only display paths above. Or have those callers fall back to stale when
`get` returns `None`.

```python
    def get_stale(self, key):
        entry = self._cache.get(key)
        return entry[0] if entry is not None else None
```

**Why.** A 25-hour-old tunnel inventory is still useful; a blank page is not.

---

## Part B — Asynchronous calls & how the UI reacts

### B1 🔴 The Dashboard blocks the whole page swap on live, uncached calls

**Problem.** `GET /dashboard` (`routers/pages.py:47-95`) renders server-side and
`await`s, in series, before returning any HTML:
1. `device_stats` (cached — fine),
2. `dc.get_recent_issues(dnac)` — **not cached at all** (`clients/dnac.py:440`),
   a live DNAC `/issues` call on *every* dashboard open,
3. `get_system_status` — 4 connectivity probes,
4. ACI health **and** faults — two more live ACI calls when ACI is up.

Because the sidebar navigates with `hx-get="/dashboard"` into `#main-content`,
the entire content area is blank (progress bar stalled at ~70%, see
`base.html:303-313`) until the slowest of those resolves. On a slow upstream the
dashboard can hang many seconds with no content.

**Files.** `routers/pages.py:47-95`, `templates/pages/dashboard_content.html`,
plus new small partial endpoints.

**Change.** Adopt the lazy-load pattern the app already uses well on
ISE/ACI/Firewall: return the shell immediately, then load each card via
`hx-trigger="load"` with an `hx-indicator`.

1. Make `/dashboard` return only the KPI shell + empty card containers (it can
   still inline the cheap cached `device_stats`).
2. Add partial endpoints (or reuse existing): 
   - `GET /api/dnac/recent-issues` → renders the events table partial,
   - the status pips already come from `/partials/status` (B2),
   - `GET /api/aci/health-summary` + faults already exist as logic functions —
     wrap them as partial endpoints.
3. In `dashboard_content.html`, replace the inlined `{{ issues }}` / `{{ aci_* }}`
   blocks with:
   ```html
   <div hx-get="/api/dnac/recent-issues" hx-trigger="load"
        hx-indicator="#issues-loading">…spinner…</div>
   ```
4. **Cache `get_recent_issues`.** Wrap the call in `get_or_set("dnac_issues",
   …, ttl=900)` (15m) in `clients/dnac.py:440` or at the call-site. It is the
   one truly-uncached upstream call on the hottest page.

**Why.** Dashboard paints instantly; each card fills in independently; one slow
system can't blank the whole page.

---

### B2 🟠 System-status probes run sequentially with a 10s timeout each

**Problem.** `get_system_status` (`utils/system_status.py:20-33`) loops the four
systems and `await asyncio.wait_for(checker(...), timeout=10)` **one at a time**.
On a cold cache with one dead system, the health bar can take up to ~10s × N
before returning. The individual checkers are already async and independently
cached (`status_*_live`, 5m), so the only reason this is slow is the serial loop.

**Files.** `utils/system_status.py:20-33`.

**Change.** Run them concurrently:
```python
    async def _run(name, checker):
        try:
            return name, await asyncio.wait_for(checker(session, loop), timeout=10)
        except asyncio.TimeoutError:
            return name, {"ok": False, "detail": "Timeout"}
        except Exception as e:
            return name, {"ok": False, "detail": str(e)[:80]}

    pairs = await asyncio.gather(*[_run(n, c) for n, c in systems])
    for name, res in pairs:
        if name == "aci" and isinstance(res, dict) and any(k.startswith("aci_") for k in res):
            results.update(res)
        else:
            results[name] = res
```
(`_check_aci` already fans out per-fabric with `gather` internally — good.)

**Why.** Worst-case health-bar latency drops from ~40s to ~10s, and the common
case is one round-trip.

---

### B3 🟠 No visible error state when an htmx panel fails

**Problem.** Panels load via `hx-get` with an `hx-indicator` spinner, but there
is no `htmx:responseError` handling. On a 4xx/5xx (e.g. the A-tier bug in C1, or
an upstream 503), htmx by default does **not** swap, so the spinner hides and the
target keeps its previous content (often the empty placeholder) with no message.
The user sees a silent no-op.

**Files.** `templates/base.html` (global handler), partial targets.

**Change.** Add a global htmx error toast in `base.html`'s script block:
```js
document.body.addEventListener('htmx:responseError', function (e) {
  showToast(`Request failed (${e.detail.xhr.status}). Try refreshing.`, 'error');
});
document.body.addEventListener('htmx:sendError', function () {
  showToast('Network error — server unreachable.', 'error');
});
```
There is already a `#toast-container` (`base.html:170`) but **no `showToast`
implementation** — add a minimal one (create a `.toast` node, auto-dismiss). This
also fixes other code paths that assume toasts exist.

**Why.** Failures become visible instead of looking like a hung/blank panel —
which is part of why caching "feels" flaky.

---

### B4 🟢 ACI sidebar re-fetches on every tab click (no client memo)

**Problem.** Every ACI sidebar button is a fresh `hx-get` with no `once`
(`aci_content.html:24-84`), so flipping between Nodes/L3Outs/BGP re-hits the API
each time. With A2's longer TTL the upstream is cached, so this is cheap, but it
still re-renders and loses scroll/sort state on every click.

**Change (optional polish).** Not worth a big refactor. If desired, switch the
result container to keep per-tab panes in the DOM (Bootstrap tab-panes with
`hx-trigger="… once"` per pane, like `aci_tenant_detail.html` already does at
lines 17-41). Low priority given caching makes it fast.

---

## Part C — Bugs found while reviewing

### C1 🐞 ACI cache refresh is broken — `NameError` on every call

**Problem.** `refresh_specific_cache` (`routers/cache_mgmt.py:369`) has signature
`(category: str, session: ...)` — **no `request` parameter** — but the `aci`
branch reads `request.query_params.get("fabric")` (`cache_mgmt.py:441`). This
raises `NameError: name 'request' is not defined` → 500 for **any** ACI refresh
(the line runs whether or not a fabric is given). The "Refresh ACI" button on the
Cache Management page and the widget is dead.

**Files.** `routers/cache_mgmt.py:369,441`.

**Change.** Add `request: Request` to the signature (mirror the pattern used by
`get_cache_status`/`get_cache_widget` in the same file, which already inject
`Request`):
```python
async def refresh_specific_cache(category: str, request: Request,
                                 session: SessionEntry = Depends(require_auth)):
```
`Request` is already imported (`cache_mgmt.py:3`). Verify with a quick manual
hit: `POST /api/cache/refresh/aci?fabric=<id>`.

---

### C2 🐞 "Clear Application Cache" wipes warm data with no re-warm and a full reload

**Problem.** The topbar button (`base.html:145-150`) POSTs
`/api/cache/refresh/clear_all` → `cache.clear()` (`cache_mgmt.py:461-463`) which
nukes **everything** (devices, sites, ISE, ACI, IPAM, tunnels…), then the
`hx-on::after-request` does `window.location.reload()`. After that, the next
page load finds a cold cache and — given A1's blocking revalidation — the user
eats full cold fetches on whatever they open next. It's a foot-gun sitting in the
global topbar.

**Change.** Either (a) move it off the global topbar into the Cache Management
page behind a confirm dialog, or (b) keep it but kick off a background re-warm
after clearing (`asyncio.create_task(cache.warm())` plus ISE/Panorama/ACI
re-fetch helpers that already exist in `cache_mgmt.py`). At minimum add a
`confirm()` before the POST. Recommend (a)+confirm.

**Why.** A single mis-click currently degrades the app for minutes.

---

### C3 🟢 Devices page ships the entire inventory as inline JSON

**Problem.** `/devices` inlines `{{ initial_devices | tojson }}` for up to 5000
devices into the swapped HTML (`devices_content.html:88`,
`routers/pages.py:101` calls `get_devices_data(limit=5000)`). That's a large
(potentially MB-scale) blob parsed on every navigation to the page, and the page
*also* has a `fetch('/api/dnac/devices?limit=5000')` fallback. Data is cached so
it's not an upstream cost, but it bloats the partial and the client parse.

**Change (optional).** Drop the inline JSON; always load via the existing
`fetch(...)` path on first render (the JS already supports an empty
`ALL_DEVICES`). Or paginate server-side. Low urgency.

---

## Part D — Layout / visual polish (low priority)

- **D1 🟢 Inline `<style>`/`<script>` blocks live inside swapped partials**
  (`ise_content.html:139-157`, `aci_content.html:100-163`,
  `dashboard_content.html:182-184`, `devices_content.html:239-244`). On every
  htmx swap these re-inject duplicate `<style>` and re-run `<script>`. It works
  but accretes duplicate style nodes. Consider moving the static CSS into
  `static/app.css` and the helpers (`setActive`, `switchFabric`) into a small
  shared JS file loaded once in `base.html`.

- **D2 🟢 `alert()` used for user feedback** (`base.html:148` clear-cache,
  `devices_content.html:224/232` Nexus refresh). Native `alert()` is blocking and
  jarring; route these through the `showToast` added in B3.

- **D3 🟢 Two date/age formatters and status vocabularies** (`cache_mgmt.py`
  `_fmt_age`/`_fmt_time` vs. inline template logic). Minor; consolidate if you
  touch the widget for A3.

- **D4 🟢 Sidebar collapse state** reads `localStorage` in an inline script in
  `base.html:213-222` that can briefly flash on slow loads. Acceptable; only fix
  if you're already in there.

---

## Suggested execution order (for the change agent)

1. **C1** (one-line bug fix, unblocks ACI refresh).
2. **A2** (change TTL default integers — trivial, immediate relief).
3. **A1** (background revalidation — the big perceived-speed win).
4. **B1** + cache `get_recent_issues` (dashboard stops blocking).
5. **A3** + **A4** (stop the false-stale signal and over-polling).
6. **B2** (parallel status probes).
7. **B3** (`showToast` + htmx error handlers) — also unblocks D2.
8. **A5, A6, C2, C3, D1–D4** as cleanup.

After 1–4 the "reloads too often / feels slow" complaint should be largely gone:
data is cached far longer, expiry no longer blocks, the dashboard paints
instantly, and the widget stops nagging you to refresh.

---

## Verification checklist

- `pytest tests/` still green (no test currently covers `get_or_set` background
  mode — consider adding one that asserts stale is returned immediately and the
  value updates after the pool drains).
- Manual: open each top-level page twice; second open should be instant.
- Manual: `POST /api/cache/refresh/aci?fabric=<id>` returns 200, not 500.
- Manual: kill one upstream (or point it at a bad host) and confirm the health
  bar still returns in ~10s and panels show an error toast rather than hanging.
- Watch `logs/` for `Background cache refresh failed` lines to confirm SWR is
  exercising the background path.
