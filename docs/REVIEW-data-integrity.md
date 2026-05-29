# Peer Review — Part 3: Data Integrity, Partial-Failure & Test Coverage

**Scope:** the IP-registry persistence + write path (`clients/ip_registry.py`,
`routers/ip_registry.py`), the reconcile engine (`utils/ip_audit.py`), the large
async modules (`routers/aci.py`, the tunnel/IPsec parsers), and test-coverage
gaps in security-critical paths.

**Overall:** the read/compute side is in good shape — the audit engine and the
tunnel inventory build both isolate per-source / per-device failures cleanly, and
the ACI cross-fabric aggregation tolerates a down fabric. The findings are
concentrated in the **registry write path** (atomicity + a uniqueness gap on
shared containers) and in **missing tests** for the command-runner safety checks
and the SSE limiter.

Severity: 🔴 high · 🟠 medium · 🟢 hardening · 🐞 bug · ✅ positive (no action).

---

## R1 🟠 `/audit/accept` bulk commit is not atomic (one transaction per row)

**Problem.** Every registry helper opens its *own* connection+transaction via
`connect()` (`clients/ip_registry.py:132-147`). The bulk-accept loop
(`routers/ip_registry.py:319-364`) calls `upsert_site`, `get_or_create_container`
and `create_prefix` **per item**, so accepting M drift items is M+ independent
commits. If the request is interrupted (worker restart, client disconnect, an
exception partway), the registry is left in a **partially-committed** state — some
sites/prefixes in, others not — with no rollback. The same applies to
`scripts/import_registry.py` if it loops the per-row helpers.

**Fix.** Give the registry a single-transaction batch entry point and have the
router prepare/validate first, then commit once.

1. Let helpers share a connection. Add an optional `conn` param to the low-level
   ops, or (simpler, less churn) add one purpose-built function:
   ```python
   # clients/ip_registry.py
   def bulk_accept(items: list[dict], path=None) -> dict:
       """Commit a validated batch in ONE transaction. Each item is one of:
         {"container": True, "cidr", "role"?, "label"?}
         {"cidr", "site_id"|"site_code", "role"?, "vlan_id"?, "label"?}
       Returns {created, skipped, sites_created, errors}. Rolls back on a hard error."""
       created = skipped = 0
       sites_created, errors = [], []
       with connect(path) as conn:           # one transaction
           for it in items:
               # ...inline the INSERT/SELECT logic using `conn` directly...
       return {...}
   ```
   Move the DB logic from the router loop into here; the router keeps the JSON
   parsing/validation and calls `registry.bulk_accept(prepared)`.
2. Decide the failure policy explicitly: either **all-or-nothing** (any hard
   error rolls the whole batch back) or **best-effort with a savepoint per item**
   (`conn.execute("SAVEPOINT s")` / `RELEASE` / `ROLLBACK TO` so one bad row
   doesn't poison the rest). Best-effort matches today's behaviour; make it
   deliberate rather than accidental.

**Why.** A half-applied accept is hard to reason about and to undo; the operator
sees "created: 7, errors: 3" with no idea whether the 7 survived a later failure.

---

## R2 🟠 Duplicate shared containers are possible (UNIQUE gap + TOCTOU)

**Problem.** Shared aggregates are `prefixes` rows with `site_id IS NULL`. The
table's only guard is `UNIQUE(site_id, cidr)` (`ip_registry.py:98`) — but SQLite
treats `NULL` as **distinct**, so two rows with `site_id=NULL` and the *same*
`cidr` do **not** violate it. `get_or_create_container` (`:360-372`) does a
find-then-create with no constraint backing it, so two concurrent accepts (two
operators, or a double-click) of the same STIP /48 or DMVPN overlay can both find
nothing and both insert → **duplicate containers**, which then split children and
corrupt the tree rollup.

**Fix.** Add a partial unique index so the DB enforces one container per CIDR:
```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_prefixes_container_cidr
    ON prefixes(cidr) WHERE site_id IS NULL;
```
Add it to `SCHEMA` (it's `IF NOT EXISTS`, so safe on existing DBs). Then
`get_or_create_container` should treat an `IntegrityError` as "someone else just
created it" and re-`find` rather than propagate:
```python
    try:
        row = create_prefix(cidr, site_id=None, role=role, ...)
        return row, True
    except sqlite3.IntegrityError:
        return find_prefix_by_cidr(cidr, site_id=None, path=path), False
```
(One-time cleanup: if any duplicate `site_id IS NULL` containers already exist,
the index creation will fail until they're de-duped — add a tiny migration that
collapses dupes by re-pointing children to the lowest id, then deletes the rest.)

---

## R3 🟢 Audit-accepted prefixes get no `parent_id` (tree is flat for them)

**Problem.** `audit_accept` always calls `create_prefix(..., )` with no
`parent_id` (`routers/ip_registry.py:355-358`). The self-FK hierarchy that the UI
tree renders (`parent_id`, `ip_registry.py:19-21`) is therefore never populated
for accepted rows — a /64 accepted under a STIP /48, or a subnet under a site
aggregate, lands as a sibling of its parent instead of a child.

**Fix.** After canonicalising each accepted CIDR, look up the tightest enclosing
prefix in the same scope (the container for `container` children; the site's
aggregate/`/56` for site children) and set `parent_id`. `ipam_net` already has
the containment math (`find_overlaps` / a "smallest enclosing" helper). Do it
inside the `bulk_accept` transaction from R1 so the parent lookup sees rows
created earlier in the same batch.

---

## R4 🟢 Bulk-accept silently bypasses overlap detection

**Problem.** The manual `POST /prefixes` path runs `find_overlapping_prefixes`
and soft-409s unless `confirm_overlap=true` (`routers/ip_registry.py:206-213`).
`audit_accept` calls `registry.create_prefix` directly, so accepted prefixes can
introduce overlaps with no signal. This is arguably *correct* (you're accepting
observed reality), but it's undocumented and inconsistent.

**Fix.** Low priority — keep the bypass but record it: stamp accepted rows that
overlap an existing prefix with a note/label (e.g. `audit_state` or a
`description` suffix) so the operator can find them later, and say so in the
endpoint docstring.

---

## R5 🟢 `vlan_id` from accept payload is not validated

**Problem.** `audit_accept` passes `vlan_id=it.get("vlan_id")` straight through
(`routers/ip_registry.py:357`), unlike the manual path which runs `_parse_vlan`
(range 1–4094, int coercion). A malformed JSON value (`"abc"`, `99999`) is stored
as-is (SQLite is typeless).

**Fix.** Route accepted `vlan_id` through `_parse_vlan` too (catch and convert to
a per-item error rather than a 400 for the whole batch).

---

## A1 🟢 ACI cross-fabric aggregation hides which fabric failed

**Problem.** `?fabric=all` endpoints wrap each fabric in a per-fabric
`try/except` that returns empty on failure (e.g. `routers/aci.py:317-327`) — so
the aggregate is resilient (one down fabric doesn't blank the view ✅) but the
failure is **silent**: the operator sees fewer nodes/tenants with no hint that a
fabric is unreachable. (Note: most of these `gather(...)` calls also omit
`return_exceptions=True`; that's currently harmless *only* because every
`_fetch_single` swallows its own exceptions — it's load-bearing, so keep it.)

**Fix.** Have `_fetch_single` return a small per-fabric status alongside its data
(`{"fabric": f.id, "ok": False, "error": ...}`) and surface a compact "N/M
fabrics responded" banner in the aggregated partials. Hardening/observability,
not a correctness bug.

---

## Test coverage gaps

### T1 🟠 The command-runner safety checks have no tests
`routers/commands.py` enforces the allow-list (`show/display/get/ping/
traceroute`), single-line, 256-char cap, `COMMANDS_ENABLED`/`CONFIG_CHANGES_ENABLED`
gating, and the `DEPLOY` confirmation. None of this — the app's most
safety-critical surface — is covered by a test. A regression here could silently
permit arbitrary or multi-command input.

**Fix.** Add `tests/test_commands_guard.py` asserting: non-allowlisted command →
400; embedded newline/tab → 400; over-length → 400; disabled flag → 403;
config-run without `confirm == "DEPLOY"` → 400; over device/line caps → 400.
These are pure request-validation paths (use `fastapi.testclient` with
`COMMANDS_ENABLED` toggled), no SSH needed.

### T2 🟢 The SSE concurrency limiter (just fixed in Part 2/S2) has no test
**Fix.** Add a test that opens the limited number of concurrent streams and
asserts the next one gets 429, then that a slot frees after a stream ends — to
lock in the body-iterator-release fix so it can't silently regress.

### T3 🟢 The CSRF middleware has no direct test
**Fix.** Assert: GET is exempt; a mutating request without `X-CSRF-Token` →403;
matching cookie+header →pass; `Bearer` requests are exempt.

---

## Positives (no action)

- ✅ `utils/ip_audit.collect_observed` isolates each source extractor in
  try/except (`:344-351`) — one platform's bad data can't abort the audit; the
  `reconcile` classifier is pure and well covered by `tests/test_ip_audit.py`.
- ✅ Tunnel inventory build isolates per-device parse failures
  (`routers/tunnels.py:112-115`) and logs+continues.
- ✅ ACI cross-fabric merges are resilient to a single fabric error (A1).
- ✅ `connect()` has correct commit-on-success / rollback-on-error semantics and
  enables `foreign_keys = ON` per connection; the schema uses `ON DELETE CASCADE`
  for a site's prefixes and `ON DELETE SET NULL` for `parent_id`.

---

## Suggested order

1. **R2** — partial unique index + IntegrityError-as-found (stops duplicate
   containers; small, schema-level, high value).
2. **R1** — `bulk_accept` single-transaction batch (also the natural home for R3
   and R5).
3. **R3 / R5** — parent linkage + vlan validation, inside the new batch.
4. **T1** — command-runner guard tests (security-critical, cheap).
5. **A1 / R4 / T2 / T3** — observability + remaining tests.
