# Peer Review — Part 2: Security, Auth & Robustness

**Scope:** the areas not covered by Part 1 (UI/async/caching) — authentication,
session/cookie handling, CSRF, the SSH command runner, Panorama XML, concurrency
correctness, and general robustness.

**Overall:** the security posture is mostly good. Credentials never appear in
request payloads; SSL verification is env-gated; the command runner is tightly
gated; there are no `shell=True`/`eval`/`exec` calls and no bare `except:`
clauses; persisted sessions are Fernet-encrypted with proper key validation.
The findings below are a small number of real gaps plus hardening suggestions.

Severity: 🔴 high · 🟠 medium · 🟢 hardening · 🐞 bug.

---

## S1 🔴 The live login path sets the session cookie without security flags

**Problem.** There are two login paths and they disagree on cookie security:

- `routers/auth.py:37-44` (`POST /api/auth/login`, JSON) sets `impact_token`
  with `httponly=True, secure=<IMPACT_SECURE_COOKIES>, samesite="strict",
  max_age=…` — correct.
- `routers/pages.py:31-34` (`POST /login`, the **HTML form** that the login page
  actually submits — `templates/login.html:24` `<form action="/login">`) sets it
  with **no flags at all**:
  ```python
  response.set_cookie(key="impact_token", value=token)
  response.set_cookie(key="impact_user", value=username)
  ```

Since the form path is the one real users hit, the session token in practice is:
- **readable by JavaScript** (no `httponly`) → any XSS becomes full session
  takeover,
- **sent over plaintext HTTP** (no `secure`),
- **sent on cross-site requests** (no `samesite`).

The token is the entire session bearer (it maps to in-memory AD creds), so this
is the most important finding in Part 2.

**Fix.** Make `pages.py` login mirror `routers/auth.py`. Factor the cookie flags
into one helper so they can't drift again:

```python
# auth.py (or a small util)
import os
def session_cookie_kwargs() -> dict:
    from dev import DEV_MODE
    secure = os.getenv("IMPACT_SECURE_COOKIES", "true").lower() == "true"
    if DEV_MODE and os.getenv("IMPACT_SECURE_COOKIES") is None:
        secure = False
    return {"httponly": True, "secure": secure, "samesite": "strict",
            "max_age": int(SESSION_TTL)}
```
Then in `pages.py:login_submit`:
```python
    response.set_cookie("impact_token", token, **auth_module.session_cookie_kwargs())
    # impact_user is cosmetic (the topbar name); still scope it.
    response.set_cookie("impact_user", username, secure=..., samesite="strict")
```
And refactor `routers/auth.py:37-44` to call the same helper.

**Verify.** Log in via the form, inspect the `impact_token` cookie in devtools →
`HttpOnly` ✓, `Secure` ✓ (prod), `SameSite=Strict` ✓.

---

## S2 🐞 The SSE concurrency limiter doesn't actually limit anything

**Problem.** `sse_rate_limit` (`main.py:80-95`) increments a counter, calls
`await call_next(request)`, then decrements in `finally`. For a
`StreamingResponse` under Starlette's HTTP-middleware model, `call_next` returns
as soon as the **response object** is ready — the body generator streams to the
client *after* `dispatch` returns. So the `finally` decrements the counter almost
immediately, while the stream is still running. Net effect: the "max 2 concurrent
streams per (session, path)" cap (documented in `CLAUDE.md`) never meaningfully
holds — a user can open many concurrent `/api/warm` / refresh / command streams
and exhaust the thread pools behind them.

**Fix.** Decrement only when the stream genuinely ends. Two options:

1. **Wrap the generator** (smallest change) — move the counter accounting around
   the response body rather than around `call_next`:
   ```python
   sse_limit_tracker[key] = sse_limit_tracker.get(key, 0) + 1
   response = await call_next(request)
   orig = response.body_iterator
   async def _counted():
       try:
           async for chunk in orig:
               yield chunk
       finally:
           sse_limit_tracker[key] = max(0, sse_limit_tracker.get(key, 0) - 1)
   response.body_iterator = _counted()
   return response
   ```
   (If `call_next` raised before returning a response, decrement in an `except`.)
2. Convert `sse_rate_limit` to a pure ASGI middleware that wraps `send` and
   decrements on the final `http.response.body` with `more_body=False`.

Either way, also guard the increment/decrement with a lock or use
`collections.Counter` carefully — concurrent requests mutate `sse_limit_tracker`
from multiple tasks. (Single-threaded asyncio makes the dict ops atomic enough in
practice, but the read-modify-write of `.get()+1` is still racy across `await`
points; a small lock or `defaultdict(int)` with care is cleaner.)

---

## S3 🟢 XPath values are string-interpolated in Panorama config reads

**Problem.** Several `config get` calls build XPath with f-strings, e.g.
`clients/panorama.py:923` `f"{dg_base}/entry[@name='{dg}']/devices"` and `:939`
`f"/config/devices/entry[@name='{device_serial}']/vsys"`. A value containing a
single quote would break the predicate (XPath injection in principle). Risk is
**low** because `dg`/`device_serial` are enumerated from Panorama itself, not
user input — and `CLAUDE.md` already steers new op-commands through
`op_via_sdk(...)` for exactly this reason.

**Fix (hardening).** For the remaining xpath-driven reads (where the SDK has no
equivalent), assert/escape the interpolated name:
```python
if "'" in dg or "]" in dg:
    raise PanoramaAPIError(f"Refusing unsafe device-group name: {dg!r}")
```
or switch to the `concat()`/double-quote form. Low priority; document the
assumption that these names are system-sourced.

---

## S4 🟢 No rate limiting on login

**Problem.** Neither `POST /login` (`pages.py:25`) nor `POST /api/auth/login`
(`routers/auth.py:19`) throttles attempts. An attacker (or a buggy script) can
brute-force AD credentials through the app, and — worse for an internal tool —
trip **AD account lockout** for real users by hammering a username.

**Fix.** Add a lightweight in-memory throttle keyed by `(client_ip, username)`:
e.g. after N failed binds in M minutes, return 429 with a short backoff. Keep it
in-process (a dict with timestamps) to match the rest of the app's stateless-ish
model; no new dependency needed.

---

## S5 🟢 Sessions slide forever — no absolute lifetime cap

**Problem.** `require_auth` (`auth.py:174-175`) resets `expires_at = now +
SESSION_TTL` on **every** authenticated request. A continuously-used session (or
a stolen-but-active token) never expires. `SESSION_TTL_HOURS` is therefore only
an *idle* timeout, not a maximum lifetime.

**Fix (optional).** Record `created_at` on `SessionEntry` and refuse to slide
past an absolute cap (e.g. `IMPACT_SESSION_MAX_HOURS`, default 24h):
```python
if time.monotonic() > session.created_at + SESSION_ABS_MAX:
    raise HTTPException(401, "Session expired (max lifetime)")
```
Decide based on operator tolerance for re-login frequency.

---

## S6 🟢 CSRF cookie + token are not bound to the session, and lack `secure`

**Problem.** `set_csrf_cookie` (`utils/csrf.py:30-38`) issues a random token in a
non-`httponly` cookie and the middleware checks cookie==header (double-submit).
That's a valid pattern, but: (a) the cookie has no `secure` flag, so it rides
plaintext HTTP; (b) the token isn't tied to the session, so it isn't invalidated
on logout/rotation. Double-submit is generally fine here (an attacker can't read
the cookie cross-origin to forge the header), so this is hardening, not a hole.

**Fix.** Add `secure=<IMPACT_SECURE_COOKIES>` to the CSRF cookie to match the
session cookie. Optionally derive the CSRF token as an HMAC of the session token
so it's automatically scoped/rotated.

---

## Positives worth keeping (no action needed)

- **Command runner** (`routers/commands.py`) is exemplary: show-mode is
  allow-listed to `show/display/get/ping/traceroute` prefixes, single-line
  enforced, length-capped, gated by `COMMANDS_ENABLED`; config-mode adds
  `CONFIG_CHANGES_ENABLED`, a literal `DEPLOY` confirmation, device/line caps,
  and per-device audit logging.
- **`auth_persist.py`**: Fernet with key validation, per-entry TTL, drops
  undecryptable/corrupt records on restore.
- **No** `shell=True`, `eval`, `exec`, or bare `except:` anywhere in the app code.
- **SSL** verification is centralized and env-gated (`IMPACT_VERIFY_SSL`).
- Passwords are held with `repr=False` on the dataclass field to avoid leaking
  via logging.

---

## Suggested order

1. **S1** — cookie flags on the form login (high impact, ~10 lines, shared helper).
2. **S2** — fix the SSE limiter so the concurrency cap is real.
3. **S4 / S5** — login throttle + absolute session cap (operator-policy calls).
4. **S3 / S6** — xpath escaping + CSRF cookie `secure` (hardening).

## Candidate next review areas (Part 3)

- **Data integrity** in the registries (`clients/ip_registry.py`, the audit
  reconcile engine) — overlap handling, FK/`parent_id` consistency, transaction
  boundaries.
- **The large modules' correctness** — `routers/aci.py` (3.3k lines),
  `utils/tunnel_inventory.py` / `ipsec_parser.py`, `clients/panorama.py` — error
  propagation, partial-failure handling, and N+1 upstream call patterns.
- **Test coverage gaps** — routers are largely covered for parsing/logic; the
  auth/session/CSRF middleware and SSE paths have little direct coverage.
