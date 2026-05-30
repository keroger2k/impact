# IP Address Policy — no real addressing in the repo

**Hard rule. No exceptions for convenience.**

This is a TSA / U.S. Government network operations tool. Real site addressing —
IPv4, IPv6, hostnames, interface names — is sensitive and must **never** be
committed to this repository in tests, fixtures, mock data, docstrings,
comments, template placeholders, sample data, or example values.

## The rule that keeps getting broken

> **Anything the user pastes into chat, screenshots, or shows in a log is REAL
> PRODUCTION DATA. Never copy it verbatim into the codebase.**

When you're building a parser test, a fixture, or a UI placeholder from
something the user showed you, that content almost always contains the real
network. The values you saw (a `10.254.x.x` neighbor table, a `2600:400:30xx`
prefix, a `RTVYH005AD001` hostname) are exactly what must **not** land in the
repo. Read the real value to understand the *shape/format*, then write an
**invented** value in the approved ranges below. Treat user-supplied addressing
as radioactive: useful to look at, never to copy.

## Approved fake values

| Kind | Use |
|---|---|
| IPv4 host | `1.2.3.4`, `5.6.7.8`, `1.1.1.1`, `2.2.2.2` |
| IPv4 subnet (invented) | `1.2.3.0/24`, `1.2.0.0/16`, `5.5.5.0/24` |
| IPv4 RFC1918 (invented only) | `10.0.0.0/8`, `10.45.0.0/16`, `192.168.1.0/24` |
| IPv4 documentation (RFC5737) | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPv6 /48 prefixes | `1000:2000:3000` (site A), `4000:5000:6000` (site B) |
| IPv6 documentation (RFC3849) | `2001:db8::/32` |
| Link-local / edge octets | `fe80::1`, `0.0.0.0`, `255.255.255.255`, `0.0.0.1` |
| vvvv values | `0100`, `0200`, `2d00`, `ffff` |

RFC1918 (`10/8`, `172.16/12`, `192.168/16`) is allowed **only when the value is
invented**. The org's real RFC1918 ranges are still off-limits — if you saw it
in a screenshot, don't use it.

## Forbidden (never in the repo, outside the one exception below)

- The org IPv6 allocation block (`2600:400:3xxx…` and similar `2600:`/`2001:`
  non-`db8` global unicast).
- Any IPv4 prefix the user has shown as their real network (e.g. `10.254.x`,
  `10.166.x` from screenshots).
- Real device hostnames, real captured running-configs.

### The one functional exception

`_DEFAULT_SCOPE_V6` in `utils/ip_audit.py` holds the org's real IPv6 block as
the **operational default** audit scope (overridable with `IMPACT_AUDIT_SCOPE_V6`).
That is functional configuration, not sample data. It is the *only* place the
real block is allowed, and the automated guard does not scan functional source.
Do not copy that value into tests, fixtures, or examples. If even that should
leave the source tree, move it to an env-only setting (`.env`, not committed).

## Enforcement

`tests/test_no_real_ips.py` scans the test suite, template placeholders, and
test fixtures for forbidden patterns and **fails the build** if any appear. If
you're adding a new forbidden pattern the user has disclosed, add it there. The
guard is a safety net, not a license to be careless — the rule applies
everywhere, including files the guard doesn't scan.
