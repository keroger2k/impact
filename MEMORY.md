# IMPACT II Remediation Learnings

- CSRF: Implemented double-submit cookie pattern. Important to exempt login and static routes. HTMX requires `htmx:configRequest` listener to attach header.
- SSE: Long-running tasks like device discovery must be non-blocking. Using `asyncio.Semaphore` helps limit concurrency. `asyncio.Queue` is useful for yielding results from concurrent tasks in a `StreamingResponse` generator.
- Panorama XML API: Version variations mean multiple XPaths should be tried. Raising domain-specific exceptions is better than returning `None` for error handling.
- Security: Secure, HttpOnly, SameSite=Strict cookies should be the default for session tokens. `?token=` query strings are a leak risk.
- Logging: Recursive redactor handles both dictionaries and raw strings (via regex). SENSITIVE_KEYS should be comprehensive (api_key, bearer, etc.).
