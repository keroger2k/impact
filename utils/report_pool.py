"""utils/report_pool.py — shared, bounded worker pool for report fan-out.

The Reports endpoints each resolve a target and then pull two independent
time windows (24h + 7d) that are worth overlapping rather than running
back-to-back — the user is watching a spinner on a synchronous, uncached
endpoint.

Those report functions already run inside a worker thread (routers/reports.py's
run_in_executor), so the fan-out needs a *second* pool: submitting to the same
pool the caller is blocked in would deadlock once that pool is saturated.
This is that second pool, shared process-wide rather than created per request
so concurrent requests can't multiply threads without bound.

Sized well above the 2 tasks a single report submits, so it overlaps rather
than queues under normal internal load, while still capping total growth.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

FANOUT_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="report-fanout")
