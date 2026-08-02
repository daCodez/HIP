# HIP Load Testing

`eng/load/hip-load.mjs` is a dependency-free Node 20+ harness for the Phase 10 latency targets. It exercises cached public lookup and browser fast scoring by default. It adds an administrative paged-list scenario only when a file-backed production session or loopback-only development identity is explicitly provided, and feedback writes only when `HIP_LOAD_ENABLE_WRITES=1` is explicitly set.

The harness never prints header values, cookie values, cookie-file paths, or response bodies. Feedback uses unique `.invalid` targets, but it still creates durable test data; run the write scenario only in an isolated test environment that may be discarded.

## Local smoke run

```powershell
$env:HIP_LOAD_BASE_URL = 'http://localhost:5260'
node eng/load/hip-load.mjs
```

## Isolated full scenario run

```powershell
$env:HIP_LOAD_BASE_URL = 'https://hip-load-test.example'
$env:HIP_LOAD_DURATION_SECONDS = '120'
$env:HIP_LOAD_CONCURRENCY = '25'
$env:HIP_LOAD_REQUESTS_PER_SECOND = '100'
$env:HIP_LOAD_DOMAIN = 'seeded-load-test.example'
$env:HIP_LOAD_ADMIN_ROLE = 'Admin'
$env:HIP_LOAD_ADMIN_USER = 'load-test-operator'
$env:HIP_LOAD_ENABLE_WRITES = '1'
node eng/load/hip-load.mjs
```

For a Production-mode admin-list run, write the dedicated load-test session's
Cookie header value to a permission-restricted temporary file and point the
harness at it. Do not use a personal browser session. The harness reads the
file once, bounds and validates the value, never reports it, and sends it only
to the protected admin scenario:

```powershell
$env:HIP_LOAD_AUTH_COOKIE_FILE = 'C:\secure-temp\hip-load.cookie'
$env:HIP_LOAD_SCENARIOS = 'admin-paged-list'
node eng/load/hip-load.mjs
```

Delete the temporary cookie file immediately after the bounded run. The
`HIP_LOAD_ADMIN_ROLE` and `HIP_LOAD_ADMIN_USER` development headers are now
rejected unless `HIP_LOAD_BASE_URL` is loopback.

`HIP_LOAD_REQUESTS_PER_SECOND` is a process-wide rate, shared across all
workers. Leave it unset only in an isolated environment whose rate limits and
capacity are intentionally under test. `HIP_LOAD_SCENARIOS` accepts a
comma-separated subset of `public-lookup-cached`, `browser-fast-score`,
`public-feedback-write`, and `admin-paged-list` (the gated scenarios must also
have their required settings).

On a shared staging endpoint, run rate-limited scenarios separately and keep
the configured request rate below the endpoint's production allowance. For
example, with the default 60-per-minute public scan limit:

```powershell
$env:HIP_LOAD_SCENARIOS = 'browser-fast-score'
$env:HIP_LOAD_REQUESTS_PER_SECOND = '1'
node eng/load/hip-load.mjs
```

The report includes HTTP status counts and network-error counts so a 429 or a
missing seeded record cannot be misreported as a latency regression.

Use the file-backed dedicated session cookie for Production-mode admin load.
Never extract or reuse a personal browser cookie for load testing.

## Gates

- cached public lookup p95: 150 ms;
- browser fast score p95: 750 ms;
- public feedback acceptance p95: 250 ms before slow work;
- admin paged list p95: 750 ms;
- error rate: at most 1 percent per scenario.

Run at warm cache and cold/database-backed states separately. Record commit, image digest, environment shape, database/Redis size, concurrency, duration, p50/p95/p99, throughput, errors, CPU, memory, connection-pool use, and queue depth. Local workstation results are diagnostic only and are not production capacity evidence.
