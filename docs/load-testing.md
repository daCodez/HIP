# HIP Load Testing

`eng/load/hip-load.mjs` is a dependency-free Node 20+ harness for the Phase 10 latency targets. It exercises cached public lookup and browser fast scoring by default. It adds an administrative paged-list scenario only when development admin identity headers are explicitly provided, and feedback writes only when `HIP_LOAD_ENABLE_WRITES=1` is explicitly set.

The harness never prints header values or response bodies. Feedback uses unique `.invalid` targets, but it still creates durable test data; run the write scenario only in an isolated test environment that may be discarded.

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
$env:HIP_LOAD_DOMAIN = 'seeded-load-test.example'
$env:HIP_LOAD_ADMIN_ROLE = 'Admin'
$env:HIP_LOAD_ADMIN_USER = 'load-test-operator'
$env:HIP_LOAD_ENABLE_WRITES = '1'
node eng/load/hip-load.mjs
```

Use supported production authentication rather than development headers outside Development. A deployment test runner may inject an authenticated cookie or gateway credential by extending the harness without logging it.

## Gates

- cached public lookup p95: 150 ms;
- browser fast score p95: 750 ms;
- public feedback acceptance p95: 250 ms before slow work;
- admin paged list p95: 750 ms;
- error rate: at most 1 percent per scenario.

Run at warm cache and cold/database-backed states separately. Record commit, image digest, environment shape, database/Redis size, concurrency, duration, p50/p95/p99, throughput, errors, CPU, memory, connection-pool use, and queue depth. Local workstation results are diagnostic only and are not production capacity evidence.
