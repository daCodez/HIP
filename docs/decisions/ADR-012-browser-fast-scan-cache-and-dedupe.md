# ADR-012: Browser fast scans use bounded privacy-safe coordination

Date: 2026-07-20
Status: Accepted

## Context

The extension previously cached only domain lookups and scores in unbounded
process memory. Link and Site Safety requests could duplicate work, cache keys
did not include every result-affecting input, and successful scan submissions
were suppressed only while the first write remained in flight.

## Decision

- Use one bounded LRU fast-scan cache for lookup, score, link, and Site Safety
  work with explicit fresh, stale-while-revalidate, and expired states.
- Coalesce identical cache misses and stale refreshes onto one loader promise.
  Remove failed promises immediately so later requests can retry.
- Include the configured HIP service identity, extension instance identity, and
  complete result-affecting request in a canonical SHA-256 cache key. Store only
  the digest as the Map key; never store a raw page URL or observation in key or
  cache metadata.
- Return explicit source, freshness, and age metadata from the coordinator while
  preserving existing browser/API response contracts at its integration seam.
- Bound fast-scan entries at 256 and per-tab popup summaries at 128, with
  deterministic least-recently-used eviction.
- Coalesce identical scan-result writes and remember successful submissions for
  30 seconds in a bounded 512-entry dedupe set. Do not remember failures.

## Consequences

The cache remains an optimization, not authoritative storage; service-worker
termination safely discards it. Stale results may be shown within the bounded
window while a single refresh runs. Rollback is a normal Git revert of the
coordinator, background integration, tests, and this record.
