# HIP Scalability Foundation

HIP currently has a development-first runtime that is useful for MVP testing, but it is not yet a millions-of-users production topology. The code now has explicit extension points for the parts that must move to production-grade infrastructure.

## Current Limits

- SQLite is the default development database through `ConnectionStrings:HipDatabase`.
- The EF implementation stores JSON records in a generic `hip_records` table.
- Several local defaults are intentionally in-memory for development and tests.
- External provider checks must not run on every page visit.
- The dashboard can read stored scan results today, but large deployments should use pre-aggregated counters.

SQLite is acceptable for local development. PostgreSQL should be the production persistence target because HIP will need stronger concurrency, indexing, retention policies, backup strategy, and operational tooling.

## Production Direction

HIP should scale around replaceable boundaries:

- PostgreSQL for durable records, scan history, rule versions, review queue, feedback, and audit logs.
- Redis for hot-path latest scan cache, provider evidence cache, dedupe windows, and rate-limit counters.
- A durable queue for slow-path scan enrichment and provider checks.
- Background workers for external provider polling and dashboard aggregation.
- Pre-aggregated dashboard summaries to avoid scanning full history on every admin refresh.

## Hot Path

The hot path must return quickly:

1. Browser plugin sends privacy-safe observed signals.
2. HIP validates the payload.
3. HIP checks cached/latest score by domain and URL hash where available.
4. HIP returns the latest score and status quickly.
5. HIP stores the privacy-safe summary and updates dashboard aggregates.

The hot path stores only public-safe scan summaries such as domain, URL hash, score, status, confidence, reasons, warnings, provider names, matched rule IDs, plugin version, and scan time.

## Slow Path

The slow path performs deeper work asynchronously:

1. HIP creates a `ScanIngestionRequest`.
2. The request is queued with domain, URL hash, signal hash, source, plugin version, and timestamp.
3. Workers dedupe repeated work by domain plus URL hash plus signal hash.
4. Workers use cached provider evidence when fresh.
5. Workers run deeper provider checks only when configured and cache entries are expired or missing.
6. Updated scores are stored and aggregates refreshed.

HIP must not call SSL Labs, Google Web Risk, VirusTotal, or similar providers for every browser page visit.

## Cache And Dedupe

The application layer now includes:

- `IScanResultCache`
- `IScanIngestionQueue`
- `IScanResultDedupeService`
- `IDashboardScanAggregateStore`
- `ISubmissionRateLimiter`

The current implementations are in-memory development adapters. Production should replace them with Redis and a durable queue without changing scanner or dashboard callers.

Provider evidence already has expiry through `IExternalSiteEvidenceCache`. External evidence should be reused until expired, and provider failures should lower confidence or create review signals without creating trust or danger by themselves.

## Dashboard Aggregation

The dashboard can still compute directly from stored scan history for MVP usage. At scale, dashboard cards should read a pre-aggregated summary updated as scans are stored or workers finish slow-path enrichment.

The current aggregate model tracks total scans, scans today, and status counts for Trusted, MostlyTrusted, LimitedTrustData, Unknown, Suspicious, HighRisk, and Dangerous.

## Privacy Rules

HIP must not store:

- page text
- form values
- passwords
- tokens
- cookies
- private messages
- browsing history
- raw full URLs unless a future explicit policy allows it

Allowed scalability keys use hashes:

- page URL hash
- signal hash from privacy-safe counts and labels
- provider cache keys based on provider name, domain, and URL hash

## Next Steps

1. Add PostgreSQL EF provider configuration beside SQLite without removing SQLite dev mode.
2. Replace in-memory scan cache and dedupe with Redis adapters.
3. Add a durable queue adapter and worker project for slow-path provider checks.
4. Persist provider evidence as first-class records for dashboard visibility.
5. Move dashboard cards to pre-aggregated summaries for large datasets.
6. Add production rate limits keyed by API key, user, device, or privacy-safe client hash.
