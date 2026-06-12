# HIP Scalability Foundation

HIP currently has a development-first runtime that is useful for MVP testing, but it is not yet a millions-of-users production topology. The code now has explicit extension points for the parts that must move to production-grade infrastructure.

## Current Limits

- SQLite is the default development database through `ConnectionStrings:HipDatabase`.
- The EF implementation stores JSON records in a generic `hip_records` table.
- Several local defaults are intentionally in-memory for development and tests.
- External provider checks must not run on every page visit.
- `RunExternalProvidersOnRequestPath` is false by default so configured providers do not block public scans.
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

The public scan request path should not call third-party providers by default. HIP can show browser-observed, history, feedback, and admin-review evidence immediately, then enqueue external provider checks for the slow path.

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

- `IBrowserScanResultWriteService`
- `IBrowserScanResultQueryService`
- `IScanResultCache`
- `IScanIngestionQueue`
- `IScanResultDedupeService`
- `IDashboardScanAggregateStore`
- `ISubmissionRateLimiter`
- `IOutboxEventRepository`
- `IInboxEventRepository`

The current cache, queue, dedupe, and aggregate implementations are in-memory development adapters. Production should replace them with Redis and a durable queue without changing scanner or dashboard callers.

Scan writes and dashboard/public lookup reads should stay separated. `IBrowserScanResultWriteService` is the scan ingestion boundary. `IBrowserScanResultQueryService` is the read boundary for public lookup and dashboards, and can later point at Redis, PostgreSQL projections, or materialized views.

HIP also has outbox/inbox interfaces so scan, provider, and review events can become durable and retry-safe. The EF-backed MVP repositories use HIP's encrypted record store; production workers should process pending outbox events and use inbox records for idempotency.

Provider evidence already has expiry through `IExternalSiteEvidenceCache`. External evidence should be reused until expired, and provider failures should lower confidence or create review signals without creating trust or danger by themselves.

External providers run through provider policy and resilience objects:

- `IProviderSubmissionPolicy` decides whether a provider may receive the current target.
- `IExternalProviderResiliencePolicy` isolates provider calls with circuit breaker and bulkhead behavior.
- `IPrivacyStoragePolicy` centralizes storage decisions for raw URLs and private metadata fields.
- `IFeedbackWeightingPolicy` keeps feedback as weighted evidence, not voting.

These policies are intentionally small and strongly typed. HIP should prefer policy objects and specification/rule objects over long conditional chains in scan and scoring services.

## Framework Performance Controls

HIP now has explicit host-level performance controls for the public hot path:

- `HipPerformance` options configure public lookup cache duration, badge cache duration, future safety/site-safety cache durations, and public request limits.
- `HIP.ApiService` and `HIP.Web` both register ASP.NET Core output caching.
- When Aspire injects a Redis connection string, both hosts use Aspire's Redis-backed output-cache integration.
- Direct local project runs still work without Redis because the hosts fall back to the normal in-process output-cache store.
- Public domain lookup and live badge endpoints opt into named output-cache policies.
- Public write-heavy endpoints use partitioned ASP.NET Core rate-limit policies keyed by the best available privacy-safe identifier: API key, HIP signer, HIP instance ID, domain, or client IP.
- Response compression is enabled for JSON, badge scripts, and web assets to reduce bandwidth without changing stored or returned trust data.

These controls are intentionally outside the scoring engine. Caching a lookup or badge response must never create trust, hide warnings, or bypass provider/rule evaluation once a fresh scan result is stored. Cache durations should stay short until HIP has production cache invalidation and event-driven projection updates.

Example configuration:

```json
{
  "HipPerformance": {
    "UseRedisOutputCacheWhenAvailable": true,
    "PublicLookupCacheSeconds": 30,
    "BadgeCacheSeconds": 60,
    "SafetyCacheSeconds": 10,
    "SiteSafetyCacheSeconds": 15,
    "PublicScanRequestsPerMinute": 60,
    "PublicFeedbackRequestsPerMinute": 30,
    "IdentityRequestsPerMinute": 10
  }
}
```

Aspire owns the local Redis resource. `HIP.AppHost` passes that Redis reference to both `hip-api` and `hip-web`, so Visual Studio/Aspire local runs can exercise distributed cache wiring without manual Docker commands.

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

1. Replace in-memory scan cache and dedupe with Redis adapters.
2. Add a durable queue adapter and worker project for slow-path provider checks.
3. Add an outbox processor that dispatches scan/provider/review events with inbox idempotency.
4. Persist provider evidence as first-class records for dashboard visibility.
5. Move dashboard cards to pre-aggregated summaries for large datasets.
6. Add distributed Redis-backed rate-limit stores when HIP moves beyond single-node MVP deployments.
7. Add EF Core compiled queries, projections, and indexes for dashboard and public lookup read models.
