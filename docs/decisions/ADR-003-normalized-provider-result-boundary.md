# ADR-003: Normalize provider results before rules and scoring

## Status

Accepted

## Date

2026-07-20

## Context

HIP consumes evidence from local adapters and third-party security providers.
Those sources vary in response shape, timing, failure behavior, freshness, and
privacy characteristics. Passing provider-authored objects directly into rules
or scoring would let malformed, stale, oversized, or mismatched data influence a
HIP result.

Provider evidence must remain a source of bounded facts. A provider does not
decide the final HIP score, and a clean provider response does not by itself
establish that a site is safe or trustworthy.

## Decision

HIP validates every provider result through one provider-neutral application
boundary before rules or scoring can consume it.

- Results receive an explicit `Succeeded`, `Partial`, `TimedOut`, or `Failed`
  status derived at the collection boundary.
- The boundary verifies registered provider identity and type, target scope,
  normalized domain and URL-hash binding, evidence and error counts, score and
  confidence ranges, enum values, bounded plain text, timestamps, lifetime, and
  latency.
- URL-, content-, and download-scoped evidence requires the canonical SHA-256
  URL hash for the current request. Domain evidence may omit the hash.
- Provider latency is measured with the injected `TimeProvider`, bounded, and
  stored as milliseconds. Freshness is classified as `Fresh`, `Stale`, or
  `Expired` at collection completion.
- Privacy classification is derived from the normalized target and provider
  type. The contract retains public domain metadata, a URL hash, or bounded
  privacy-safe observed signals; it never retains raw provider bodies or private
  page values.
- Timeout, exception, and malformed-result paths produce safe non-authoritative
  failure evidence with zero confidence. A failed result cannot retain risk or
  trust authority flags.
- Authority flags are adapter policy, not remote-provider input. Even when an
  adapter is allowed to mark evidence authoritative, HIP rules and the formal
  scoring pipeline remain responsible for the final decision.
- ApiService and Web expose the normalized operational fields additively while
  preserving all existing provider-evidence response fields.

## Alternatives Considered

### Let each adapter validate its own result

Rejected. Independent validation would drift across providers and make it easy
for one error path to bypass size, identity, freshness, or privacy controls.

### Serialize raw provider responses for later analysis

Rejected. Raw bodies are provider-specific, difficult to bound, and can contain
sensitive or unexpectedly identifying data. Normalized facts and safe errors are
sufficient for scoring and operations.

### Treat provider failures as scan failures

Rejected. Optional provider outages must lower confidence without taking down
public lookup or allowing a provider to decide the final HIP status.

## Consequences

- All scan paths share one fail-closed provider contract.
- Existing provider implementations remain source-compatible because the new
  result fields are trailing optional record parameters.
- API clients can distinguish operational failure from a clean result and can
  display latency, freshness, and privacy handling consistently.
- Provider result limits and classifications become compatibility-sensitive and
  require deliberate review when changed.
- Durable provider scheduling and retries remain HIP-0305 work; this decision
  defines the normalized payload that those jobs will persist and return.
