# ADR-004: Run external evidence providers as durable leased jobs

## Status

Accepted

## Date

2026-07-20

## Context

Third-party security providers are slower and less reliable than HIP's request
path. Calling them while a browser or API request waits couples HIP availability
to provider latency, encourages overly long request timeouts, and makes abandoned
work difficult to recover safely.

External evidence work may also contain sensitive inputs. The durable boundary
must not retain raw URLs, query strings, fragments, provider bodies, credentials,
or private page values.

## Decision

HIP accepts explicit external-evidence requests as durable background jobs.

- Enqueue stores the encrypted job and a privacy-safe outbox event in one
  compare-and-swap database transaction before returning `202 Accepted`.
- Durable work retains only the normalized domain, canonical URL hash, bounded
  observed signals, a one-way requester digest, and the encrypted settings scope
  needed to reproduce the authorized provider configuration.
- Workers claim the oldest ready job with a bounded lease and random lease token.
  Compare-and-swap versioning prevents concurrent workers from winning the same
  claim. An expired lease makes abandoned work eligible for another claim.
- Attempt counts include lease recovery. Jobs that repeatedly lose workers are
  failed at the configured maximum, preventing crash-driven retry storms.
- Only transient transport, timeout, and cancellation failures are retried, with
  bounded exponential backoff. Invalid or unexpected results fail closed.
- Completion persists only HIP-0304 normalized provider evidence. Lease tokens,
  worker identities, owner digests, settings keys, URL hashes, and observed
  signals are excluded from API responses.
- Status lookup is owner-scoped and uses fixed-time requester-digest comparison.
  Service clients must also retain an exact grant for the job domain.
- The existing synchronous route remains temporarily available for compatible
  clients while they migrate to the accepted-job and status-polling contract.

The first durable implementation uses HIP's encrypted generic record store.
Because job state is encrypted, candidate discovery currently decrypts the job
partition before selecting a bounded claim batch. This preserves correctness and
privacy but is not the final high-volume queue index. Load testing must establish
the threshold for a separately indexed, retention-managed queue projection before
production scale.

## Alternatives Considered

### Continue running providers in the request path

Rejected. It makes client latency and HIP availability depend directly on every
configured provider and provides no durable recovery after process loss.

### Put raw requests on an external queue

Rejected. Raw URLs and provider payloads expand HIP's sensitive-data footprint.
The normalized work item is sufficient for the supported provider adapters.

### Use an in-memory channel

Rejected for runtime use. It loses accepted work on restart and cannot coordinate
claims across multiple worker instances. The in-memory repository remains useful
only for focused tests and local dependency-light execution.

## Consequences

- API requests return after durable acceptance rather than after provider latency.
- Worker restarts and horizontal concurrency preserve at-most-one active lease,
  bounded recovery, and a terminal attempt budget.
- Provider results remain evidence sources and never decide the HIP score directly.
- The job/status contract is additive, while the synchronous compatibility route
  can be deprecated separately after clients migrate.
- Production scale still requires queue-depth and oldest-job-age instrumentation,
  retention policy, and load evidence for the encrypted polling implementation.
