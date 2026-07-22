# ADR-006: Persist immutable privacy-safe rule simulation records

## Status

Accepted

## Date

2026-07-20

## Context

Rule activation decisions need durable evidence. HIP already calculated useful
simulation metrics and stored results, but records were overwriteable, were not
bound to a rule version or fixture set, and did not distinguish persisted fixture
structure from transient fixture values.

Simulation fixtures may represent browser, chat, email, file, or image metadata.
Persisting their raw values would unnecessarily retain URLs, message-like values,
or other private content.

## Decision

- New simulation IDs are random canonical identifiers and are stored once with
  aggregate version one. Duplicate writes fail instead of overwriting evidence.
- Every result records the exact rule version, a deterministic SHA-256 fixture-set
  digest, start/completion times, aggregate counts and rates, confidence,
  recommendations, failed cases, and rollback plan.
- Persisted case descriptors contain case name, expected and actual outcomes, and
  sorted input field names only. Input values are evaluated transiently and are
  never copied into the durable result or API response.
- Private-content field names and labels, inconsistent counts or rates, duplicate
  cases, malformed failed-case projections, unbounded text, and invalid rollback
  metadata are rejected before persistence.
- Results use HIP's encrypted generic record store. Version-zero records created
  before HIP-0403 remain readable, while all new writes use the immutable contract.
- Simulation routes remain restricted to the existing rule-management policy;
  anonymous callers cannot create or retrieve results.

## Consequences

- Approval packages can refer to a stable simulation record and fixture digest.
- Re-running a rule produces a new record rather than rewriting historical
  decision evidence.
- Reviewers can inspect aggregate quality and failed synthetic cases without HIP
  retaining private fixture values.
- HIP-0404 can enforce approval requirements against immutable simulation evidence.
