# ADR-002: Add stable typed scoring reasons alongside plain text

## Status

Accepted

## Date

2026-07-20

## Context

HIP scoring already returns plain-language reasons and warnings. Those strings
are useful to people but are unsafe as machine contracts: wording improvements,
punctuation changes, or localization would break clients that compare text.
Signed trust receipts also need stable reason and warning identifiers without
changing their version-one document shape.

The reason contract must remain explainable, privacy-safe, bounded, and usable
by older API and browser-extension clients. A score cap, rule, or evidence state
must not expose raw page content, form values, credentials, private identifiers,
or provider secrets.

## Decision

HIP adds immutable `ReasonEntries` to the formal scoring result while preserving
the existing `Reasons` and `Warnings` collections unchanged.

- Each entry contains a canonical lowercase reason code, plain-language
  explanation, optional paired warning code and warning, typed impact, bounded
  evidence source code, optional UTC evidence time, and public or derived
  metadata classification.
- Mandatory score-cap codes are fixed catalog identifiers. Changing or removing
  one requires an explicit compatibility migration; wording may evolve without
  changing the code's meaning.
- Enforced score-changing Site Safety rules receive deterministic rule codes.
  Simulation-only and watch-only matches never enter the formal catalog.
- Pipeline-generated missing-page, freshness, and confidence warnings receive
  stable codes but use a `None` numeric impact because confidence does not alter
  the score.
- Formal scoring results allow at most 32 entries. Site Safety reserves eight
  slots for mandatory caps and pipeline evidence warnings and publishes at most
  24 enforced rule entries in ordinal rule-ID order.
- Duplicate codes, malformed protocol tokens, invalid impact/value pairs,
  unpaired warnings, control characters, and oversized text are rejected at the
  scoring boundary.
- The Site Safety API and Web compatibility route expose explicit public-safe
  projections instead of serializing internal scoring objects directly.
- The browser extension treats API data as untrusted, copies only bounded known
  fields, freezes accepted entries, and ignores malformed optional entries
  without discarding an otherwise valid score.
- Trust receipts add catalog codes to their existing `reasonCodes` and
  `warningCodes` arrays. The version-one receipt schema and canonical signing
  shape do not change, and each collection remains capped at 32 codes.
- `hip-0301-v1` remains the formal score model version because the score
  direction and composition semantics did not change; the catalog fields are
  additive.

## Alternatives Considered

### Replace plain-language strings with codes

Rejected. Existing clients and user interfaces depend on the readable strings.
Removing or retyping those fields would be a breaking change and would force
every client to ship its own message catalog immediately.

### Derive codes by hashing explanation text

Rejected. Text hashes would change whenever wording changes and would make code
meaning opaque. Fixed semantic identifiers keep presentation text evolvable and
machine behavior understandable.

### Serialize the internal scoring result directly

Rejected. Internal stage and evidence objects are implementation details. An
explicit API projection limits observable fields and prevents future internal
changes from silently becoming public contracts.

### Put full evidence values in reason entries

Rejected. Raw values can contain private page data, identifiers, or provider
details. Catalog entries carry only bounded source tokens, optional timestamps,
and privacy classifications.

## Consequences

- Clients can make stable decisions from reason and warning codes while showing
  server-authored plain language.
- Older clients continue using `Reasons` and `Warnings`; newer clients can adopt
  `ReasonEntries` incrementally.
- Catalog codes become long-lived protocol commitments and require deliberate
  deprecation when their meaning changes.
- The 32-entry limit can omit lower-priority rule detail on unusually large rule
  sets, but mandatory caps and evidence warnings retain reserved capacity.
- Provider-specific latency, status, freshness, and privacy normalization remain
  HIP-0304 work; HIP-0303 records only evidence metadata already known safely.
