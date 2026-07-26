# ADR-013: Separate certificate evidence, risk scores, and live badge presentation

## Status

Accepted

## Date

2026-07-24

## Context

A registered account, a high HIP score, a copied badge image, and a valid signature answer different questions. Treating any one of them as a general trust assertion would let unverified owners claim trust, hide current risk, or keep displaying stale state after suspension or revocation. HIP also needs to evolve signing providers without placing private keys in application storage.

## Decision

- Model domain enrollment and certificate lifecycle as separate explicit state machines.
- Issue a HIP Domain Trust Certificate only from a versioned policy evaluation after required domain-control, HTTPS, identity, security, and monitoring evidence is satisfied.
- Canonicalize signed payloads with RFC 8785 and sign through the managed signer boundary. Persist the signed public document, decision digest, indexed public projection, and permanent issuance event atomically.
- Fail closed unless the signer authority/key pair is explicitly authorized and the resulting document self-verifies against authoritative key lifecycle state.
- Keep the HIP score independent. A certificate signature establishes origin and integrity only; the badge and public page must continue to show risk separately.
- Bind short-lived live badge responses to the current exact hostname and the full current certificate presentation. Recheck signature and lifecycle state through HIP; do not trust website-controlled visual markup.
- Preserve certificate history. Lifecycle mutations are concurrency-safe, reasoned, authorized, and audited; revocation is permanent in the current state machine.
- Keep public projections privacy-minimal: no owner IDs, private contacts, challenge secrets, raw scans, internal notes, provider payloads, or sensitive URLs.
- Keep algorithm identifiers and provider abstractions crypto-agile, but make no quantum-resistant claim without an audited ML-DSA-capable provider and deployment evidence.

## Consequences

Badge availability depends on online HIP verification and managed signer/key-lifecycle availability. A copied visual may look similar but cannot produce a current domain-bound signed response. Deployments must bootstrap signer custody, public key lifecycle state, and the explicit certificate authority allowlist; the secure default is unavailable. Certificate/event storage grows because audit history is retained, so production retention, archival, and export controls require an operations decision. Risk scoring can change independently without rewriting certificate history, while lifecycle state can immediately suppress an otherwise valid signed certificate.
