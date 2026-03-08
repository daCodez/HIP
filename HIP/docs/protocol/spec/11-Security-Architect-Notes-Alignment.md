# HIP Protocol v1 — Security Architect Notes Alignment

This document records how the SECURITY ARCHITECT NOTES are reflected in the HIP protocol workstream.

## Core vision alignment
- HIP is treated as protocol above HTTP/TLS.
- UI/platform are explicitly separated from protocol contracts.

## Layering alignment
- `HIP.Protocol` ✅
- `HIP.Protocol.Security` ✅
- `HIP.Protocol.Transport.Http` ✅
- `HIP.Platform` (existing app services) ✅
- `HIP.Web` (management/UI layer) ✅

## v1 scope alignment
Implemented v1 objects + handshake + envelope + replay controls + policy decision + trust receipt + error model + HTTP mapping starter.

## Portable identity alignment
- Identity documents defined in protocol contracts.
- Key lifecycle fields supported (`NotBeforeUtc`, `NotAfterUtc`, `Revoked`, `ReplacedByKeyId`) in security key model.

## Signed envelope alignment
Envelope canonical payload includes protocol-critical fields and signs payload hash (not raw payload).

## Canonical serialization alignment
Current canonicalization is deterministic with sorted keys/UTF-8/no insignificant whitespace.

### Pending for strict interop hardening
- enforce lowercase canonical field names (spec hardening option)
- add explicit fixed field-order appendix vectors for all mandatory objects

## Replay defense alignment
- nonce + timestamp required
- skew policy enforced
- replay guard enforced (in-memory starter)

## Trust receipt alignment
- receipt contract + signer/verifier implemented
- receipt excludes raw secret payloads

## Policy decision alignment
- standardized decisions defined (`Allow`, `Challenge`, `Warn`, `RateLimit`, `Quarantine`, `Block`)

## Reputation model alignment
- reputation not in sender envelope trust boundary by default
- optional snapshot only in trust receipt

## Transport model alignment
- HTTP mapping implemented via headers + middleware starter
- core protocol remains transport-agnostic

## Key rotation and revocation alignment
- key lifecycle validator implemented
- revocation checker abstraction present
- revocation backend integration remains pending

## Fail-closed alignment
- invalid/missing required fields fail validation
- invalid signature / replay / version mismatch all reject

## Threat model alignment
- documented in `01-Threat-Model.md`
- tested via protocol tests (signature, replay, timestamp, version, canonical mismatch)

## Adoption strategy alignment
- middleware + mappers + test vectors started
- progressive enforcement levels documented; endpoint policy gating integration pending

## Test harness alignment
- required test set covered
- conformance vectors included (HMAC envelope + HMAC receipt + Ed25519 RFC vector)

## Source of truth principle
- Spec package under `docs/protocol/spec/` is primary protocol source.
- Traceability file (`10-Spec-To-Code-Traceability.md`) tracks implementation status.
