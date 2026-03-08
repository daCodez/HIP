# HIP Protocol v1 — Overview

Status: Draft v1 (implementation target)

HIP is a protocol-level trust and identity layer above transport security (TLS). HIP does not replace TLS.

## Goals
- Interoperable trust protocol between independent systems
- Portable cryptographic identity
- Signed envelopes for integrity + sender authenticity
- Replay resistance (nonce + UTC timestamp + skew policy)
- Policy decision portability via signed trust receipts

## Non-goals (v1)
- Replacing TLS
- Solving host compromise or endpoint malware
- Blockchain dependency
- Full telecom integration

## Layering
1. HIP.Protocol — contracts, canonicalization, validation, errors, versions
2. HIP.Protocol.Security — signing/verification, replay/timestamp, key abstractions
3. HIP.Protocol.Transport.Http — HTTP mapping and middleware/filter helpers
4. HIP.Platform — policy/reputation/audit/admin APIs
5. HIP.Web — UI over platform

## v1 focus
- Identity handshake
- Protected HTTP request
- Protected message interaction
- Trust receipt verification
