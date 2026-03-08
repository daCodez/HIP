# HIP Protocol v1 — Spec to Code Traceability Matrix

Status legend:
- ✅ Implemented
- 🟡 Partial / starter only
- ❌ Gap

## A) Spec package to implementation map

| Spec section | Requirement summary | Code location(s) | Status | Notes |
|---|---|---|---|---|
| 00 Overview | Protocol-layer decomposition | `HIP.Protocol*` projects | ✅ | Layer split established |
| 01 Threat Model | Replay/signature/version/malformed protections | `HipEnvelopeSecurityService`, validators | 🟡 | Core protections present; no formal threat test vectors yet |
| 02 Trust Model | Decision + trust receipt path | `HipPolicyDecision`, `HipTrustReceipt`, `HipReceiptSecurityService` | ✅ | Baseline flow implemented |
| 03 Protocol Objects | Contract object set | `HIP.Protocol/Contracts/HipContracts.cs` | ✅ | All v1 objects present |
| 04 Flows | Handshake, protected request/message, receipt verify | `HipChallengeService`, `HipProtocolMiddleware`, receipt service | 🟡 | Message flow modeled; no dedicated transport-agnostic message handler service yet |
| 05 Error Model | Structured protocol errors | `HipError`, `HipErrorCode` | ✅ | HTTP mapping table not fully enforced in middleware responses |
| 06 Versioning | Supported version checks | envelope/receipt services check `HipProtocolVersions.V1` | 🟡 | Allowlist abstraction not implemented yet |
| 07 HTTP Mapping | HIP headers + mapper + middleware | `HipHttpHeaders`, `HipHttpEnvelopeMapper`, `HipProtocolMiddleware` | ✅ | Middleware is starter-level |
| 08 Trust Receipt Spec | Sign + verify receipt | `HipReceiptSecurityService` | ✅ | Works with reference signer |
| 09 Security assumptions/non-goals | Explicitly documented | docs only | ✅ | Present in spec docs |

## B) Core requirement traceability

### B1. Contracts
- ✅ `HipIdentityDocument`
- ✅ `HipHello`
- ✅ `HipChallenge`
- ✅ `HipProof`
- ✅ `HipMessageEnvelope`
- ✅ `HipTrustAssertion`
- ✅ `HipPolicyDecision`
- ✅ `HipTrustReceipt`
- ✅ `HipError`

Source: `HIP.Protocol/Contracts/HipContracts.cs`

### B2. Canonicalization
- ✅ Deterministic canonical serializer implemented
- ✅ Lowercase canonical field names + fixed field order implemented
- 🟡 Formal RFC-style canonicalization appendix not yet written

Source: `HIP.Protocol/Canonicalization/HipCanonicalization.cs`

### B3. Replay + freshness
- ✅ Nonce replay detection abstraction + in-memory implementation
- ✅ Timestamp skew policy abstraction + implementation
- 🟡 Distributed replay store backend not implemented

Source: `HIP.Protocol.Security/Abstractions/SecurityAbstractions.cs`, `HIP.Protocol.Security/Services/HipSecurityServices.cs`

### B4. Signature verification and trust receipt
- ✅ Envelope sign/verify (reference HMAC implementation)
- ✅ Receipt sign/verify
- ✅ Asymmetric provider path implemented (`ECDSA_P256_SHA256`) via algorithm abstraction/router
- 🟡 Ed25519 provider pending (abstraction ready)

Source: `HIP.Protocol.Security/Services/HipSecurityServices.cs`

### B5. HTTP transport
- ✅ Header constants
- ✅ Envelope mapper
- ✅ Middleware starter
- 🟡 Rich error-body mapping and automatic receipt attachment in middleware still minimal

Source: `HIP.Protocol.Transport.Http/*`

## C) Test coverage traceability

Tests: `HIP.Protocol.Tests/Protocol/HipProtocolSecurityTests.cs`

Covered (requested):
- ✅ valid envelope
- ✅ invalid signature
- ✅ expired timestamp
- ✅ replayed nonce
- ✅ unsupported version
- ✅ missing required field
- ✅ invalid trust receipt signature
- ✅ canonical serialization mismatch
- ✅ challenge success
- ✅ challenge fail

## D) Simulator evidence path (protocol conformance via simulator)

Protocol evidence artifacts are produced by simulator protocol-mode runs and can be used as release evidence:

- Scenarios: `HIP.Simulator.Cli/scenarios/protocol/*.json`
- Run command: `dotnet run --project HIP.Simulator.Cli -- run --mode protocol --suite protocol --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out`
- Artifacts: `HIP.Simulator.Cli/out/simulation-report-*.json`, `simulation-report-*.html`, `simulation-suggestions-*.md`
- Test coverage: `HIP.Simulator.Tests/ProtocolExecutionTests.cs`

These artifacts complement `HIP.Protocol.Tests` by exercising protocol behaviors through simulator orchestration paths.

## E) Open gaps to close before protocol hardening milestone

1. 🟡 Add Ed25519 provider (ECDSA implemented)
2. 🟡 Expand key-rotation policy and key-validity window enforcement (starter validator implemented)
3. ❌ Add revocation source integration (not noop)
4. ❌ Add transport-independent protected message flow service (beyond HTTP middleware)
5. ✅ Add HTTP error mapping policy to return structured `HipError` consistently (middleware starter)
6. ✅ Add conformance vectors (initial HMAC vector fixture)
7. ❌ Add downgrade/extension confusion tests

## F) Immediate implementation plan (next pass)

1. Implement `IHipAlgorithmProvider` and Ed25519/ECDSA reference path
2. Add `HipVersionPolicy` allowlist and extension policy hooks
3. Add `HipRevocationProvider` + in-memory revoked key source and tests
4. Expand middleware to emit structured protocol errors and optional signed receipts
5. Add conformance fixtures under `HIP.Protocol.Tests/Conformance`

---

This file is the execution checklist for moving from protocol starter to interoperable protocol reference implementation.
