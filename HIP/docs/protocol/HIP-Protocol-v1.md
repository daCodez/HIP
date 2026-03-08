# HIP Protocol v1 — Overview and Draft Spec

## 1) Executive summary

HIP is a protocol-level trust and identity layer that operates above transport security (TLS) and can be mapped to HTTP in v1.
HIP is **not** a UI feature, and not a single app API contract.

HIP v1 delivers:
- Portable identity documents (`HipIdentityDocument`)
- Signed envelopes (`HipMessageEnvelope`)
- Replay defenses (nonce + UTC timestamp + skew policy)
- Policy decision objects (`HipPolicyDecision`)
- Signed trust receipts (`HipTrustReceipt`)
- Protocol-level error model (`HipError`)

## 2) What makes HIP a protocol (not just an app)

HIP is a protocol because it defines:
- Wire contracts independent of one codebase
- Canonical serialization rules for deterministic signatures
- Verification and replay rules that any implementation can apply
- Versioning and error semantics for interoperability
- Transport mappings (HTTP now, others later)

Two independent systems can implement HIP from spec and interoperate if they follow the same contracts + canonicalization + crypto verification rules.

## 3) Protocol architecture

### HIP.Protocol
- Contracts and enums
- Canonicalization interfaces
- Validation rules and result model
- Flow contracts

### HIP.Protocol.Security
- Crypto abstractions (sign/verify/hash)
- Replay guard abstractions
- Timestamp and skew validation
- Key resolver abstraction, revocation abstraction
- Trust receipt signer/verifier

### HIP.Protocol.Transport.Http
- HTTP header mapping and constants
- Envelope extraction and response mapping
- Middleware/filter starter

### HIP.Platform
- Policy engine, reputation, audit, storage, operational workflows

### HIP.Web
- Management and observability UI

## 4) Threat model (v1)

HIP addresses:
- Replay attacks (nonce + timestamp + skew + replay store)
- Spoofed sender identity (signature verification with sender key)
- Envelope tampering (payload hash + canonical signed fields)
- Receipt forgery (signed receipt verification)
- Version confusion (strict supported-version checks)
- Malformed envelope abuse (strict validation + fail-closed)

Out-of-scope (explicit non-goals in v1):
- Endpoint compromise after trust is granted
- Insecure private key storage on sender side
- Full anti-malware or endpoint detection
- Transport security replacement (HIP requires TLS for channel protection)

## 5) Trust model

Trust in HIP is built from:
1. Identity proof (key ownership)
2. Envelope integrity and freshness
3. Optional policy/reputation/device assertions
4. Signed trust receipt issued by verifier

Default is fail-closed: missing signature/nonce/timestamp/required field => deny.

## 6) HIP v1 objects

- `HipIdentityDocument`
- `HipHello`
- `HipChallenge`
- `HipProof`
- `HipMessageEnvelope`
- `HipTrustAssertion`
- `HipPolicyDecision`
- `HipTrustReceipt`
- `HipError`

## 7) Fields that MUST always be signed

Minimum signed content in `HipMessageEnvelope` canonical payload:
- HipVersion
- MessageType
- SenderHipId
- ReceiverHipId (if present)
- TimestampUtc (ISO 8601 UTC)
- Nonce
- PayloadHash
- CorrelationId
- DeviceId (if present)
- TrustClaims canonical object (if present)
- Extensions canonical object (if present)

For `HipTrustReceipt`:
- ReceiptId
- HipVersion
- InteractionType
- SenderHipId
- ReceiverHipId (if present)
- TimestampUtc
- MessageHash
- DeviceId (if present)
- Checks
- Decision
- AppliedPolicyIds
- ReputationSnapshot (if present)

## 8) Canonical serialization

HIP canonicalization rules v1:
- UTF-8
- JSON object keys sorted lexicographically (ordinal)
- No insignificant whitespace
- Stable string representation for UTC timestamps (`O` format)
- Arrays preserve order
- Null fields omitted from signature payload

Any signature verification MUST canonicalize using same rules before verify.

## 9) Replay protection rules

- `Nonce` required and unique per sender within replay window
- `TimestampUtc` required, must be UTC
- Reject if outside allowed skew window
- Reject if nonce already seen in replay window
- Replay store abstraction allows distributed backends

## 10) HTTP mapping (v1)

Header mapping (default names):
- `HIP-Version`
- `HIP-MessageType`
- `HIP-Sender`
- `HIP-Receiver` (optional)
- `HIP-Timestamp`
- `HIP-Nonce`
- `HIP-PayloadHash`
- `HIP-Signature`
- `HIP-CorrelationId`
- `HIP-Device` (optional)

Receipt response headers:
- `HIP-Receipt-Id`
- `HIP-Receipt-Signature`
- optional full receipt in body JSON

## 11) Versioning strategy

- Semantic protocol version string (`1.0`)
- Receiver keeps allowlist of supported major/minor
- Major mismatch => `UnsupportedVersion`
- Unknown optional extensions ignored if extension policy allows

## 12) Key rotation and revocation

- Identity docs reference `PublicKeyId`
- Key resolver returns active key by `PublicKeyId`
- Revocation checker consulted before trust grant
- Receipts include key id used for signing where applicable

## 13) Trust receipt design

Receipts are verifier-signed decision artifacts.
Used for external validation and audit portability.

Verification requires:
- Supported version
- Required fields present
- Signature valid under verifier key
- Canonical receipt payload unchanged

## 14) Security assumptions and non-goals

Assumptions:
- TLS is in place
- Private keys are protected by implementation
- Clocks are reasonably synchronized

Non-goals:
- Replacing TLS
- Solving host compromise
- Replacing secure key management systems

## 15) Design questions answered

1. HIP is a protocol because it defines interoperable wire contracts + verification semantics independent of app code.
2. Protocol = contracts/validation; Platform = policy/reputation/audit; Web = management UI.
3. Signed fields listed in section 7.
4. Canonical serialization = sorted-key deterministic JSON UTF-8 without insignificant whitespace.
5. Replay = nonce uniqueness + timestamp skew + replay-store rejection.
6. Receipts are signed over canonical receipt payload and verified with verifier public key.
7. Key rotation via key ids + resolver + validity windows.
8. Revocation represented by revocation status lookup on sender key/id.
9. HTTP uses explicit header mapping; contracts are transport-agnostic so future transports map same envelope.
10. Clean minimal v1 = identity doc + envelope + replay/timestamp + policy decision + trust receipt + errors.
