# HIP Protocol

HIP is an application-layer trust protocol above TCP and TLS. TCP provides
connectivity, TLS protects transport, and HIP adds signed origin and integrity
evidence plus separately evaluated identity, reputation, and risk evidence.
A valid HIP signature never establishes safety or reputation by itself.

## Implemented Version-One Documents

The repository currently implements two strict JSON documents:

- a replay-protected protocol envelope for signed claims and content digests;
- an immutable `hip-trust-receipt` recording one server-authoritative Site
  Safety evaluation.

The checked-in interoperability fixtures are:

- `tests/HIP.Tests/Protocol/Fixtures/hip-envelope-v1.json`;
- `tests/HIP.Tests/Protocol/Fixtures/hip-envelope-v1.signing.canonical.json`;
- `tests/HIP.Tests/Protocol/Fixtures/hip-trust-receipt-v1.json`;
- `tests/HIP.Tests/Protocol/Fixtures/hip-trust-receipt-v1.signing.canonical.json`.

Version-one parsing is intentionally strict. Property names are case-sensitive;
unknown, missing, duplicate, or malformed fields are rejected; timestamps use
UTC millisecond precision; enums use their canonical string names; and input
size and nesting are bounded before cryptographic work.

## Signing and Verification

For both documents, HIP serializes the validated document, removes only
`signature.value` from the signing object, RFC 8785-canonicalizes that object,
and signs its SHA-256 digest. Verification selects the provider from the
authoritative managed-key record rather than caller-supplied algorithm metadata.
It validates issuer state, canonical identity binding, key lifecycle state,
provider policy, signature metadata, and signature bytes, then rereads issuer
and key state after cryptographic verification to close revocation races.

The production provider policy permits the platform ML-DSA-65 implementation
only when it is available. The development provider remains explicit,
Development-only, and unsuitable for production claims.

Protocol envelopes also reserve their message ID and nonce in distributed replay
state after successful verification. Trust receipts deliberately do not consume
replay state: the same immutable receipt is expected to verify repeatedly until
it expires or its issuer/key becomes invalid. Receipt verification also rejects
issuance timestamps beyond the policy's small clock-skew allowance and validity
windows longer than the issuing policy permits.

## Trust Receipt Contract

A version-one receipt contains:

- `documentType`, `version`, `receiptId`, and `relatedEvaluationId`;
- a normalized subject and evaluation, issue, and expiry timestamps;
- domain trust, optional page trust, optional content risk, and final HIP scores;
- status, confidence, bounded reason codes, and bounded warning codes;
- policy version, rule-set version, and a SHA-256 evidence digest;
- issuer identity and complete public signature metadata.

Trust scores increase as trust increases. `contentRiskScore` has the opposite
direction: larger values mean greater risk. Issuance maps it from the server's
`OverallSafetyRiskScore`; callers cannot submit receipt scores, evidence digests,
issuer data, signing keys, or signature values.

The evidence digest binds the receipt to a deterministic, privacy-safe projection
of the authoritative evaluation. Raw URLs, page summaries, warning prose,
provider values, source references, private page content, and credentials are not
stored in the receipt. The raw URL is reduced to a SHA-256 digest inside the
evidence projection before the projection itself is hashed.

Receipt IDs are deterministic for an issuer, authoritative evaluation ID, and
evidence digest. Persistence is insert-only through the receipt repository, with
primary receipt-ID and unique related-evaluation constraints. An exact retry
returns the existing receipt only after its signature and current issuer/key state
verify again; conflicting evidence or policy reuse fails closed.

## Public Receipt HTTP Surface

Both HIP HTTP hosts expose the same versioned routes:

- `POST /api/v1/protocol/issue-receipt` accepts a URL-only
  `HipTrustReceiptIssueRequest`, runs the authoritative server scanner with
  server-controlled providers and rules, and returns the exact signed receipt;
- `GET /api/v1/protocol/receipts/{receiptId}` returns the exact stored JSON;
- `POST /api/v1/protocol/receipts/verify` accepts a raw receipt document and
  returns a privacy-safe typed verification result.

Issuance and verification are rate limited, client-write CORS policy applies to
POST requests, issuance bodies are capped at 16,384 bytes, verification bodies
are capped at 65,536 UTF-8 bytes, and public errors do not include provider,
persistence, key, or exception details.
Caller-observed signals, plugin metadata, client-scoped provider switches, and
caller-authored scores or evidence never enter the signed evaluation.

The default managed receipt signer is deliberately unavailable. A production
host must replace it with an audited HSM, cloud key service, or equivalent
managed-custody implementation and explicitly authorize the signer issuer/key
pair through `HipTrustReceiptIssuerPolicy`. The default authorization policy is
empty and fails closed; a generally verified website key is not automatically a
HIP receipt-issuance key. Private key material must never cross the
`IManagedTrustReceiptSigner` boundary or enter API models, receipt JSON,
persistence, logs, or fixtures.

## Signed Live Badge

Live badge responses bind HIP-derived domain, score, status, identity meaning,
last-check time, issue time, and expiry into a version-one `hip-live-badge`
document. The document also binds its issuer, key ID, algorithm family,
algorithm, signature scope, and RFC 8785 canonicalization profile. Badge
signatures use the same `IManagedTrustReceiptSigner` custody boundary and
explicit `HipTrustReceiptIssuerPolicy` allowlist as trust receipts, while
remaining a separate document type because a public lookup is not itself an
authoritative site-safety receipt.

Both HTTP hosts expose a public verification route beside their badge lookup.
The Web embed script checks that signed fields exactly match displayed fields,
rejects expired or missing signature state, and renders only after the server
verifier confirms current issuer/key lifecycle and cryptographic state. Any
missing, unauthorized, revoked, malformed, expired, or unavailable signing state
renders `HIP Unavailable`; unsigned score data is never presented as current.
A verified badge signature proves HIP origin and integrity only, not that the
domain is safe.

## Website Verification

Implemented website-control methods are DNS TXT and `.well-known/hip.json`.
Additional methods such as HTML file upload or a meta tag remain future protocol
work.

## Compatibility Note

The implemented fixtures are the executable contract for the current code. The
older master-plan JSON example uses different envelope naming and extension
assumptions. That difference must be resolved with an explicit compatibility and
migration decision before declaring the wire format externally stable.
