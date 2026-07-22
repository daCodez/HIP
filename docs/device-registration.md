# HIP Device Registration

HIP-0204 establishes a revocable proof-of-possession identity for a consumer-owned
device. It proves that the registrant controlled one private key during
registration. It does not prove that the device, software, account, or person is
safe, reputable, uncompromised, or entitled to a particular API scope.

## Ownership Boundary

All Web routes and Blazor operations derive ownership from exactly one validated
`hip_consumer_id` claim. Requests do not contain an owner field. Missing, blank,
or duplicate consumer claims fail before persistence. Owner scope is a
case-sensitive, domain-separated HMAC and the raw consumer identifier is not
stored in the device aggregate.

The Web-only routes are:

- `POST /api/v1/consumer/devices/registration-challenges`
- `POST /api/v1/consumer/devices/registration-challenges/{challengeId}/responses`
- `GET /api/v1/consumer/devices`
- `POST /api/v1/consumer/devices/{deviceId}/revoke`

All four require `ConsumerPolicies.CanUseConsumerPortal`. Anonymous requests get
401 and authenticated non-consumers get 403 without redirects. Unknown and
wrong-owner challenge/device identifiers return the same 404 response. Mutations
are limited to 8 KiB, use a bounded partition derived from the authenticated
consumer scope, and require antiforgery validation for HIP session-cookie callers.
Unauthenticated and ambiguous callers use a separate remote-address partition,
so they cannot consume an authenticated consumer's budget behind the same NAT.

These routes intentionally are not mirrored into `HIP.ApiService`: that host does
not yet have the scoped service-client authentication owned by HIP-0205.

## Key and Signature Contract

The exact algorithm identifier is `ECDSA-P256-SHA256`.

- Public keys are canonical, unpadded base64url DER SubjectPublicKeyInfo values
  on the P-256 curve.
- Signatures are canonical, unpadded base64url 64-byte IEEE-P1363 `r || s`
  values, matching browser WebCrypto output.
- PKCS#8 private keys, non-P-256 keys, padded/noncanonical encodings, trailing
  data, wrong algorithm casing, and oversized values are rejected.
- Public-key fingerprints bind the algorithm identifier and canonical public-key
  bytes through the HIP fingerprint context.

The browser portal creates a non-exportable private key. Only its public key and
signature cross the JavaScript/.NET boundary. The private `CryptoKey` is stored in
origin-scoped IndexedDB and is activated locally only after server completion.

## Challenge and Storage Contract

The server creates opaque random challenge and device IDs plus a random 32-byte
nonce. The RFC 8785 canonical signing input covers:

- version and single-purpose registration context;
- challenge ID, nonce, device ID, and owner scope;
- exact algorithm and public-key fingerprint;
- bounded friendly name, platform type, and client version; and
- server-owned issue and expiry timestamps.

Clients sign the exact returned `signingInput`; they do not reconstruct JSON.
Completion returns that exact input and the signature. The server retains only a
`sha256:` digest of the signing input, never the raw nonce, payload, or signature.
Challenges expire after five minutes and are rechecked after cryptographic work.

One encrypted, versioned aggregate per owner serializes issuance, completion,
device quotas, and revocation. Compare-and-swap permits exactly one concurrent
challenge consumer. Insert-only global key and device bindings prevent the same
key or device ID from being claimed by another aggregate. State, bindings, and
privacy-safe audit facts share one database transaction. No schema migration is
needed because the records use the existing encrypted `hip_records` store.

Current limits are five pending challenges, 25 retained challenges, 25 active
devices, and at most 25 retained device rows per consumer. Registering a
replacement can prune the oldest revoked row while its global key and device-ID
bindings remain reserved. The repository rejects owner-scope mismatches,
encrypted payload/row version mismatches, malformed collections, and plaintext
records.

## Device and Revocation Semantics

Successful completion creates `ProofOfPossessionVerified` trust state and active
revocation state. That trust label means only that the submitted signature was
valid for the registered public key.

Owner revocation is terminal and idempotent. The global key binding is retained
after revocation so the old key cannot be registered again. Public responses show
only bounded device metadata, algorithm, fingerprint, proof/revocation state, and
timestamps. They exclude owner scope, raw public key, challenge data, signatures,
private keys, hardware fingerprints, network identifiers, and audit internals.
`LastSeenAtUtc` starts at registration time in HIP-0204; until a later signed
client-activity contract updates it, that value does not prove subsequent use.

HIP-0205 will add separate scoped API client credentials. A Web session cookie is
not an API client credential, and a registered device does not automatically gain
permission to submit high-trust evidence.
