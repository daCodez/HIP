# HIP Identity and Signing Foundation

HIP identity verifies who signed content and whether the signed hash changed. A valid HIP signature does not automatically mean content is safe.

A valid signature means:

- HIP knows which identity signed it.
- HIP can verify the signed content hash was not changed.
- HIP can apply reputation to the signer.

Safety still depends on HIP scoring, reputation, rules, and risk review.

## Identity Types

HIP identities support:

- Person
- Website
- Domain
- App
- Organization
- DeviceKey
- VirtualWorldAvatar
- ContentPublisher

An identity contains an ID, type, display name, public key, key algorithm, verification status, creation time, and reputation target ID.

Verification statuses:

- Unverified
- Pending
- Verified
- Suspended
- Revoked

## Signing Model

HIP signatures include:

- signature ID
- identity ID
- algorithm
- content hash
- signature value
- signed time
- optional expiration time

Signed content supports:

- Website
- WebPage
- File
- Image
- App
- ApiResponse
- Email
- SocialPost
- Download
- RuleResult

## Crypto Provider

The application uses `IHipCryptoProvider` so a real post-quantum provider can be plugged in later.

Current development implementation:

`DevelopmentHipCryptoProvider`

This provider is not production-safe. It exists only so the identity, signing, verification, API, and tests can be built before adding a real post-quantum implementation.

Future provider options may include liboqs or Dilithium-style signatures. No heavy native dependency is included yet.

## Domain Verification

Supported verification methods:

- DNS TXT
- `.well-known/hip.json`
- HTML file
- Meta tag

The MVP service starts with DNS TXT and `.well-known/hip.json` contracts. Implementation is in-memory and development-only.

## `.well-known/hip.json`

Shape:

```json
{
  "hipIdentityId": "hip:domain:example.com",
  "domain": "example.com",
  "publicKey": "...",
  "keyAlgorithm": "PQ-Placeholder",
  "signedAtUtc": "2026-05-29T00:00:00Z",
  "signature": "..."
}
```

## API Routes

Versioned routes:

- `POST /api/v1/identity/register`
- `POST /api/v1/identity/domain-verification/start`
- `POST /api/v1/identity/domain-verification/verify`
- `POST /api/v1/identity/sign`
- `POST /api/v1/identity/verify`

Temporary compatibility aliases also exist under `/api/identity/...`.

## Trust Badge and Lookup

Public lookup and badge responses include:

- signed identity status
- identity verification status
- signature validity when available

The badge must still show score and status. A verified signer cannot hide a low HIP score.
