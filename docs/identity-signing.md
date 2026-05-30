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

## Signed Website Identity

Signed website identity lets a domain publish a HIP identity and public signing keys. For the MVP, website registration creates:

- `HipIdentity`
- `WebsiteIdentity`
- default `SigningKey`
- `DomainVerificationRequest`

The first implemented verification paths are:

- DNS TXT placeholder token: `hip-domain-verification=...`
- `.well-known/hip.json` placeholder document

HTML file upload and meta tag are modeled as future verification methods but are not implemented in the MVP flow.

## `.well-known/hip.json`

Shape:

```json
{
  "domain": "example.com",
  "hipIdentityId": "hip:web:example.com",
  "publicKeys": [
    {
      "keyId": "default",
      "algorithm": "placeholder-pq-signature",
      "publicKey": "base64-placeholder"
    }
  ],
  "issuedAtUtc": "2026-05-30T00:00:00Z"
}
```

This document does not make a site safe by itself. It only gives HIP public key material and identity metadata that can be verified and scored.

## API Routes

Versioned routes:

- `POST /api/v1/identity/register`
- `POST /api/v1/identity/websites/register`
- `POST /api/v1/identity/websites/verify`
- `GET /api/v1/identity/websites/{domain}`
- `POST /api/v1/identity/signature/verify`
- `POST /api/v1/identity/domain-verification/start`
- `POST /api/v1/identity/domain-verification/verify`
- `POST /api/v1/identity/sign`
- `POST /api/v1/identity/verify`

Identity routes are versioned under `/api/v1/identity/...`.

Website registration and verification are admin-protected in the MVP. Signature verification is public-safe because it returns only the verification result, identity status, signer reputation status, final risk status, and a plain-English reason.

## Signature Does Not Equal Safe

Example result:

```text
Signature: Valid
Signer reputation: Low
Final risk: Caution
```

A valid HIP signature proves origin and signed-hash integrity. HIP still applies reputation, scoring, rules, and review before showing final trust.

## Trust Badge and Lookup

Public lookup and badge responses include:

- signed identity status
- identity verification status
- signature validity when available

The badge must still show score and status. A verified signer cannot hide a low HIP score.

## MVP Limitations

- `DevelopmentHipCryptoProvider` is not production-safe.
- DNS TXT and `.well-known/hip.json` verification use placeholder behavior.
- Website identities are MVP foundation objects; production key rotation, revocation, and signed well-known responses still need implementation.
- Real post-quantum provider integration, such as a Dilithium/liboqs-backed provider, is future work.
