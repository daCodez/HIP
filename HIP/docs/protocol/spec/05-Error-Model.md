# HIP Protocol v1 — Error Model

Errors are protocol-level and transport-neutral.

## Structure
- Code (enum)
- Message
- CorrelationId?
- Details?

## Mapping guidance
- InvalidEnvelope -> 400 (HTTP mapping)
- UnsupportedVersion -> 400/426
- InvalidSignature -> 401
- UnknownIdentity -> 401
- ReplayDetected -> 409
- TimestampExpired -> 401
- KeyRevoked -> 403
- PolicyViolation -> 403
- ChallengeRequired -> 401/403 with challenge payload

## Rule
Do not leak secret material in error details.
