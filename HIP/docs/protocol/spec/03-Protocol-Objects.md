# HIP Protocol v1 — Object Definitions

## HipIdentityDocument
- HipVersion (required)
- HipId (required)
- PublicKeyId (required)
- PublicKey (required)
- Algorithm (required)
- CreatedUtc (UTC required)
- ExpiresUtc (optional)
- DeviceBindings (optional)
- Metadata (optional)
- Extensions (optional)

## HipHello
- HipVersion, SenderHipId, ReceiverHipId?, Nonce, TimestampUtc

## HipChallenge
- HipVersion, ChallengeId, SenderHipId, VerifierHipId, Nonce, IssuedUtc, ExpiresUtc

## HipProof
- HipVersion, ChallengeId, SenderHipId, Signature, TimestampUtc

## HipMessageEnvelope
- HipVersion
- MessageType
- SenderHipId
- ReceiverHipId?
- TimestampUtc
- Nonce
- PayloadHash
- Signature
- CorrelationId
- DeviceId?
- TrustClaims?
- Extensions?

Canonical signed payload field labels are lowercase in v1 canonicalization (e.g., `hipversion`, `senderhipid`, `payloadhash`).

## HipTrustAssertion
- ClaimType, ClaimValue, Source, TimestampUtc

## HipPolicyDecision
- Decision, Reason, AppliedPolicyIds, TimestampUtc

## HipTrustReceipt
- ReceiptId
- HipVersion
- InteractionType
- SenderHipId
- ReceiverHipId?
- TimestampUtc
- MessageHash
- DeviceId?
- Checks[]
- Decision
- AppliedPolicyIds[]
- ReputationSnapshot?
- ReceiptSignature

## HipError
Codes:
- InvalidSignature
- ReplayDetected
- TimestampExpired
- UnsupportedVersion
- InvalidEnvelope
- UnknownIdentity
- DeviceNotTrusted
- LowReputation
- PolicyViolation
- ChallengeRequired
- KeyRevoked
