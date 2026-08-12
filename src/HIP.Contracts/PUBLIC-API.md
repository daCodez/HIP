# HIP.Contracts public API baseline 0.1

This is the reviewed public surface for the first candidate package. Changes
must be additive unless a separately documented major-version migration has
been approved.

## Public trust explanations

- `PublicTrustExplanation`
- `PublicTrustExplanationItem`
- `PublicObservedEvidence`
- `PublicScoreImpact`

## Plugin declarations

- `HipPluginConfigurationRequirement`
- `HipPluginState`
- `HipPluginManifest`
- `IHipPluginManifestProvider`
- `IHipPluginStatusProvider`
- `HipPluginRuntimeStatus`
- `HipFeatureDescriptor`
- `IHipPlanFeatureProvider`

## Signature and signed-document verification

- `HipSignatureVerificationCapabilities`
- `IHipSignatureVerificationProvider`
- `IHipPublicKeyFingerprintProvider`
- `HipSignedDocumentVerificationStatus`
- `HipSignedDocumentVerificationInput`
- `HipSignedDocumentVerificationResult`
- `IHipSignedDocumentVerificationService`

## Version-one wire envelope

- `HipProtocolEnvelopeDocument`
- `HipProtocolEnvelopeIssuer`
- `HipProtocolEnvelopeSubject`
- `HipProtocolEnvelopeDigest`
- `HipProtocolEnvelopeSignature`
- `HipProtocolEnvelopeDocumentJson`

The baseline excludes hosted scoring and detection, entitlement evaluation,
subscription and billing behavior, provider selection, secrets, private-key
operations, signing, replay policy, authoritative identity state, certificate
issuance, persistence, administration, UI, and deployment infrastructure.
