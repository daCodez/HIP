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

## Shared protocol vocabulary

- `HipContentType`
- `IdentitySubjectType`
- `VerificationMethod`
- `VerificationStatus`
- `RiskStatus`
- `DevicePlatformType`
- `ReportPlatform`
- `SourceClient`
- `ReportType`
- `DomainDnssecStatus`
- `DeviceRevocationState`
- `DomainCertificateLevel`
- `DomainCertificateStatus`
- `DomainCertificateApplicationStatus`

## DNS lookup provider

- `DnsLookupRecordType`
- `DnsLookupAnswer`
- `DnssecValidationStatus`
- `DnsProviderLookupResult`
- `IDnsLookupProvider`

## Browser scoring and link classification

- `PublicEvidencePresentation`
- `BrowserScoreSiteRequest`
- `BrowserScoreSiteResponse`
- `BrowserScanLinksRequest`
- `BrowserLinkRiskResult`
- `BrowserScanLinksResponse`

## Device registration

- `DeviceTrustState`
- `StartDeviceRegistrationRequest`
- `CompleteDeviceRegistrationRequest`
- `DeviceRegistrationChallengeResponse`
- `DeviceRegistrationDeviceResponse`
- `DeviceRequestProof`
- `DeviceRequestProofCanonicalizer`

The shared vocabulary retains its existing `HIP.Domain` CLR namespaces for compatibility; this does not license or
publish the `HIP.Domain` assembly. The baseline excludes hosted scoring and detection, entitlement evaluation,
subscription and billing behavior, provider selection, secrets, private-key
operations, proof acceptance policy, replay state, authoritative identity state, certificate
issuance, persistence, administration, UI, and deployment infrastructure.
