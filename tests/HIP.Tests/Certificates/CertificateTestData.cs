using HIP.Application.Certificates;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Certificates;

internal static class CertificateTestData
{
    internal static readonly DateTimeOffset Now =
        new(2026, 7, 24, 17, 0, 0, TimeSpan.Zero);

    internal static DomainCertificateIssuanceRequest Request() =>
        new("enrollment-1", "owner-1", "actor-1", Draft());

    internal static DomainCertificateSigningDraft Draft() =>
        new(
            "hip-domain-cert-0001",
            1,
            "example.com",
            DomainCertificateLevel.Verified,
            "Example Site",
            "Example Organization",
            "registrant-key-1",
            [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            DomainCertificatePublicRiskClassification.Low,
            ["scan.no-critical", "tls.valid"],
            "https://hiptrust.com/api/v1/certificates/hip-domain-cert-0001/status",
            "https://hiptrust.com/certificate/hip-domain-cert-0001",
            Now.AddMinutes(-10),
            null,
            new DomainCertificatePolicyEvaluationResult(
                "example.com",
                DomainCertificateLevel.Verified,
                DomainCertificatePolicy.V1.Version,
                DomainCertificatePolicyDecision.Eligible,
                "This domain completed HIP identity and baseline security verification.",
                [
                    new DomainCertificateRequirementResult(
                        "ownership.dns",
                        DomainCertificateRequirementStatus.Satisfied,
                        "DNS domain control is verified.")
                ],
                Now.AddMinutes(-1)));

    internal static SignedDomainTrustCertificate SignedCertificate()
    {
        var draft = Draft();
        return new SignedDomainTrustCertificate(
            new DomainTrustCertificatePayload(
                draft.CertificateId,
                draft.CertificateVersion,
                DomainCertificatePolicy.V1.Version,
                draft.Domain,
                draft.PublicDisplayName,
                draft.PublicOrganizationName,
                draft.Level,
                DomainCertificateStatus.Active,
                Now,
                Now.Add(DomainCertificatePolicy.V1.VerifiedLifetime),
                draft.LastVerificationAtUtc,
                draft.LastMonitoringAtUtc,
                draft.RegistrantPublicKeyId,
                draft.CompletedVerificationMethods,
                draft.PublicRiskClassification,
                draft.PublicFindingCodes,
                draft.RevocationStatusUrl,
                draft.PublicCertificateUrl),
            new DomainTrustCertificateSignature(
                "hip:service:domain-certificate-authority",
                "certificate-key-1",
                "test-signature-v1",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                "test-signature"));
    }
}
