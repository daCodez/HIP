using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;

namespace HIP.Application.Certificates;

public sealed record DomainCertificatePublicEndpointOptions(string PublicOrigin)
{
    public static DomainCertificatePublicEndpointOptions Default { get; } =
        new("https://guardwithhip.com");
}

public enum DomainCertificateProvisioningStatus
{
    NotFound,
    NotReady,
    ScanUnavailable,
    PersistenceUnavailable,
    Ineligible,
    ReviewRequired,
    IssuanceUnavailable,
    Conflict,
    Issued,
    Existing
}

public sealed record DomainCertificateProvisioningResult(
    DomainCertificateProvisioningStatus Status,
    DomainCertificatePolicyEvaluationResult? Evaluation = null,
    SignedDomainTrustCertificate? Certificate = null);

public interface IDomainCertificateProvisioningService
{
    Task<DomainCertificateProvisioningResult> ReviewAndIssueAsync(
        string ownerId,
        string domain,
        bool accountContactVerified,
        CancellationToken cancellationToken);
}

/// <summary>Coordinates owner-bound server evidence, durable review state, and signed V1 issuance.</summary>
public sealed class DomainCertificateProvisioningService(
    IDomainEnrollmentRepository enrollmentRepository,
    IDomainCertificateSecurityScanService securityScanService,
    IDomainCertificateIssuanceService issuanceService,
    ICanonicalJsonService canonicalJsonService,
    DomainCertificatePublicEndpointOptions endpointOptions) : IDomainCertificateProvisioningService
{
    public async Task<DomainCertificateProvisioningResult> ReviewAndIssueAsync(
        string ownerId,
        string domain,
        bool accountContactVerified,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerId);
        var normalized = PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        var enrollment = await enrollmentRepository.GetCurrentAsync(ownerId, normalized, cancellationToken)
            .ConfigureAwait(false);
        if (enrollment is null)
        {
            return Result(DomainCertificateProvisioningStatus.NotFound);
        }
        if (enrollment.Status is not DomainEnrollmentStatus.PendingSecurityReview and not DomainEnrollmentStatus.Verified ||
            enrollment.DnsVerifiedAtUtc is null ||
            enrollment.WebsiteVerifiedAtUtc is null ||
            enrollment.IdentityCompletedAtUtc is null ||
            string.IsNullOrWhiteSpace(enrollment.PublicDisplayName) ||
            enrollment.ApplicationStatus != DomainCertificateApplicationStatus.Approved)
        {
            return Result(DomainCertificateProvisioningStatus.NotReady);
        }

        var scan = await securityScanService.ScanAsync(
                new DomainCertificateSecurityScanRequest(
                    normalized,
                    DomainCertificateLevel.Verified,
                    accountContactVerified,
                    enrollment.DnsVerifiedAtUtc,
                    enrollment.DnsVerifiedAtUtc,
                    enrollment.WebsiteVerifiedAtUtc,
                    IdentityInformationCompleted: true),
                cancellationToken)
            .ConfigureAwait(false);
        if (scan.Status == DomainCertificateSecurityScanStatus.ScanUnavailable)
        {
            return Result(DomainCertificateProvisioningStatus.ScanUnavailable);
        }
        if (scan.Status != DomainCertificateSecurityScanStatus.Evaluated ||
            scan.Scan is null ||
            scan.Evaluation is null)
        {
            return Result(DomainCertificateProvisioningStatus.PersistenceUnavailable);
        }

        var evaluation = scan.Evaluation;
        var evidenceDigest = Digest(evaluation);
        if (enrollment.Status == DomainEnrollmentStatus.PendingSecurityReview)
        {
            var reviewWrite = await enrollmentRepository.TryApplySecurityReviewAsync(
                    new DomainCertificateSecurityReviewRecord(
                        enrollment.EnrollmentId,
                        ownerId,
                        normalized,
                        evaluation.Decision,
                        scan.Scan.FinalHipScore,
                        CriticalFindingCount(evaluation),
                        evidenceDigest,
                        evaluation.EvaluatedAtUtc,
                        $"certificate-event:review:{evidenceDigest[7..55]}"),
                    cancellationToken)
                .ConfigureAwait(false);
            if (reviewWrite.Status is not DomainEnrollmentTransitionWriteStatus.Updated
                and not DomainEnrollmentTransitionWriteStatus.AlreadyApplied)
            {
                return new DomainCertificateProvisioningResult(
                    DomainCertificateProvisioningStatus.Conflict,
                    evaluation);
            }
        }

        if (evaluation.Decision == DomainCertificatePolicyDecision.Ineligible)
        {
            return new DomainCertificateProvisioningResult(
                DomainCertificateProvisioningStatus.Ineligible,
                evaluation);
        }
        if (evaluation.Decision == DomainCertificatePolicyDecision.RequiresReview)
        {
            return new DomainCertificateProvisioningResult(
                DomainCertificateProvisioningStatus.ReviewRequired,
                evaluation);
        }

        var certificateId = CertificateId(enrollment.EnrollmentId, normalized);
        var origin = ValidatedPublicOrigin(endpointOptions.PublicOrigin);
        var draft = new DomainCertificateSigningDraft(
            certificateId,
            CertificateVersion: 1,
            normalized,
            DomainCertificateLevel.Verified,
            enrollment.PublicDisplayName,
            enrollment.PublicOrganizationName,
            RegistrantPublicKeyId: null,
            [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            scan.PublicRiskClassification,
            scan.PublicFindingCodes ?? [],
            $"{origin}/api/v1/certificates/{certificateId}",
            $"{origin}/certificate/{certificateId}",
            enrollment.WebsiteVerifiedAtUtc.Value,
            LastMonitoringAtUtc: null,
            evaluation);
        var issued = await issuanceService.IssueAsync(
                new DomainCertificateIssuanceRequest(
                    enrollment.EnrollmentId,
                    ownerId,
                    ownerId,
                    draft),
                cancellationToken)
            .ConfigureAwait(false);
        return issued.Status switch
        {
            DomainCertificateIssuanceStatus.Issued => new(
                DomainCertificateProvisioningStatus.Issued,
                evaluation,
                issued.Certificate),
            DomainCertificateIssuanceStatus.Existing => new(
                DomainCertificateProvisioningStatus.Existing,
                evaluation,
                issued.Certificate),
            DomainCertificateIssuanceStatus.Conflict => new(
                DomainCertificateProvisioningStatus.Conflict,
                evaluation),
            _ => new DomainCertificateProvisioningResult(
                DomainCertificateProvisioningStatus.IssuanceUnavailable,
                evaluation)
        };
    }

    private string Digest(DomainCertificatePolicyEvaluationResult evaluation)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(evaluation);
        return $"sha256:{Convert.ToHexString(
            SHA256.HashData(canonicalJsonService.Canonicalize(json))).ToLowerInvariant()}";
    }

    private static int CriticalFindingCount(DomainCertificatePolicyEvaluationResult evaluation) =>
        evaluation.Requirements.Any(item =>
            item.Code == "security.no-critical-findings" &&
            item.Status == DomainCertificateRequirementStatus.Missing)
            ? 1
            : 0;

    private static string CertificateId(string enrollmentId, string domain)
    {
        var digest = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{enrollmentId}\n{domain}\n{DomainCertificatePolicy.V1.Version}")))
            .ToLowerInvariant();
        return $"hip-domain-cert-v1-{digest[..40]}";
    }

    private static string ValidatedPublicOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "The certificate public origin must be an HTTPS origin on port 443.");
        }
        return value.TrimEnd('/');
    }

    private static DomainCertificateProvisioningResult Result(
        DomainCertificateProvisioningStatus status) => new(status);
}
