using System.Security.Cryptography;
using System.Text;
using HIP.Application.Certificates;
using HIP.Domain.Certificates;
using HIP.Domain.Domains;
using HIP.Domain.Identity;

namespace HIP.Application.Domains;

/// <summary>Outcome of issuing an approved managed-domain certificate application.</summary>
public enum ManagedDomainCertificateIssuanceStatus
{
    NotReady,
    Ineligible,
    ReviewRequired,
    IssuanceUnavailable,
    Conflict,
    Issued,
    Existing
}

/// <summary>Owner-safe managed-domain issuance result.</summary>
public sealed record ManagedDomainCertificateIssuanceResult(
    ManagedDomainCertificateIssuanceStatus Status,
    string? PublicCertificateNumber = null,
    DomainCertificatePolicyEvaluationResult? Evaluation = null,
    SignedDomainTrustCertificate? Certificate = null);

/// <summary>Creates a stable opaque public number from an already-random application identifier.</summary>
public interface IPublicCertificateNumberGenerator
{
    /// <summary>Creates the same public number for every retry of one application.</summary>
    string Create(string applicationId, DateTimeOffset applicationCreatedAtUtc);
}

/// <summary>SHA-256 based public numbering with 96 bits of opaque identifier material.</summary>
public sealed class OpaquePublicCertificateNumberGenerator : IPublicCertificateNumberGenerator
{
    /// <inheritdoc />
    public string Create(string applicationId, DateTimeOffset applicationCreatedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(applicationId) || applicationId.Length > 128 ||
            applicationId.Any(character => char.IsControl(character) || char.IsSurrogate(character)) ||
            applicationCreatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Certificate application identity is invalid.", nameof(applicationId));
        }
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"hip-public-certificate-v1\n{applicationId}"));
        return $"HIP-{applicationCreatedAtUtc.Year:D4}-{Convert.ToHexString(digest.AsSpan(0, 12))}";
    }
}

/// <summary>Revalidates approved applications and coordinates auditable signed certificate issuance.</summary>
public sealed class ManagedDomainCertificateIssuanceService(
    IDomainManagementService domainManagement,
    ManagedDomainCertificateApplicationService applicationService,
    IManagedDomainCertificationEvidenceSource evidenceSource,
    IDomainCertificatePolicyEvaluator policyEvaluator,
    IDomainEnrollmentRepository enrollmentRepository,
    IDomainCertificateIssuanceService issuanceService,
    IPublicCertificateNumberGenerator numberGenerator,
    DomainCertificatePublicEndpointOptions endpointOptions,
    TimeProvider timeProvider)
{
    /// <summary>Issues one approved application after fresh authorization and evidence checks.</summary>
    public async Task<ManagedDomainCertificateIssuanceResult> IssueAsync(
        string actorId,
        string applicationId,
        CancellationToken cancellationToken)
    {
        var application = await applicationService.GetAsync(actorId, applicationId, cancellationToken).ConfigureAwait(false);
        if (application.Status != DomainCertificateApplicationStatus.Approved)
            return Result(ManagedDomainCertificateIssuanceStatus.NotReady);

        var domain = await domainManagement.GetAsync(actorId, application.DomainId, cancellationToken).ConfigureAwait(false);
        if (domain is null || !ManagedDomainAccessPolicy.CanManageSecurity(domain.AccessRole))
            throw new DomainAccessDeniedException();

        var current = await evidenceSource.GetAsync(domain.DomainId, domain.DomainName, cancellationToken).ConfigureAwait(false);
        var now = timeProvider.GetUtcNow();
        var evaluation = policyEvaluator.Evaluate(new DomainCertificatePolicyEvaluationRequest(
            domain.DomainName, application.RequestedLevel, current.Evidence, current.ReviewSignals, now));
        if (evaluation.Decision == DomainCertificatePolicyDecision.Ineligible)
            return Result(ManagedDomainCertificateIssuanceStatus.Ineligible, evaluation: evaluation);

        var review = AuthorizedReview(application, evaluation);
        if (evaluation.Decision == DomainCertificatePolicyDecision.RequiresReview && review is null)
            return Result(ManagedDomainCertificateIssuanceStatus.ReviewRequired, evaluation: evaluation);

        var enrollment = await enrollmentRepository.GetCurrentAsync(
            domain.OwnerId, domain.DomainName, cancellationToken).ConfigureAwait(false);
        if (enrollment is null)
            return Result(ManagedDomainCertificateIssuanceStatus.NotReady, evaluation: evaluation);

        var publicNumber = numberGenerator.Create(application.ApplicationId, application.CreatedAtUtc);
        var origin = ValidatedPublicOrigin(endpointOptions.PublicOrigin);
        var methods = CompletedMethods(domain, current.Evidence);
        var verifiedAt = LatestVerification(current.Evidence) ?? domain.OwnershipVerifiedAtUtc;
        if (methods.Count == 0 || verifiedAt is null)
            return Result(ManagedDomainCertificateIssuanceStatus.NotReady, evaluation: evaluation);

        var draft = new DomainCertificateSigningDraft(
            publicNumber,
            CertificateVersion: 1,
            domain.DomainName,
            application.RequestedLevel,
            enrollment.PublicDisplayName ?? domain.DomainName,
            enrollment.PublicOrganizationName,
            RegistrantPublicKeyId: null,
            methods,
            RiskClassification(current.Evidence.CurrentTrustScore),
            ["certification.policy-passed"],
            $"{origin}/api/v1/certificates/{publicNumber}",
            $"{origin}/certificate/{publicNumber}",
            verifiedAt.Value,
            current.Evidence.LastMonitoringAtUtc,
            evaluation,
            review);
        var snapshot = new DomainCertificateIssuanceSnapshot(
            current.Evidence.CurrentTrustScore ?? 0,
            current.Evidence.DomainTrustScore,
            current.Evidence.PageTrustScore,
            current.Evidence.ContentRiskScore,
            review is null ? "PolicyEligible" : "ApprovedManualReview",
            current.Evidence.HttpsAvailable,
            current.Evidence.DnssecStatus,
            current.Evidence.ScanId,
            $"certificate-policy-{evaluation.PolicyVersion}",
            evaluation.PolicyVersion,
            evaluation.EvaluatedAtUtc);
        var issued = await issuanceService.IssueAsync(new DomainCertificateIssuanceRequest(
            enrollment.EnrollmentId,
            domain.OwnerId,
            actorId,
            draft,
            domain.DomainId,
            domain.OrganizationId,
            application.ApplicationId,
            publicNumber,
            snapshot), cancellationToken).ConfigureAwait(false);
        return issued.Status switch
        {
            DomainCertificateIssuanceStatus.Issued => Result(ManagedDomainCertificateIssuanceStatus.Issued, publicNumber, evaluation, issued.Certificate),
            DomainCertificateIssuanceStatus.Existing => Result(ManagedDomainCertificateIssuanceStatus.Existing, publicNumber, evaluation, issued.Certificate),
            DomainCertificateIssuanceStatus.Conflict => Result(ManagedDomainCertificateIssuanceStatus.Conflict, publicNumber, evaluation),
            DomainCertificateIssuanceStatus.Ineligible => Result(ManagedDomainCertificateIssuanceStatus.Ineligible, publicNumber, evaluation),
            DomainCertificateIssuanceStatus.ReviewRequired => Result(ManagedDomainCertificateIssuanceStatus.ReviewRequired, publicNumber, evaluation),
            _ => Result(ManagedDomainCertificateIssuanceStatus.IssuanceUnavailable, publicNumber, evaluation)
        };
    }

    private static DomainCertificateAuthorizedReview? AuthorizedReview(
        ManagedDomainCertificateApplication application,
        DomainCertificatePolicyEvaluationResult evaluation)
    {
        if (evaluation.Decision != DomainCertificatePolicyDecision.RequiresReview) return null;
        return application.ReviewerId is { } reviewerId && application.DecisionAtUtc is { } reviewedAt
            ? new DomainCertificateAuthorizedReview(application.ApplicationId, reviewerId, reviewedAt, "Approved")
            : null;
    }

    private static IReadOnlyCollection<VerificationMethod> CompletedMethods(
        ManagedDomainAccessView domain,
        DomainCertificateEvidenceSnapshot evidence)
    {
        var methods = new HashSet<VerificationMethod>();
        if (evidence.DnsVerifiedAtUtc is not null) methods.Add(VerificationMethod.DnsTxt);
        if (evidence.WebsiteVerifiedAtUtc is not null)
        {
            methods.Add(domain.VerificationMethod is VerificationMethod.HtmlFile or VerificationMethod.MetaTag or VerificationMethod.WellKnownHipJson
                ? domain.VerificationMethod.Value
                : VerificationMethod.WellKnownHipJson);
        }
        if (methods.Count == 0 && domain.VerificationMethod is { } method && domain.OwnershipVerifiedAtUtc is not null)
            methods.Add(method);
        return methods.Order().ToArray();
    }

    private static DateTimeOffset? LatestVerification(DomainCertificateEvidenceSnapshot evidence) =>
        new[] { evidence.DomainControlVerifiedAtUtc, evidence.DnsVerifiedAtUtc, evidence.WebsiteVerifiedAtUtc }
            .Where(value => value is not null).Max();

    private static DomainCertificatePublicRiskClassification RiskClassification(int? score) => score switch
    {
        >= 85 => DomainCertificatePublicRiskClassification.Low,
        >= 70 => DomainCertificatePublicRiskClassification.Medium,
        >= 50 => DomainCertificatePublicRiskClassification.High,
        _ => DomainCertificatePublicRiskClassification.Critical
    };

    private static string ValidatedPublicOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 || !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidOperationException("The certificate public origin must be an HTTPS origin on port 443.");
        return value.TrimEnd('/');
    }

    private static ManagedDomainCertificateIssuanceResult Result(
        ManagedDomainCertificateIssuanceStatus status,
        string? publicNumber = null,
        DomainCertificatePolicyEvaluationResult? evaluation = null,
        SignedDomainTrustCertificate? certificate = null) =>
        new(status, publicNumber, evaluation, certificate);
}
