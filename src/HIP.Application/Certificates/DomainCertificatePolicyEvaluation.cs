using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Certificates;
using HIP.Domain.Domains;

namespace HIP.Application.Certificates;

/// <summary>Final routing decision produced before certificate issuance.</summary>
public enum DomainCertificatePolicyDecision
{
    Ineligible,
    RequiresReview,
    Eligible
}

/// <summary>Status of an individual policy requirement.</summary>
public enum DomainCertificateRequirementStatus
{
    Missing,
    ReviewRequired,
    Satisfied
}

/// <summary>One explainable, non-secret certificate requirement result.</summary>
public sealed record DomainCertificateRequirementResult(
    string Code,
    DomainCertificateRequirementStatus Status,
    string PublicSummary);

/// <summary>Minimum evidence snapshot used by the V1 certificate policy.</summary>
public sealed record DomainCertificateEvidenceSnapshot(
    bool AccountContactVerified = false,
    DateTimeOffset? DomainControlVerifiedAtUtc = null,
    DateTimeOffset? DnsVerifiedAtUtc = null,
    DateTimeOffset? WebsiteVerifiedAtUtc = null,
    bool InitialSecurityScanCompleted = false,
    int UnresolvedCriticalFindings = 0,
    bool IdentityInformationCompleted = false,
    bool HttpsAvailable = false,
    bool TlsCertificateValid = false,
    bool RequiredPoliciesPassed = false,
    bool ContinuousMonitoringEnabled = false,
    bool CertificateActive = false,
    int? CurrentTrustScore = null,
    DateTimeOffset? LastMonitoringAtUtc = null,
    DomainDnssecStatus DnssecStatus = DomainDnssecStatus.Unknown,
    int UnresolvedHighRiskFindings = 0,
    bool OrganizationIdentityVerified = false,
    int? DomainTrustScore = null,
    int? PageTrustScore = null,
    int? ContentRiskScore = null,
    string? ScanId = null);

/// <summary>Signals that prevent automatic issuance and require an authorized human decision.</summary>
public sealed record DomainCertificateReviewSignals(
    bool IdentityConflict = false,
    bool LowScanConfidence = false,
    bool UnresolvedHighRiskFindings = false,
    bool ReputationConflict = false,
    bool OwnershipRecentlyChanged = false,
    bool PolicyRequiresManualReview = false,
    bool SuspiciousCertificateData = false,
    bool BadgeAbuseReported = false);

/// <summary>Reproducible input to one certificate policy evaluation.</summary>
public sealed record DomainCertificatePolicyEvaluationRequest(
    string Domain,
    DomainCertificateLevel RequestedLevel,
    DomainCertificateEvidenceSnapshot Evidence,
    DomainCertificateReviewSignals ReviewSignals,
    DateTimeOffset EvaluatedAtUtc);

/// <summary>Explainable result stored before any certificate signing or state mutation.</summary>
public sealed record DomainCertificatePolicyEvaluationResult(
    string Domain,
    DomainCertificateLevel RequestedLevel,
    string PolicyVersion,
    DomainCertificatePolicyDecision Decision,
    string PublicMeaning,
    IReadOnlyCollection<DomainCertificateRequirementResult> Requirements,
    DateTimeOffset EvaluatedAtUtc);

/// <summary>Evaluates certificate eligibility without signing or persisting a certificate.</summary>
public interface IDomainCertificatePolicyEvaluator
{
    DomainCertificatePolicyEvaluationResult Evaluate(DomainCertificatePolicyEvaluationRequest request);
}

/// <summary>Applies versioned certificate policy while keeping assurance level separate from HIP score.</summary>
public sealed class DomainCertificatePolicyEvaluator(DomainCertificatePolicy policy)
    : IDomainCertificatePolicyEvaluator
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly DomainCertificatePolicy certificatePolicy = policy.Validate();

    /// <inheritdoc />
    public DomainCertificatePolicyEvaluationResult Evaluate(DomainCertificatePolicyEvaluationRequest request)
    {
        Validate(request);
        var requirements = new List<DomainCertificateRequirementResult>();
        AddRequirement(requirements, "account.contact", request.Evidence.AccountContactVerified,
            "The HIP account contact is verified.", "Verify the HIP account contact before certification can continue.");
        AddRequirement(requirements, "ownership.domain-control",
            IsCurrentEvidence(request.Evidence.DomainControlVerifiedAtUtc, request.EvaluatedAtUtc),
            "Domain control evidence is present.", "Domain control has not been verified.");

        if (request.RequestedLevel is DomainCertificateLevel.Verified or DomainCertificateLevel.Monitored or DomainCertificateLevel.Certified)
        {
            AddVerifiedRequirements(requirements, request);
        }
        if (request.RequestedLevel == DomainCertificateLevel.Monitored)
        {
            AddMonitoredRequirements(requirements, request);
        }
        if (request.RequestedLevel == DomainCertificateLevel.Certified)
        {
            AddCertifiedRequirements(requirements, request);
        }

        AddReviewSignals(requirements, request.ReviewSignals);
        var decision = requirements.Any(item => item.Status == DomainCertificateRequirementStatus.Missing)
            ? DomainCertificatePolicyDecision.Ineligible
            : requirements.Any(item => item.Status == DomainCertificateRequirementStatus.ReviewRequired)
                ? DomainCertificatePolicyDecision.RequiresReview
                : DomainCertificatePolicyDecision.Eligible;

        return new DomainCertificatePolicyEvaluationResult(
            request.Domain,
            request.RequestedLevel,
            certificatePolicy.Version,
            decision,
            PublicMeaning(request.RequestedLevel),
            requirements.AsReadOnly(),
            request.EvaluatedAtUtc);
    }

    private void AddVerifiedRequirements(
        ICollection<DomainCertificateRequirementResult> requirements,
        DomainCertificatePolicyEvaluationRequest request)
    {
        var evidence = request.Evidence;
        AddRequirement(requirements, "ownership.dns", IsCurrentEvidence(evidence.DnsVerifiedAtUtc, request.EvaluatedAtUtc),
            "DNS domain control is verified.", "DNS domain control verification is required.");
        AddRequirement(requirements, "ownership.https", IsCurrentEvidence(evidence.WebsiteVerifiedAtUtc, request.EvaluatedAtUtc),
            "HTTPS website control is verified.", "HTTPS website control verification is required.");
        AddRequirement(requirements, "security.baseline", evidence.InitialSecurityScanCompleted,
            "The initial HIP security review completed.", "The initial HIP security review has not completed.");
        AddRequirement(requirements, "security.no-critical-findings", evidence.UnresolvedCriticalFindings == 0,
            "No unresolved critical findings are present.", "Resolve critical findings before certification.");
        AddRequirement(requirements, "identity.public-profile", evidence.IdentityInformationCompleted,
            "Required public identity information is complete.", "Required identity information is incomplete.");
        AddRequirement(requirements, "transport.https", evidence.HttpsAvailable,
            "HTTPS is available.", "HTTPS availability is required.");
        AddRequirement(requirements, "transport.tls", evidence.TlsCertificateValid,
            "The TLS certificate check passed.", "The TLS certificate check did not pass.");
        AddRequirement(requirements, "policy.required", evidence.RequiredPoliciesPassed,
            "Required HIP verification policies passed.", "One or more required HIP verification policies did not pass.");
        if (certificatePolicy.RequireDnssecForVerified)
        {
            AddRequirement(requirements, "dnssec.valid", evidence.DnssecStatus == DomainDnssecStatus.Valid,
                "DNSSEC validation passed.", "A valid DNSSEC chain is required by this policy.");
        }
    }

    private void AddCertifiedRequirements(
        ICollection<DomainCertificateRequirementResult> requirements,
        DomainCertificatePolicyEvaluationRequest request)
    {
        var evidence = request.Evidence;
        if (certificatePolicy.RequireDnssecForCertified &&
            requirements.All(item => item.Code != "dnssec.valid"))
        {
            AddRequirement(requirements, "dnssec.valid", evidence.DnssecStatus == DomainDnssecStatus.Valid,
                "DNSSEC validation passed.", "Certified domains require a valid DNSSEC chain.");
        }
        AddRequirement(requirements, "security.no-high-risk-findings", evidence.UnresolvedHighRiskFindings == 0,
            "No unresolved high-risk findings are present.", "Resolve high-risk findings before Certified issuance.");
        if (certificatePolicy.RequireIdentityForCertified)
        {
            AddRequirement(requirements, "identity.organization", evidence.OrganizationIdentityVerified,
                "The organization or registrant identity is verified.", "Certified issuance requires verified organization or registrant identity.");
        }
        AddRequirement(requirements, "score.certified-minimum",
            evidence.CurrentTrustScore is not null && evidence.CurrentTrustScore >= certificatePolicy.MinimumCertifiedTrustScore,
            "The HIP score meets the Certified policy threshold.", "The HIP score is below the Certified policy threshold.");
        if (certificatePolicy.RequireManualReviewForCertified && !request.ReviewSignals.PolicyRequiresManualReview)
        {
            requirements.Add(new DomainCertificateRequirementResult(
                "review.certified",
                DomainCertificateRequirementStatus.ReviewRequired,
                "Certified issuance requires authorized manual review."));
        }
    }

    private void AddMonitoredRequirements(
        ICollection<DomainCertificateRequirementResult> requirements,
        DomainCertificatePolicyEvaluationRequest request)
    {
        var evidence = request.Evidence;
        AddRequirement(requirements, "monitoring.enabled", evidence.ContinuousMonitoringEnabled,
            "Continuous HIP monitoring is enabled.", "Continuous HIP monitoring is not enabled.");
        AddRequirement(requirements, "monitoring.certificate-active", evidence.CertificateActive,
            "The HIP Domain Trust Certificate is active.", "An active HIP Domain Trust Certificate is required.");
        AddRequirement(requirements, "monitoring.score",
            evidence.CurrentTrustScore is not null &&
            evidence.CurrentTrustScore >= certificatePolicy.MinimumMonitoredTrustScore,
            "The current HIP score meets the monitoring policy threshold.",
            "The current HIP score is below the monitoring policy threshold.");
        AddRequirement(requirements, "monitoring.freshness",
            evidence.LastMonitoringAtUtc is { } monitoredAt &&
            IsCurrentEvidence(monitoredAt, request.EvaluatedAtUtc) &&
            monitoredAt >= request.EvaluatedAtUtc.Subtract(certificatePolicy.MonitoringFreshness),
            "Monitoring evidence is current.", "Monitoring evidence is missing or stale.");
    }

    private static void AddReviewSignals(
        ICollection<DomainCertificateRequirementResult> requirements,
        DomainCertificateReviewSignals signals)
    {
        AddReview(requirements, "review.identity-conflict", signals.IdentityConflict, "Identity information conflicts require review.");
        AddReview(requirements, "review.low-confidence", signals.LowScanConfidence, "Low-confidence security evidence requires review.");
        AddReview(requirements, "review.high-risk", signals.UnresolvedHighRiskFindings, "Unresolved high-risk findings require review.");
        AddReview(requirements, "review.reputation-conflict", signals.ReputationConflict, "Conflicting reputation evidence requires review.");
        AddReview(requirements, "review.ownership-change", signals.OwnershipRecentlyChanged, "Recent ownership changes require review.");
        AddReview(requirements, "review.policy", signals.PolicyRequiresManualReview, "Certificate policy requires manual review.");
        AddReview(requirements, "review.suspicious-data", signals.SuspiciousCertificateData, "Suspicious certificate data requires review.");
        AddReview(requirements, "review.badge-abuse", signals.BadgeAbuseReported, "Reported badge misuse requires review.");
    }

    private static void AddRequirement(
        ICollection<DomainCertificateRequirementResult> requirements,
        string code,
        bool satisfied,
        string satisfiedSummary,
        string missingSummary) =>
        requirements.Add(new DomainCertificateRequirementResult(
            code,
            satisfied ? DomainCertificateRequirementStatus.Satisfied : DomainCertificateRequirementStatus.Missing,
            satisfied ? satisfiedSummary : missingSummary));

    private static void AddReview(
        ICollection<DomainCertificateRequirementResult> requirements,
        string code,
        bool required,
        string summary)
    {
        if (required)
        {
            requirements.Add(new DomainCertificateRequirementResult(
                code,
                DomainCertificateRequirementStatus.ReviewRequired,
                summary));
        }
    }

    private static bool IsCurrentEvidence(DateTimeOffset? timestamp, DateTimeOffset evaluatedAtUtc) =>
        timestamp is { Offset: { } offset } &&
        offset == TimeSpan.Zero &&
        timestamp <= evaluatedAtUtc.Add(MaximumClockSkew);

    private static string PublicMeaning(DomainCertificateLevel level) => level switch
    {
        DomainCertificateLevel.Registered => "Domain control has been verified by HIP.",
        DomainCertificateLevel.Verified => "This domain completed HIP identity and baseline security verification.",
        DomainCertificateLevel.Monitored => "This domain is verified and continuously monitored by HIP.",
        DomainCertificateLevel.Certified => "This domain passed HIP's stronger certification requirements and required review.",
        _ => throw new ArgumentOutOfRangeException(nameof(level))
    };

    private static void Validate(DomainCertificatePolicyEvaluationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Evidence);
        ArgumentNullException.ThrowIfNull(request.ReviewSignals);
        var normalized = DomainInputValidator.ValidateAndNormalize(request.Domain);
        if (!string.Equals(normalized, request.Domain, StringComparison.Ordinal))
        {
            throw new ArgumentException("Certificate policy requires a canonical domain.", nameof(request));
        }
        if (request.EvaluatedAtUtc.Offset != TimeSpan.Zero ||
            request.Evidence.UnresolvedCriticalFindings < 0 ||
            request.Evidence.UnresolvedHighRiskFindings < 0 ||
            request.Evidence.CurrentTrustScore is < 0 or > 100 ||
            request.Evidence.DomainTrustScore is < 0 or > 100 ||
            request.Evidence.PageTrustScore is < 0 or > 100 ||
            request.Evidence.ContentRiskScore is < 0 or > 100 ||
            request.Evidence.ScanId is { Length: > 220 } ||
            request.Evidence.ScanId?.Any(char.IsControl) == true)
        {
            throw new ArgumentException("Certificate evidence snapshot values are invalid.", nameof(request));
        }
    }
}
