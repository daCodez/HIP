using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

public sealed record PublicDomainLookupResponse(
    string Domain,
    int Score,
    int FinalHipScore,
    RiskStatus Status,
    string VerificationStatus,
    IReadOnlyCollection<string> KnownRisks,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Explanations,
    string RecommendedAction,
    DateTimeOffset LastCheckedUtc,
    string SignedIdentityStatus,
    string VerificationMethod,
    string? VerifiedOrganization,
    string SignatureStatus,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    bool PublicBadgeEligible,
    string PublicLookupUrl,
    IReadOnlyCollection<ScoreBreakdownItem> ScoreBreakdown);

public sealed record ScoreBreakdownItem(
    string Category,
    int Score,
    RiskStatus Status,
    string Explanation,
    IReadOnlyCollection<string> Reasons);
