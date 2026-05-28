using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

public sealed record PublicDomainLookupResponse(
    string Domain,
    int FinalHipScore,
    RiskStatus Status,
    string VerificationStatus,
    IReadOnlyCollection<string> KnownRisks,
    IReadOnlyCollection<string> Explanations,
    DateTimeOffset LastCheckedUtc,
    string SignedIdentityStatus,
    bool PublicBadgeEligible,
    string PublicLookupUrl,
    IReadOnlyCollection<ScoreBreakdownItem> ScoreBreakdown);

public sealed record ScoreBreakdownItem(
    string Category,
    int Score,
    RiskStatus Status,
    string Explanation,
    IReadOnlyCollection<string> Reasons);
