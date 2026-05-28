using HIP.Domain.Risk;

namespace HIP.Domain.Review;

public sealed record ReviewItem(
    string ReviewItemId,
    ReviewType ReviewType,
    TargetType TargetType,
    string TargetId,
    string Title,
    string Summary,
    RiskStatus RiskLevel,
    ReviewStatus Status,
    ReviewPriority Priority,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string CreatedBy,
    string? AssignedTo,
    string Source,
    string EvidenceSummary,
    IReadOnlyDictionary<string, string> PrivacySafeEvidence,
    string RecommendedAction,
    string? Decision,
    string? DecisionReason);
