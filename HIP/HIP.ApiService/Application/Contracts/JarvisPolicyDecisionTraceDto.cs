namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Cross-pillar decision trace linking identity, reputation, and policy decision context.
/// </summary>
public sealed record JarvisPolicyDecisionTraceDto(
    string IdentityId,
    bool IdentityExists,
    int ReputationScore,
    double AcceptanceComponent,
    double FeedbackComponent,
    double TrustComponent,
    double AggregatePenaltyComponent,
    double EventPenaltyComponent,
    int EventCount,
    string Decision,
    string PolicyCode,
    string PolicyVersion,
    string ToolAccessReason,
    DateTimeOffset ComputedAtUtc);
