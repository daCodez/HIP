using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed record RuleScanContext(
    string Url,
    string Domain,
    int DomainAgeDays,
    bool UsesShortener,
    bool HasObfuscation,
    int RedirectCount,
    int SenderScore,
    int DomainScore,
    int ContentRiskScore);

public sealed record RuleEvaluationRequest(
    IReadOnlyCollection<TrustRule>? Rules,
    RuleScanContext Context);

public sealed record RuleEvaluationResponse(
    IReadOnlyCollection<string> MatchedRules,
    IReadOnlyCollection<RuleActionSummary> Actions,
    RiskStatus RiskLevel,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<RuleEvaluationItem> WatchModeResults,
    IReadOnlyCollection<RuleEvaluationItem> EnforcementResults,
    bool ShouldRouteToSafetyPage,
    bool ShouldBlock,
    bool RequiresReview);

public sealed record RuleEvaluationItem(
    string RuleId,
    string Name,
    RuleMode Mode,
    bool Matched,
    IReadOnlyCollection<RuleActionSummary> Actions,
    IReadOnlyCollection<string> Reasons,
    bool Enforced);

public sealed record RuleActionSummary(
    RuleActionType Type,
    string Value);
