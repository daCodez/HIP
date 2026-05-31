using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Ai;

public sealed record HipAiUrlRiskAnalysisRequest(
    string? Url,
    string? Domain,
    string? RiskReasonSummary,
    string? Platform,
    IReadOnlyDictionary<string, string>? RuleSignals);

public sealed record HipAiContentRiskAnalysisRequest(
    string? Domain,
    string? Platform,
    string? RiskReasonSummary,
    string? SuspiciousTextSnippet,
    IReadOnlyDictionary<string, string>? RuleSignals);

public sealed record HipAiRiskAnalysisResult(
    RiskStatus RiskLevel,
    int Confidence,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> DetectedPatterns,
    string RecommendedAction,
    bool RequiresReview,
    bool SuggestRule,
    bool IsPlaceholder,
    string ProviderName);

public sealed record HipAiRuleSuggestionRequest(
    string? Domain,
    string? Url,
    string? Platform,
    HipAiRiskAnalysisResult Analysis);

public sealed record HipAiRuleSuggestionResult(
    TrustRule ProposedRule,
    bool SimulationRequired,
    bool RequiresApproval,
    RuleMode RecommendedMode,
    bool IsPlaceholder,
    string ProviderName);
