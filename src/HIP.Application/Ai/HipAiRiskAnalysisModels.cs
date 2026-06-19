using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Ai;

/// <summary>
/// Describes a privacy-safe URL risk analysis request for an AI-assisted analyzer.
/// </summary>
/// <param name="Url">Optional URL to analyze. Callers must not include unrelated browsing history.</param>
/// <param name="Domain">Optional normalized domain for domain-level risk context.</param>
/// <param name="RiskReasonSummary">Short privacy-safe reason summary from existing HIP signals.</param>
/// <param name="Platform">Optional source platform, such as BrowserPlugin or PublicLookup.</param>
/// <param name="RuleSignals">Structured rule signals that avoid raw page text, passwords, tokens, and private messages.</param>
public sealed record HipAiUrlRiskAnalysisRequest(
    string? Url,
    string? Domain,
    string? RiskReasonSummary,
    string? Platform,
    IReadOnlyDictionary<string, string>? RuleSignals);

/// <summary>
/// Describes a privacy-safe content risk analysis request for AI-assisted review.
/// </summary>
/// <param name="Domain">Optional domain connected to the content signals.</param>
/// <param name="Platform">Optional source platform that observed the signals.</param>
/// <param name="RiskReasonSummary">Short privacy-safe summary of why the content may be risky.</param>
/// <param name="SuspiciousTextSnippet">Small optional snippet for controlled analysis; callers must not send private messages or form values.</param>
/// <param name="RuleSignals">Structured rule signals derived from safer detectors.</param>
public sealed record HipAiContentRiskAnalysisRequest(
    string? Domain,
    string? Platform,
    string? RiskReasonSummary,
    string? SuspiciousTextSnippet,
    IReadOnlyDictionary<string, string>? RuleSignals);

/// <summary>
/// Returns the AI-assisted risk analysis result used by HIP as supporting evidence, not final authority.
/// </summary>
/// <param name="RiskLevel">Suggested risk level from the analyzer.</param>
/// <param name="Confidence">Analyzer confidence from 0 to 100.</param>
/// <param name="Reasons">Plain-English reasons suitable for review and user display.</param>
/// <param name="DetectedPatterns">Detected pattern names, such as phishing wording or suspicious redirect behavior.</param>
/// <param name="RecommendedAction">Suggested next action for HIP to consider.</param>
/// <param name="RequiresReview">Whether the result should be reviewed by an administrator.</param>
/// <param name="SuggestRule">Whether the analyzer believes a structured rule suggestion may be useful.</param>
/// <param name="IsPlaceholder">Whether the result came from a non-production placeholder analyzer.</param>
/// <param name="ProviderName">Name of the analyzer or provider that produced the result.</param>
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

/// <summary>
/// Describes a request to turn an AI-assisted finding into a structured HIP rule suggestion.
/// </summary>
/// <param name="Domain">Optional domain related to the finding.</param>
/// <param name="Url">Optional URL related to the finding.</param>
/// <param name="Platform">Optional source platform for audit and review context.</param>
/// <param name="Analysis">The analysis result that motivated the rule suggestion.</param>
public sealed record HipAiRuleSuggestionRequest(
    string? Domain,
    string? Url,
    string? Platform,
    HipAiRiskAnalysisResult Analysis);

/// <summary>
/// Returns a proposed structured rule and the safety controls required before it can affect live scoring.
/// </summary>
/// <param name="ProposedRule">The generated HIP trust rule.</param>
/// <param name="SimulationRequired">Whether the rule must run through simulation before activation.</param>
/// <param name="RequiresApproval">Whether an administrator must approve the rule before enforcement.</param>
/// <param name="RecommendedMode">Recommended starting mode, such as Watch or Active.</param>
/// <param name="IsPlaceholder">Whether the suggestion came from a non-production placeholder analyzer.</param>
/// <param name="ProviderName">Name of the analyzer or provider that proposed the rule.</param>
public sealed record HipAiRuleSuggestionResult(
    TrustRule ProposedRule,
    bool SimulationRequired,
    bool RequiresApproval,
    RuleMode RecommendedMode,
    bool IsPlaceholder,
    string ProviderName);
