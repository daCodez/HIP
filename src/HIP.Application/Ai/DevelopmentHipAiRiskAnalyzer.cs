using System.Text.Json;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Ai;

public sealed class DevelopmentHipAiRiskAnalyzer : IHipAiRiskAnalyzer
{
    public const string ProviderName = "Development deterministic HIP AI placeholder - not production AI";

    private static readonly string[] ShortenerDomains =
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    ];

    private static readonly string[] UrgencyTerms =
    [
        "urgent",
        "act now",
        "limited time",
        "immediately",
        "final notice",
        "expires"
    ];

    private static readonly string[] RewardTerms =
    [
        "free",
        "prize",
        "reward",
        "claim",
        "gift",
        "win",
        "won",
        "500l",
        "crypto giveaway"
    ];

    private static readonly string[] CredentialTerms =
    [
        "login",
        "password",
        "verify account",
        "reset account",
        "security alert",
        "confirm identity"
    ];

    public Task<HipAiRiskAnalysisResult> AnalyzeUrlRiskAsync(
        HipAiUrlRiskAnalysisRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidatePrivacySafeInput(request.RiskReasonSummary, nameof(request.RiskReasonSummary));

        var text = string.Join(' ', request.Url, request.Domain, request.RiskReasonSummary, request.Platform);
        var patterns = DetectPatterns(text, request.RuleSignals);
        var result = BuildAnalysis(patterns, "URL/link analysis");
        return Task.FromResult(result);
    }

    public Task<HipAiRiskAnalysisResult> AnalyzeContentRiskAsync(
        HipAiContentRiskAnalysisRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidatePrivacySafeInput(request.RiskReasonSummary, nameof(request.RiskReasonSummary));
        ValidatePrivacySafeInput(request.SuspiciousTextSnippet, nameof(request.SuspiciousTextSnippet));

        var text = string.Join(' ', request.Domain, request.Platform, request.RiskReasonSummary, request.SuspiciousTextSnippet);
        var patterns = DetectPatterns(text, request.RuleSignals);
        var result = BuildAnalysis(patterns, "Content-context analysis");
        return Task.FromResult(result);
    }

    public Task<HipAiRuleSuggestionResult> SuggestRuleAsync(
        HipAiRuleSuggestionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var severity = request.Analysis.RiskLevel switch
        {
            RiskStatus.Critical => RuleSeverity.Critical,
            RiskStatus.Dangerous => RuleSeverity.Dangerous,
            RiskStatus.HighRisk => RuleSeverity.HighRisk,
            RiskStatus.Caution => RuleSeverity.Caution,
            _ => RuleSeverity.Low
        };

        var highImpact = severity is RuleSeverity.HighRisk or RuleSeverity.Dangerous or RuleSeverity.Critical;
        var conditions = BuildConditions(request);
        var actions = BuildActions(request.Analysis, highImpact);
        var ruleId = $"ai-suggested-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..43];

        var rule = new TrustRule(
            ruleId,
            BuildRuleName(request.Analysis),
            "AI-assisted MVP rule suggestion. This rule must be simulated and reviewed before enforcement.",
            Enabled: true,
            highImpact ? RuleMode.Watch : RuleMode.Active,
            severity,
            conditions,
            actions,
            RequiresApproval: highImpact,
            SimulationRequired: true,
            CreatedBy: "HIP AI Risk Analyzer MVP",
            CreatedReason: "Generated from privacy-safe risk patterns. AI suggestions do not punish users without rules, simulation, and review.",
            highImpact ? ApprovalStatus.Pending : ApprovalStatus.NotRequired,
            request.Analysis.Confidence,
            Version: 1);

        return Task.FromResult(new HipAiRuleSuggestionResult(
            rule,
            SimulationRequired: true,
            RequiresApproval: rule.RequiresApproval,
            RecommendedMode: rule.Mode,
            IsPlaceholder: true,
            ProviderName));
    }

    private static IReadOnlyCollection<string> DetectPatterns(
        string input,
        IReadOnlyDictionary<string, string>? ruleSignals)
    {
        var text = input.ToLowerInvariant();
        var patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (ShortenerDomains.Any(text.Contains) || IsSignalTrue(ruleSignals, "url.usesShortener"))
        {
            patterns.Add("ShortenedUrl");
        }

        if (text.Contains("hxxp", StringComparison.Ordinal) ||
            text.Contains("dot com", StringComparison.Ordinal) ||
            text.Contains("[.]", StringComparison.Ordinal) ||
            text.Contains("htt ps", StringComparison.Ordinal) ||
            IsSignalTrue(ruleSignals, "url.isObfuscated"))
        {
            patterns.Add("ObfuscatedUrl");
        }

        if (UrgencyTerms.Any(text.Contains) || IsSignalTrue(ruleSignals, "content.containsUrgencyLanguage"))
        {
            patterns.Add("UrgencyLanguage");
        }

        if (RewardTerms.Any(text.Contains) || IsSignalTrue(ruleSignals, "content.containsFinancialPromise"))
        {
            patterns.Add("RewardOrFinancialPromise");
        }

        if (CredentialTerms.Any(text.Contains))
        {
            patterns.Add("CredentialRequest");
        }

        if (text.Contains("known phishing", StringComparison.Ordinal) ||
            text.Contains("known scam", StringComparison.Ordinal) ||
            text.Contains("malware", StringComparison.Ordinal) ||
            IsSignalTrue(ruleSignals, "url.hasKnownRisk"))
        {
            patterns.Add("KnownRiskSignal");
        }

        return patterns.ToArray();
    }

    private static HipAiRiskAnalysisResult BuildAnalysis(IReadOnlyCollection<string> patterns, string analysisType)
    {
        var score = patterns.Sum(pattern => pattern switch
        {
            "KnownRiskSignal" => 35,
            "ObfuscatedUrl" => 25,
            "ShortenedUrl" => 20,
            "CredentialRequest" => 20,
            "UrgencyLanguage" => 15,
            "RewardOrFinancialPromise" => 15,
            _ => 5
        });

        var riskLevel = score switch
        {
            >= 70 => RiskStatus.Dangerous,
            >= 45 => RiskStatus.HighRisk,
            >= 20 => RiskStatus.Caution,
            _ => RiskStatus.Unknown
        };

        var confidence = Math.Clamp(35 + score, 0, 95);
        var reasons = patterns.Count == 0
            ? [$"{analysisType} found no strong AI-assisted risk patterns in the privacy-safe input."]
            : patterns.Select(ToReason).ToArray();

        var recommendedAction = riskLevel switch
        {
            RiskStatus.Dangerous or RiskStatus.Critical => "RouteToSafetyPage",
            RiskStatus.HighRisk => "RouteToSafetyPage",
            RiskStatus.Caution => "ShowCaution",
            _ => "RequireMoreSignals"
        };

        return new HipAiRiskAnalysisResult(
            riskLevel,
            confidence,
            reasons,
            patterns,
            recommendedAction,
            RequiresReview: riskLevel is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical,
            SuggestRule: confidence >= 70 && riskLevel is (RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical),
            IsPlaceholder: true,
            ProviderName);
    }

    private static IReadOnlyCollection<RuleCondition> BuildConditions(HipAiRuleSuggestionRequest request)
    {
        var conditions = new List<RuleCondition>();

        foreach (var pattern in request.Analysis.DetectedPatterns)
        {
            switch (pattern)
            {
                case "ShortenedUrl":
                    conditions.Add(new RuleCondition("url.usesShortener", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
                    break;
                case "ObfuscatedUrl":
                    conditions.Add(new RuleCondition("url.isObfuscated", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
                    break;
                case "UrgencyLanguage":
                    conditions.Add(new RuleCondition("content.containsUrgencyLanguage", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
                    break;
                case "RewardOrFinancialPromise":
                    conditions.Add(new RuleCondition("content.containsFinancialPromise", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
                    break;
                case "KnownRiskSignal":
                    conditions.Add(new RuleCondition("url.hasKnownRisk", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
                    break;
            }
        }

        if (!string.IsNullOrWhiteSpace(request.Domain))
        {
            conditions.Add(new RuleCondition("domain.name", RuleOperator.Equals, JsonSerializer.SerializeToElement(NormalizeDomain(request.Domain))));
        }

        if (conditions.Count == 0)
        {
            conditions.Add(new RuleCondition("url.hasKnownRisk", RuleOperator.Equals, JsonSerializer.SerializeToElement(true)));
        }

        return conditions;
    }

    private static IReadOnlyCollection<RuleAction> BuildActions(HipAiRiskAnalysisResult analysis, bool highImpact)
    {
        var actions = new List<RuleAction>
        {
            new(RuleActionType.AddReason, JsonSerializer.SerializeToElement(string.Join(' ', analysis.Reasons))),
            new(RuleActionType.MarkForSimulation, JsonSerializer.SerializeToElement(true))
        };

        if (highImpact)
        {
            actions.Add(new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement(analysis.RiskLevel.ToString())));
            actions.Add(new RuleAction(RuleActionType.RouteToSafetyPage, JsonSerializer.SerializeToElement(true)));
            actions.Add(new RuleAction(RuleActionType.RequireReview, JsonSerializer.SerializeToElement(true)));
        }

        return actions;
    }

    private static string BuildRuleName(HipAiRiskAnalysisResult analysis)
    {
        var primaryPattern = analysis.DetectedPatterns.FirstOrDefault() ?? "Risk Signal";
        return $"AI Suggested {primaryPattern} Rule";
    }

    private static string ToReason(string pattern) => pattern switch
    {
        "ShortenedUrl" => "The input contains a shortened URL pattern that can hide the final destination.",
        "ObfuscatedUrl" => "The input contains URL obfuscation often used to avoid scanning.",
        "UrgencyLanguage" => "The input contains urgency language associated with social engineering.",
        "RewardOrFinancialPromise" => "The input contains reward or financial promise wording associated with scams.",
        "CredentialRequest" => "The input asks for credential or account verification context.",
        "KnownRiskSignal" => "The input contains a known-risk signal supplied by HIP rules or services.",
        _ => "The input contains an AI-assisted risk pattern."
    };

    private static bool IsSignalTrue(IReadOnlyDictionary<string, string>? signals, string key)
    {
        return signals is not null &&
            signals.TryGetValue(key, out var value) &&
            bool.TryParse(value, out var parsed) &&
            parsed;
    }

    private static void ValidatePrivacySafeInput(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (value.Length > 500)
        {
            throw new ArgumentException($"{fieldName} must be a short privacy-safe summary or snippet.");
        }

        var lowered = value.ToLowerInvariant();
        if (lowered.Contains("password:", StringComparison.Ordinal) ||
            lowered.Contains("token=", StringComparison.Ordinal) ||
            lowered.Contains("authorization:", StringComparison.Ordinal) ||
            lowered.Contains("private chat log", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{fieldName} appears to contain private or secret content.");
        }
    }

    private static string NormalizeDomain(string domain)
    {
        return domain.Trim().TrimEnd('/').ToLowerInvariant();
    }
}
