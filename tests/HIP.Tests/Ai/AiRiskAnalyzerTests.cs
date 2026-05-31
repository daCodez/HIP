using HIP.Application.Ai;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Tests.Ai;

[TestFixture]
public sealed class AiRiskAnalyzerTests
{
    [Test]
    public async Task Url_analysis_returns_risk_reasons_and_recommendation()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();

        var result = await analyzer.AnalyzeUrlRiskAsync(new HipAiUrlRiskAnalysisRequest(
            "https://bit.ly/win-now",
            "bit.ly",
            "Limited time prize claim link.",
            "Web",
            null), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.HighRisk));
            Assert.That(result.Confidence, Is.GreaterThanOrEqualTo(70));
            Assert.That(result.Reasons, Is.Not.Empty);
            Assert.That(result.RecommendedAction, Is.EqualTo("RouteToSafetyPage"));
        });
    }

    [Test]
    public async Task Content_analysis_detects_social_engineering_patterns()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();

        var result = await analyzer.AnalyzeContentRiskAsync(new HipAiContentRiskAnalysisRequest(
            "scam-prize.example",
            "SecondLife",
            "Known phishing reward wording near obfuscated URL.",
            "You won a prize. Claim it now at hxxps://prize dot com",
            null), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.Dangerous));
            Assert.That(result.RequiresReview, Is.True);
            Assert.That(result.SuggestRule, Is.True);
            Assert.That(result.DetectedPatterns, Does.Contain("ObfuscatedUrl"));
        });
    }

    [Test]
    public async Task Analyzer_is_clearly_marked_as_non_production_placeholder()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();

        var result = await analyzer.AnalyzeUrlRiskAsync(new HipAiUrlRiskAnalysisRequest(
            "https://example.com",
            "example.com",
            null,
            "Web",
            null), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsPlaceholder, Is.True);
            Assert.That(result.ProviderName, Does.Contain("Development"));
            Assert.That(result.ProviderName, Does.Contain("not production AI"));
        });
    }

    [Test]
    public void Analyzer_rejects_private_or_secret_content()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();

        var exception = Assert.ThrowsAsync<ArgumentException>(() => analyzer.AnalyzeContentRiskAsync(
            new HipAiContentRiskAnalysisRequest(
                "example.com",
                "Chat",
                "private chat log password: hunter2",
                null,
                null),
            CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("private or secret"));
    }

    [Test]
    public async Task Rule_suggestion_requires_simulation_and_watch_mode_for_high_impact()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();
        var analysis = await analyzer.AnalyzeUrlRiskAsync(new HipAiUrlRiskAnalysisRequest(
            "https://tinyurl.com/claim-login",
            "tinyurl.com",
            "Known phishing reward link asks user to verify account immediately.",
            "Web",
            new Dictionary<string, string> { ["url.hasKnownRisk"] = "true" }), CancellationToken.None);

        var suggestion = await analyzer.SuggestRuleAsync(new HipAiRuleSuggestionRequest(
            "tinyurl.com",
            "https://tinyurl.com/claim-login",
            "Web",
            analysis), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(suggestion.SimulationRequired, Is.True);
            Assert.That(suggestion.RequiresApproval, Is.True);
            Assert.That(suggestion.RecommendedMode, Is.EqualTo(RuleMode.Watch));
            Assert.That(suggestion.ProposedRule.SimulationRequired, Is.True);
            Assert.That(suggestion.ProposedRule.ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
            Assert.That(suggestion.ProposedRule.Actions.Any(action => action.Type == RuleActionType.RouteToSafetyPage), Is.True);
        });
    }

    [Test]
    public async Task Low_risk_rule_suggestion_can_be_active_but_still_requires_simulation()
    {
        var analyzer = new DevelopmentHipAiRiskAnalyzer();
        var analysis = new HipAiRiskAnalysisResult(
            RiskStatus.Caution,
            55,
            ["The input contains one weak privacy-safe risk signal."],
            ["UrgencyLanguage"],
            "ShowCaution",
            RequiresReview: false,
            SuggestRule: false,
            IsPlaceholder: true,
            DevelopmentHipAiRiskAnalyzer.ProviderName);

        var suggestion = await analyzer.SuggestRuleAsync(new HipAiRuleSuggestionRequest(
            "example.com",
            null,
            "Web",
            analysis), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(suggestion.RecommendedMode, Is.EqualTo(RuleMode.Active));
            Assert.That(suggestion.RequiresApproval, Is.False);
            Assert.That(suggestion.SimulationRequired, Is.True);
        });
    }
}
