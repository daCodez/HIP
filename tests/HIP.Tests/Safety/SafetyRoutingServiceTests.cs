using HIP.Application.Safety;
using HIP.Domain.Risk;

namespace HIP.Tests.Safety;

public sealed class SafetyRoutingServiceTests
{
    [Test]
    public void CreateUrlSafetyResult_routes_high_risk_urls_to_safety_page()
    {
        var result = new SafetyRoutingService().CreateUrlSafetyResult(
            "https://short.example/login",
            "https://new-danger.example/login",
            35,
            50,
            ["This link is risky because it uses a shortener and redirects to a new domain."]);

        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.HighRisk));
        Assert.That(result.ShouldRouteToSafetyPage, Is.True);
        Assert.That(result.AllowContinue, Is.True);
        Assert.That(result.RecommendedAction, Is.EqualTo("RouteToSafetyPage"));
        Assert.That(result.CanReportAsSafe, Is.True);
        Assert.That(result.CanReportAsDangerous, Is.True);
    }

    [Test]
    public void CreateUrlSafetyResult_blocks_continue_for_dangerous_urls()
    {
        var result = new SafetyRoutingService().CreateUrlSafetyResult(
            "https://danger.example/download",
            null,
            12,
            null,
            ["The destination has confirmed dangerous public risk signals."]);

        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.Dangerous));
        Assert.That(result.ShouldRouteToSafetyPage, Is.True);
        Assert.That(result.AllowContinue, Is.True);
    }

    [Test]
    public void EvaluateUrl_rejects_invalid_url()
    {
        Assert.Throws<ArgumentException>(() => new SafetyRoutingService().EvaluateUrl("javascript:alert(1)", "browser"));
    }

    [Test]
    public void EvaluateUrl_marks_shortened_url_as_suspicious()
    {
        var result = new SafetyRoutingService().EvaluateUrl("https://bit.ly/example", "browser");

        Assert.That(SafetyRoutingService.DisplayRiskLevel(result.RiskLevel), Is.EqualTo("Suspicious"));
        Assert.That(result.ShouldRouteToSafetyPage, Is.True);
        Assert.That(result.AllowContinue, Is.True);
    }

    [Test]
    public void EvaluateUrl_blocks_continue_for_critical_risk()
    {
        var result = new SafetyRoutingService().EvaluateUrl("https://critical-example.com/pay", "sl-hud");

        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.Critical));
        Assert.That(result.AllowContinue, Is.False);
        Assert.That(result.RecommendedAction, Is.EqualTo("Block"));
    }

    [Test]
    public void Safety_evaluation_does_not_require_private_data()
    {
        var method = typeof(ISafetyRoutingService).GetMethod(nameof(ISafetyRoutingService.EvaluateUrl))!;
        var parameterNames = method.GetParameters().Select(parameter => parameter.Name).ToArray();

        Assert.That(parameterNames, Is.EquivalentTo(new[] { "url", "source" }));
        Assert.That(parameterNames, Does.Not.Contain("chatLog"));
        Assert.That(parameterNames, Does.Not.Contain("formContents"));
        Assert.That(parameterNames, Does.Not.Contain("privateMessage"));
    }
}
