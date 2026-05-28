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
        Assert.That(result.AllowContinue, Is.False);
    }
}
