using HIP.Application.PublicLookup;
using HIP.Domain.Risk;

namespace HIP.Tests.PublicLookup;

public sealed class PublicLookupServiceTests
{
    [Test]
    public async Task LookupDomainAsync_returns_privacy_safe_public_domain_output()
    {
        var service = new PublicDomainLookupService();

        var result = await service.LookupDomainAsync("Verified-Example.com", CancellationToken.None);

        Assert.That(result.Domain, Is.EqualTo("verified-example.com"));
        Assert.That(result.FinalHipScore, Is.InRange(0, 100));
        Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.Unknown));
        Assert.That(result.SignedIdentityStatus, Is.EqualTo("PostQuantumSignaturePresent"));
        Assert.That(result.ScoreBreakdown.Select(item => item.Category), Does.Contain("Final"));
        Assert.That(result.PublicBadgeEligible, Is.True);
        Assert.That(result.PublicLookupUrl, Is.EqualTo("/lookup/verified-example.com"));
        Assert.That(result.RecommendedAction, Is.Not.Empty);
        Assert.That(result.VerificationMethod, Is.EqualTo("WellKnownHipJsonPlaceholder"));
        Assert.That(result.Explanations.All(explanation => !string.IsNullOrWhiteSpace(explanation)), Is.True);
        Assert.That(result.Reasons.All(reason => !string.IsNullOrWhiteSpace(reason)), Is.True);
    }

    [Test]
    public async Task LookupDomainAsync_does_not_expose_private_fields()
    {
        var service = new PublicDomainLookupService();

        var result = await service.LookupDomainAsync("example.com", CancellationToken.None);
        var propertyNames = result.GetType().GetProperties().Select(property => property.Name).ToArray();

        Assert.That(propertyNames, Does.Not.Contain("PrivateChatLogs"));
        Assert.That(propertyNames, Does.Not.Contain("PrivateReports"));
        Assert.That(propertyNames, Does.Not.Contain("UserIdentities"));
        Assert.That(propertyNames, Does.Not.Contain("RawUserSubmittedEvidence"));
    }

    [Test]
    public void LookupDomainAsync_rejects_invalid_domain_input()
    {
        var service = new PublicDomainLookupService();

        Assert.ThrowsAsync<ArgumentException>(() => service.LookupDomainAsync("https://example.com/path", CancellationToken.None));
    }

    [Test]
    public async Task TrustBadgeService_always_includes_score_and_status()
    {
        var service = new TrustBadgeService(new PublicDomainLookupService());

        var result = await service.GetDomainBadgeAsync("danger-example.com", CancellationToken.None);

        Assert.That(result.Domain, Is.EqualTo("danger-example.com"));
        Assert.That(result.Score, Is.InRange(0, 100));
        Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.Unknown));
        Assert.That(result.BadgeText, Does.Contain(result.Score.ToString()));
        Assert.That(result.PublicLookupUrl, Is.EqualTo("/lookup/danger-example.com"));
        Assert.That(result.ResponseSignature, Is.Null);
    }

    [Test]
    public async Task Known_suspicious_test_domain_returns_high_risk_or_dangerous()
    {
        var service = new PublicDomainLookupService();

        var result = await service.LookupDomainAsync("danger-example.com", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(RiskStatus.Dangerous).Or.EqualTo(RiskStatus.HighRisk));
        Assert.That(result.KnownRisks, Is.Not.Empty);
        Assert.That(result.RecommendedAction, Is.EqualTo("RouteToSafetyPage").Or.EqualTo("ShowWarning"));
    }

    [Test]
    public async Task Unknown_normal_domain_returns_caution_or_safe_mvp_result()
    {
        var service = new PublicDomainLookupService();

        var result = await service.LookupDomainAsync("zerotoherobudgeting.com", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(RiskStatus.Caution).Or.EqualTo(RiskStatus.ProbablySafe).Or.EqualTo(RiskStatus.Trusted));
        Assert.That(result.Reasons, Has.Some.Contains("MVP"));
    }

    [TestCase(20, RiskStatus.Dangerous)]
    [TestCase(21, RiskStatus.HighRisk)]
    [TestCase(40, RiskStatus.HighRisk)]
    [TestCase(41, RiskStatus.Caution)]
    [TestCase(60, RiskStatus.Caution)]
    [TestCase(61, RiskStatus.ProbablySafe)]
    [TestCase(80, RiskStatus.ProbablySafe)]
    [TestCase(81, RiskStatus.Trusted)]
    public void Score_bands_map_to_statuses(int score, RiskStatus expected)
    {
        Assert.That(PublicDomainLookupService.StatusForScore(score), Is.EqualTo(expected));
    }

    [TestCase(RiskStatus.Trusted, "Allow")]
    [TestCase(RiskStatus.ProbablySafe, "Allow")]
    [TestCase(RiskStatus.Caution, "ShowCaution")]
    [TestCase(RiskStatus.HighRisk, "ShowWarning")]
    [TestCase(RiskStatus.Dangerous, "RouteToSafetyPage")]
    public void Recommended_action_maps_to_risk_status(RiskStatus status, string expected)
    {
        Assert.That(PublicDomainLookupService.RecommendedActionFor(status), Is.EqualTo(expected));
    }

    [Test]
    public void TrustBadgeService_rejects_invalid_domain_input()
    {
        var service = new TrustBadgeService(new PublicDomainLookupService());

        Assert.ThrowsAsync<ArgumentException>(() => service.GetDomainBadgeAsync("bad domain with spaces", CancellationToken.None));
    }
}
