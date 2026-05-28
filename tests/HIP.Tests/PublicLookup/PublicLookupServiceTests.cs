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
        Assert.That(result.Explanations.All(explanation => !string.IsNullOrWhiteSpace(explanation)), Is.True);
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
        Assert.That(result.PublicLookupUrl, Does.Contain("/api/public/lookup/domain/danger-example.com"));
    }
}
