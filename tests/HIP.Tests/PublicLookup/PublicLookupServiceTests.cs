using HIP.Application.Browser;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Domain.Risk;

namespace HIP.Tests.PublicLookup;

public sealed class PublicLookupServiceTests
{
    [Test]
    public async Task LookupDomainAsync_returns_privacy_safe_public_domain_output()
    {
        var service = await CreateServiceWithStoredScanAsync("Verified-Example.com");

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
        Assert.That(result.DataSource, Is.EqualTo("BrowserPluginScan"));
    }

    [Test]
    public async Task LookupDomainAsync_does_not_expose_private_fields()
    {
        var service = await CreateServiceWithStoredScanAsync("example.com");

        var result = await service.LookupDomainAsync("example.com", CancellationToken.None);
        var propertyNames = result.GetType().GetProperties().Select(property => property.Name).ToArray();

        Assert.That(propertyNames, Does.Not.Contain("PrivateChatLogs"));
        Assert.That(propertyNames, Does.Not.Contain("PrivateReports"));
        Assert.That(propertyNames, Does.Not.Contain("UserIdentities"));
        Assert.That(propertyNames, Does.Not.Contain("RawUserSubmittedEvidence"));
        Assert.That(propertyNames, Does.Not.Contain("PageUrl"));
        Assert.That(propertyNames, Does.Not.Contain("PageUrlHash"));
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
        var lookupService = await CreateServiceWithStoredScanAsync("danger-example.com", 18, "Dangerous");
        var service = new TrustBadgeService(lookupService);

        var result = await service.GetDomainBadgeAsync("danger-example.com", CancellationToken.None);

        Assert.That(result.Domain, Is.EqualTo("danger-example.com"));
        Assert.That(result.Score, Is.InRange(0, 100));
        Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.Unknown));
        Assert.That(result.BadgeText, Does.Contain(result.Score.ToString()));
        Assert.That(result.PublicLookupUrl, Is.EqualTo("/lookup/danger-example.com"));
        Assert.That(result.ResponseSignature, Is.Null);
    }

    [Test]
    public async Task Lookup_uses_stored_scan_result_when_available()
    {
        var service = await CreateServiceWithStoredScanAsync("danger-example.com", 18, "Dangerous");

        var result = await service.LookupDomainAsync("danger-example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(RiskStatus.Dangerous));
            Assert.That(result.Score, Is.EqualTo(18));
            Assert.That(result.DataSource, Is.EqualTo("BrowserPluginScan"));
            Assert.That(result.RecommendedAction, Is.EqualTo("RouteToSafetyPage"));
        });
    }

    [Test]
    public async Task Lookup_returns_unknown_when_no_stored_data_exists()
    {
        var service = new PublicDomainLookupService();

        var result = await service.LookupDomainAsync("zerotoherobudgeting.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(RiskStatus.Unknown));
            Assert.That(result.DataSource, Is.EqualTo("NoStoredData"));
            Assert.That(result.Reasons, Has.Some.Contains("HIP has not scanned this domain yet"));
            Assert.That(result.RecommendedAction, Is.EqualTo("ShowCaution"));
        });
    }

    [Test]
    public async Task Lookup_shows_last_checked_date_and_scan_counts_from_stored_scan()
    {
        var service = await CreateServiceWithStoredScanAsync("example.com");

        var result = await service.LookupDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.LastCheckedUtc, Is.Not.EqualTo(default(DateTimeOffset)));
            Assert.That(result.LinksScanned, Is.EqualTo(42));
            Assert.That(result.RiskyLinksFound, Is.EqualTo(2));
            Assert.That(result.SuspiciousLinksFound, Is.EqualTo(2));
            Assert.That(result.DangerousLinksFound, Is.EqualTo(0));
        });
    }

    [Test]
    public async Task Lookup_response_includes_data_source()
    {
        var service = await CreateServiceWithStoredScanAsync("example.com");

        var result = await service.LookupDomainAsync("example.com", CancellationToken.None);

        Assert.That(result.DataSource, Is.EqualTo("BrowserPluginScan"));
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

    /// <summary>
    /// Creates a public lookup service backed by an in-memory stored browser scan result.
    /// </summary>
    /// <param name="domain">Domain to seed.</param>
    /// <param name="score">Stored HIP score.</param>
    /// <param name="status">Stored risk status.</param>
    /// <returns>A lookup service that will return stored scan data for the domain.</returns>
    private static async Task<PublicDomainLookupService> CreateServiceWithStoredScanAsync(string domain, int score = 84, string status = "Trusted")
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var scanResultService = new BrowserScanResultService(repository, new Sha256PrivacyHashingService());
        await scanResultService.SaveAsync(new BrowserScanResultSaveRequest(
            domain,
            $"https://{domain.ToLowerInvariant()}/page?token=secret",
            score,
            status,
            status,
            ["Last browser scan found no dangerous links"],
            42,
            2,
            2,
            0,
            status is "Dangerous" or "Critical" ? "RouteToSafetyPage" : "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal"
            }), CancellationToken.None);

        return new PublicDomainLookupService(repository);
    }
}
