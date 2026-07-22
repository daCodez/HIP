using HIP.Application.SiteSafety;

namespace HIP.Tests.SiteSafety;

/// <summary>Locks the HIP-0304 provider-neutral result contract and untrusted-result validation.</summary>
public sealed class SiteSafetyProviderResultContractTests
{
    private static readonly DateTimeOffset CheckedAtUtc =
        new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void Successful_provider_result_normalizes_status_latency_freshness_and_privacy()
    {
        var context = Context();
        var result = SiteSafetyProviderResultContract.Normalize(
            Evidence(),
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            context,
            TimeSpan.FromMilliseconds(125),
            CheckedAtUtc.AddMinutes(1));

        Assert.Multiple(() =>
        {
            Assert.That(result.ResultStatus, Is.EqualTo(SiteSafetyProviderResultStatus.Succeeded));
            Assert.That(result.LatencyMilliseconds, Is.EqualTo(125));
            Assert.That(result.Freshness, Is.EqualTo(SiteSafetyProviderFreshness.Fresh));
            Assert.That(result.PrivacyClassification, Is.EqualTo(SiteSafetyProviderPrivacyClassification.HashedUrlMetadata));
            Assert.That(result.EvidenceItems, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public void Provider_result_distinguishes_partial_stale_and_expired_evidence()
    {
        var context = Context();
        var partial = SiteSafetyProviderResultContract.Normalize(
            Evidence() with { Errors = ["One provider signal was unavailable."] },
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            context,
            TimeSpan.FromMilliseconds(15),
            CheckedAtUtc.AddMinutes(1));
        var stale = SiteSafetyProviderResultContract.Normalize(
            Evidence() with
            {
                CheckedAtUtc = CheckedAtUtc.AddHours(-2),
                ExpiresAtUtc = CheckedAtUtc.AddHours(1)
            },
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            context,
            TimeSpan.Zero,
            CheckedAtUtc);
        var expired = SiteSafetyProviderResultContract.Normalize(
            Evidence() with { ExpiresAtUtc = CheckedAtUtc.AddSeconds(30) },
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            context,
            TimeSpan.Zero,
            CheckedAtUtc.AddMinutes(1));

        Assert.Multiple(() =>
        {
            Assert.That(partial.ResultStatus, Is.EqualTo(SiteSafetyProviderResultStatus.Partial));
            Assert.That(stale.Freshness, Is.EqualTo(SiteSafetyProviderFreshness.Stale));
            Assert.That(expired.Freshness, Is.EqualTo(SiteSafetyProviderFreshness.Expired));
        });
    }

    [Test]
    public void Timeout_is_a_safe_non_authoritative_provider_result()
    {
        var result = SiteSafetyProviderResultContract.CreateFailure(
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            Context(),
            SiteSafetyProviderResultStatus.TimedOut,
            TimeSpan.FromMilliseconds(250),
            CheckedAtUtc.AddSeconds(1),
            "Provider timed out.");

        Assert.Multiple(() =>
        {
            Assert.That(result.ResultStatus, Is.EqualTo(SiteSafetyProviderResultStatus.TimedOut));
            Assert.That(result.LatencyMilliseconds, Is.EqualTo(250));
            Assert.That(result.Confidence, Is.Zero);
            Assert.That(result.EvidenceItems, Is.Empty);
            Assert.That(result.Errors, Is.EqualTo(new[] { "Provider timed out." }));
            Assert.That(result.IsAuthoritativeForRisk, Is.False);
            Assert.That(result.IsAuthoritativeForTrust, Is.False);
        });
    }

    [Test]
    public void Failed_provider_result_cannot_retain_authority_flags()
    {
        var result = Normalize(Evidence() with
        {
            EvidenceItems = [],
            Errors = ["Provider returned no usable evidence."],
            IsAuthoritativeForRisk = true,
            IsAuthoritativeForTrust = true
        }, Context());

        Assert.Multiple(() =>
        {
            Assert.That(result.ResultStatus, Is.EqualTo(SiteSafetyProviderResultStatus.Failed));
            Assert.That(result.IsAuthoritativeForRisk, Is.False);
            Assert.That(result.IsAuthoritativeForTrust, Is.False);
        });
    }

    [Test]
    public void Mismatched_or_unbounded_provider_results_are_rejected_before_scoring()
    {
        var context = Context();
        var tooManyItems = Enumerable.Range(0, SiteSafetyProviderResultContract.MaximumEvidenceItems + 1)
            .Select(index => Item() with { Category = $"Signal{index}" })
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(() => Normalize(Evidence() with { ProviderName = "SpoofedProvider" }, context), Throws.ArgumentException);
            Assert.That(() => Normalize(Evidence() with { Domain = "other.example" }, context), Throws.ArgumentException);
            Assert.That(() => Normalize(Evidence() with { UrlHash = new string('0', 64) }, context), Throws.ArgumentException);
            Assert.That(() => Normalize(Evidence() with { UrlHash = null }, context), Throws.ArgumentException);
            Assert.That(() => Normalize(Evidence() with { Confidence = 101 }, context), Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => Normalize(Evidence() with { EvidenceItems = tooManyItems }, context), Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => Normalize(Evidence() with { ExpiresAtUtc = CheckedAtUtc }, context), Throws.ArgumentException);
        });
    }

    private static SiteSafetyEvidence Normalize(SiteSafetyEvidence evidence, SiteSafetyEvidenceContext context) =>
        SiteSafetyProviderResultContract.Normalize(
            evidence,
            "TestProvider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            context,
            TimeSpan.Zero,
            CheckedAtUtc.AddMinutes(1));

    private static SiteSafetyEvidenceContext Context() => new(
        new Uri("https://provider.example/path"),
        "provider.example",
        new string('a', 64),
        new SiteSafetyObservedSignals(),
        CheckedAtUtc);

    private static SiteSafetyEvidence Evidence() => new(
        "TestProvider",
        SiteSafetyEvidenceProviderType.ThreatIntel,
        SiteSafetyEvidenceTargetType.Url,
        "provider.example",
        new string('a', 64),
        [Item()],
        Confidence: 90,
        CheckedAtUtc,
        CheckedAtUtc.AddHours(1),
        [],
        IsAuthoritativeForRisk: true,
        IsAuthoritativeForTrust: false);

    private static SiteSafetyEvidenceItem Item() => new(
        "ThreatMatch",
        "Hit",
        SiteSafetyEvidenceStatus.Dangerous,
        RiskImpact: 95,
        TrustImpact: 0,
        "Provider-neutral threat match.",
        EvidenceType: "ThreatMatch",
        Confidence: 90,
        Severity: SiteSafetyEvidenceSeverity.Critical,
        EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
        SourceReference: "test-provider",
        IsNegativeSignal: true,
        IsBlockingSignal: true);
}
