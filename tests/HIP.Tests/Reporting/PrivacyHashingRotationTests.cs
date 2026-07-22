using HIP.Application.Reporting;

namespace HIP.Tests.Reporting;

/// <summary>
/// Verifies planned privacy-HMAC rotation remains bounded and backward compatible.
/// </summary>
public sealed class PrivacyHashingRotationTests
{
    [Test]
    public void Candidate_hashes_are_current_first_and_deduplicate_repeated_keys()
    {
        const string currentKey = "privacy-hash-current-key-material";
        const string legacyKey = "privacy-hash-legacy-key-material";
        var service = new Sha256PrivacyHashingService(new PrivacyHashingOptions(
            currentKey,
            AllowDevelopmentKey: false,
            LegacyKeys: [legacyKey, currentKey, legacyKey]));
        var currentOnly = new Sha256PrivacyHashingService(new PrivacyHashingOptions(
            currentKey,
            AllowDevelopmentKey: false));
        var legacyOnly = new Sha256PrivacyHashingService(new PrivacyHashingOptions(
            legacyKey,
            AllowDevelopmentKey: false));

        var candidates = service.HashCandidates(" Consumer-A ");

        Assert.That(candidates, Is.EqualTo(new[]
        {
            currentOnly.Hash(" Consumer-A "),
            legacyOnly.Hash(" Consumer-A ")
        }));
    }

    [Test]
    public void Current_only_hashing_implementations_keep_the_default_single_candidate_contract()
    {
        IPrivacyHashingService service = new CurrentOnlyHashingService();

        var candidates = service.HashCandidates("consumer-A");

        Assert.That(candidates, Is.EqualTo(new[] { "current:consumer-A" }));
    }

    [Test]
    public void Candidate_hashing_rejects_unbounded_or_unsafe_legacy_keys()
    {
        var tooMany = Enumerable.Range(0, PrivacyHashingOptions.MaximumLegacyKeyCount + 1)
            .Select(index => $"privacy-hash-legacy-key-{index:D2}-material")
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                () => new Sha256PrivacyHashingService(new PrivacyHashingOptions(
                    "privacy-hash-current-key-material",
                    AllowDevelopmentKey: false,
                    LegacyKeys: tooMany)),
                Throws.InstanceOf<InvalidOperationException>());
            Assert.That(
                () => new Sha256PrivacyHashingService(new PrivacyHashingOptions(
                    "privacy-hash-current-key-material",
                    AllowDevelopmentKey: false,
                    LegacyKeys: [Sha256PrivacyHashingService.DevelopmentOnlyKey])),
                Throws.InstanceOf<InvalidOperationException>());
        });
    }

    private sealed class CurrentOnlyHashingService : IPrivacyHashingService
    {
        public string Hash(string value) => $"current:{value}";
    }
}
