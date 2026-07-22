using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;
using HIP.Application.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientOwnerScopeDerivationTests
{
    private const string TestKey = "service-client-owner-scope-test-key";

    [Test]
    public void Owner_scope_is_an_exact_domain_separated_lowercase_HMAC()
    {
        const string ownerId = "Tenant:Owner-A ";
        var derivation = new ServiceClientOwnerScopeDerivation(
            new PrivacyHashingOptions(TestKey, AllowDevelopmentKey: false));
        var expectedInput = "HIP\0service-client\0owner\0v1\0" + ownerId;
        var expectedDigest = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(TestKey),
            Encoding.UTF8.GetBytes(expectedInput));

        var ownerScopeId = derivation.OwnerScopeId(ownerId);

        Assert.Multiple(() =>
        {
            Assert.That(
                ownerScopeId,
                Is.EqualTo(
                    "service-client-owner-hmac-sha256-v1:" +
                    Convert.ToHexString(expectedDigest).ToLowerInvariant()));
            Assert.That(ownerScopeId, Does.Match("^service-client-owner-hmac-sha256-v1:[0-9a-f]{64}$"));
            Assert.That(derivation.OwnerScopeId(ownerId), Is.EqualTo(ownerScopeId));
            Assert.That(derivation.OwnerScopeId(ownerId.Trim()), Is.Not.EqualTo(ownerScopeId));
            Assert.That(derivation.OwnerScopeId(ownerId.ToLowerInvariant()), Is.Not.EqualTo(ownerScopeId));
        });
    }

    [Test]
    public void Production_configuration_rejects_the_built_in_development_key()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions(
                        Sha256PrivacyHashingService.DevelopmentOnlyKey,
                        AllowDevelopmentKey: false)),
                Throws.InvalidOperationException);
            Assert.That(
                () => new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions(string.Empty, AllowDevelopmentKey: false)),
                Throws.InvalidOperationException);
        });
    }

    [Test]
    public void Owner_scopes_include_current_then_unique_legacy_key_partitions()
    {
        const string currentKey = "service-client-owner-scope-current-key";
        const string legacyKey = "service-client-owner-scope-legacy-key";
        var derivation = new ServiceClientOwnerScopeDerivation(
            new PrivacyHashingOptions(
                currentKey,
                AllowDevelopmentKey: false,
                LegacyKeys: [legacyKey, currentKey, legacyKey]));

        var scopes = derivation.OwnerScopeIds("owner-from-principal");
        var currentOnly = new ServiceClientOwnerScopeDerivation(
            new PrivacyHashingOptions(currentKey, AllowDevelopmentKey: false));
        var legacyOnly = new ServiceClientOwnerScopeDerivation(
            new PrivacyHashingOptions(legacyKey, AllowDevelopmentKey: false));

        Assert.That(scopes, Is.EqualTo(new[]
        {
            currentOnly.OwnerScopeId("owner-from-principal"),
            legacyOnly.OwnerScopeId("owner-from-principal")
        }));
    }

    [Test]
    public void Owner_scope_configuration_rejects_unbounded_or_unsafe_legacy_keys()
    {
        var tooMany = Enumerable.Range(0, PrivacyHashingOptions.MaximumLegacyKeyCount + 1)
            .Select(index => $"service-client-legacy-owner-key-{index:D2}")
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                () => new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions(
                        "service-client-owner-scope-current-key",
                        AllowDevelopmentKey: false,
                        LegacyKeys: tooMany)),
                Throws.InstanceOf<InvalidOperationException>());
            Assert.That(
                () => new ServiceClientOwnerScopeDerivation(
                    new PrivacyHashingOptions(
                        "service-client-owner-scope-current-key",
                        AllowDevelopmentKey: false,
                        LegacyKeys: [Sha256PrivacyHashingService.DevelopmentOnlyKey])),
                Throws.InstanceOf<InvalidOperationException>());
        });
    }
}
