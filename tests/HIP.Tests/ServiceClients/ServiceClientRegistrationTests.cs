using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientRegistrationTests
{
    private const string ClientId = "hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ";
    private const string OwnerScopeId =
        "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string CredentialVerifier =
        "pbkdf2-sha256-v1$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string ReplacementCredentialVerifier =
        "pbkdf2-sha256-v1$600000$QQQQQQQQQQQQQQQQQQQQQQ$QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    private const string NearExpiryCredentialVerifier =
        "pbkdf2-sha256-v1$600000$gggggggggggggggggggggg$ggggggggggggggggggggggggggggggggggggggggggg";
    private static readonly DateTimeOffset CreatedAtUtc =
        new(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public void Creation_produces_a_version_one_active_registration_without_a_raw_secret_surface()
    {
        var registration = CreateRegistration();
        var domainPropertyNames = typeof(ServiceClientRegistration)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(registration.ClientId, Is.EqualTo(ClientId));
            Assert.That(registration.Status, Is.EqualTo(ServiceClientStatus.Active));
            Assert.That(registration.CredentialVersion, Is.EqualTo(1));
            Assert.That(registration.AggregateVersion, Is.EqualTo(1));
            Assert.That(registration.RevokedAtUtc, Is.Null);
            Assert.That(domainPropertyNames, Has.None.Contains("Secret"));
        });
    }

    [TestCase("client-for-example.com")]
    [TestCase("hipc_v1_short")]
    [TestCase("HIPC_V1_ABCDEFGHIJKLMNOPQRSTUQ")]
    [TestCase("hipc_v1_ABCDEFGHIJKLMNOPQRSTU+")]
    [TestCase("hipc_v1_ABCDEFGHIJKLMNOPQRSTUV")]
    public void Client_identifiers_must_use_the_exact_opaque_identifier_format(string clientId)
    {
        Assert.That(
            () => CreateRegistration(clientId: clientId),
            Throws.InstanceOf<ArgumentException>());
    }

    [TestCase("owner-scope:AAAAAAAAAAAAAAAAAAAAAA")]
    [TestCase("service-client-owner-hmac-sha256-v1:aaaaaaaa")]
    [TestCase("service-client-owner-hmac-sha256-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [TestCase(" service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Owner_scope_identifiers_require_the_exact_versioned_privacy_hash_format(string ownerScopeId)
    {
        Assert.That(
            () => ServiceClientRegistration.Create(
                ClientId,
                ownerScopeId,
                "Evidence checker",
                ServiceClientScope.DomainVerificationCheck,
                ["example.com"],
                CredentialVerifier,
                CreatedAtUtc,
                CreatedAtUtc.AddDays(90)),
            Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void Domain_grants_are_exact_and_cannot_authorize_parent_or_child_domains()
    {
        var registration = CreateRegistration(domainGrants: ["api.example.com"]);

        Assert.Multiple(() =>
        {
            Assert.That(registration.HasExactDomainGrant("api.example.com"), Is.True);
            Assert.That(registration.HasExactDomainGrant("example.com"), Is.False);
            Assert.That(registration.HasExactDomainGrant("child.api.example.com"), Is.False);
            Assert.That(registration.HasExactDomainGrant("API.EXAMPLE.COM"), Is.False);
        });
    }

    [Test]
    public void Credential_rotation_and_terminal_revocation_advance_only_the_correct_versions()
    {
        var original = CreateRegistration();
        var rotated = original.RotateCredential(
            ReplacementCredentialVerifier,
            CreatedAtUtc.AddDays(30));
        var revoked = rotated.Revoke(CreatedAtUtc.AddDays(31));

        Assert.Multiple(() =>
        {
            Assert.That(rotated.Status, Is.EqualTo(ServiceClientStatus.Active));
            Assert.That(rotated.CredentialVersion, Is.EqualTo(2));
            Assert.That(rotated.AggregateVersion, Is.EqualTo(2));
            Assert.That(rotated.ExpiresAtUtc, Is.EqualTo(original.ExpiresAtUtc));
            Assert.That(revoked.Status, Is.EqualTo(ServiceClientStatus.Revoked));
            Assert.That(revoked.CredentialVersion, Is.EqualTo(2));
            Assert.That(revoked.AggregateVersion, Is.EqualTo(3));
            Assert.That(revoked.RevokedAtUtc, Is.EqualTo(CreatedAtUtc.AddDays(31)));
            Assert.That(
                () => revoked.RotateCredential(CredentialVerifier, CreatedAtUtc.AddDays(32)),
                Throws.InvalidOperationException);
            Assert.That(() => revoked.Revoke(CreatedAtUtc.AddDays(32)), Throws.InvalidOperationException);
        });
    }

    [Test]
    public void Rotation_preserves_original_expiry_and_allows_less_than_one_day_remaining()
    {
        var original = CreateRegistration();
        var transitionAtUtc = original.ExpiresAtUtc.AddMinutes(-1);

        var rotated = original.RotateCredential(
            NearExpiryCredentialVerifier,
            transitionAtUtc);

        Assert.Multiple(() =>
        {
            Assert.That(rotated.ExpiresAtUtc, Is.EqualTo(original.ExpiresAtUtc));
            Assert.That(rotated.CredentialChangedAtUtc, Is.EqualTo(transitionAtUtc));
            Assert.That(rotated.CredentialVersion, Is.EqualTo(2));
        });
    }

    [Test]
    public void Rotation_at_or_after_original_expiry_is_rejected()
    {
        var registration = CreateRegistration();

        Assert.Multiple(() =>
        {
            Assert.That(
                () => registration.RotateCredential(CredentialVerifier, registration.ExpiresAtUtc),
                Throws.InvalidOperationException);
            Assert.That(
                () => registration.RotateCredential(CredentialVerifier, registration.ExpiresAtUtc.AddTicks(1)),
                Throws.InvalidOperationException);
        });
    }

    [Test]
    public void Rotation_rejects_an_unchanged_protected_verifier()
    {
        var registration = CreateRegistration();

        Assert.That(
            () => registration.RotateCredential(CredentialVerifier, CreatedAtUtc.AddDays(1)),
            Throws.InvalidOperationException);
    }

    [TestCase(0)]
    [TestCase(366)]
    public void Creation_rejects_expiry_outside_the_one_to_365_day_window(int lifetimeDays)
    {
        Assert.That(
            () => CreateRegistration(expiresAtUtc: CreatedAtUtc.AddDays(lifetimeDays)),
            Throws.InstanceOf<ArgumentOutOfRangeException>());
    }

    private static ServiceClientRegistration CreateRegistration(
        string clientId = ClientId,
        IReadOnlyList<string>? domainGrants = null,
        DateTimeOffset? expiresAtUtc = null) =>
        ServiceClientRegistration.Create(
            clientId,
            OwnerScopeId,
            "Evidence checker",
            ServiceClientScope.DomainVerificationCheck,
            domainGrants ?? ["example.com"],
            CredentialVerifier,
            CreatedAtUtc,
            expiresAtUtc ?? CreatedAtUtc.AddDays(90));
}
