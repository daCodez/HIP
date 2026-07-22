using HIP.Web.Security;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies production authentication configuration fails closed before an OIDC session can start.
/// </summary>
public sealed class HipProductionAuthenticationOptionsValidatorTests
{
    private readonly HipProductionAuthenticationOptionsValidator validator = new();

    [Test]
    public void Assurance_defaults_require_explicit_mfa_trust_and_recent_authentication_within_ten_minutes()
    {
        var options = new HipProductionAuthenticationOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.AcceptStandardMfaAmr, Is.False);
            Assert.That(options.TrustedMfaAcrValues, Is.Empty);
            Assert.That(options.RecentAuthenticationLifetime, Is.EqualTo(TimeSpan.FromMinutes(10)));
        });
    }

    [Test]
    public void Valid_options_succeed()
    {
        var result = validator.Validate(null, ValidOptions());

        Assert.That(result.Succeeded, Is.True);
    }

    [TestCase("")]
    [TestCase("not-a-uri")]
    [TestCase("http://identity.hip.test")]
    public void Authority_must_be_an_absolute_https_uri(string authority)
    {
        var options = ValidOptions();
        options.Authority = authority;

        var result = validator.Validate(null, options);

        Assert.That(result.Failed, Is.True);
    }

    [Test]
    public void Client_id_and_secret_are_required()
    {
        var missingClientId = ValidOptions();
        missingClientId.ClientId = "   ";
        var missingClientSecret = ValidOptions();
        missingClientSecret.ClientSecret = "\t";

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, missingClientId).Failed, Is.True);
            Assert.That(validator.Validate(null, missingClientSecret).Failed, Is.True);
        });
    }

    [Test]
    public void Role_configuration_is_explicit_and_bounded()
    {
        var missingClaimType = ValidOptions();
        missingClaimType.RoleClaimType = string.Empty;
        var missingMappings = ValidOptions();
        missingMappings.RoleMappings.Clear();
        var tooManyMappings = ValidOptions();
        tooManyMappings.RoleMappings = Enumerable.Range(0, HipProductionAuthenticationOptions.MaxRoleMappings + 1)
            .ToDictionary(index => $"external-role-{index}", _ => AdminRoles.ReadOnly, StringComparer.Ordinal);

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, missingClaimType).Failed, Is.True);
            Assert.That(validator.Validate(null, missingMappings).Failed, Is.True);
            Assert.That(validator.Validate(null, tooManyMappings).Failed, Is.True);
        });
    }

    [Test]
    public void Role_mappings_may_target_only_existing_hip_roles()
    {
        var options = ValidOptions();
        options.RoleMappings["external-superuser"] = "Superuser";

        var result = validator.Validate(null, options);

        Assert.That(result.Failed, Is.True);
    }

    [Test]
    public void Role_mapping_values_and_claim_type_have_length_limits()
    {
        var oversizedClaimType = ValidOptions();
        oversizedClaimType.RoleClaimType = new string('r', HipProductionAuthenticationOptions.MaxClaimTypeLength + 1);
        var oversizedExternalRole = ValidOptions();
        oversizedExternalRole.RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [new string('r', HipProductionAuthenticationOptions.MaxExternalRoleLength + 1)] = AdminRoles.Owner
        };

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, oversizedClaimType).Failed, Is.True);
            Assert.That(validator.Validate(null, oversizedExternalRole).Failed, Is.True);
        });
    }

    [Test]
    public void Session_lifetimes_must_stay_within_bounds_and_absolute_must_cover_idle()
    {
        var shortIdle = ValidOptions();
        shortIdle.IdleSessionLifetime = HipProductionAuthenticationOptions.MinimumIdleSessionLifetime - TimeSpan.FromTicks(1);
        var longIdle = ValidOptions();
        longIdle.IdleSessionLifetime = HipProductionAuthenticationOptions.MaximumIdleSessionLifetime + TimeSpan.FromTicks(1);
        var longAbsolute = ValidOptions();
        longAbsolute.AbsoluteSessionLifetime = HipProductionAuthenticationOptions.MaximumAbsoluteSessionLifetime + TimeSpan.FromTicks(1);
        var absoluteBeforeIdle = ValidOptions();
        absoluteBeforeIdle.IdleSessionLifetime = TimeSpan.FromHours(2);
        absoluteBeforeIdle.AbsoluteSessionLifetime = TimeSpan.FromHours(1);

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, shortIdle).Failed, Is.True);
            Assert.That(validator.Validate(null, longIdle).Failed, Is.True);
            Assert.That(validator.Validate(null, longAbsolute).Failed, Is.True);
            Assert.That(validator.Validate(null, absoluteBeforeIdle).Failed, Is.True);
        });
    }

    [Test]
    public void At_least_one_explicit_mfa_evidence_source_is_required()
    {
        var options = ValidOptions();
        options.AcceptStandardMfaAmr = false;
        options.TrustedMfaAcrValues.Clear();

        var result = validator.Validate(null, options);

        Assert.That(result.Failed, Is.True);
    }

    [Test]
    public void Trusted_mfa_acr_values_are_exact_unique_and_bounded()
    {
        var missing = ValidOptions();
        missing.TrustedMfaAcrValues = null!;
        var tooMany = ValidOptions();
        tooMany.TrustedMfaAcrValues = Enumerable
            .Range(0, HipProductionAuthenticationOptions.MaxTrustedMfaAcrValues + 1)
            .Select(index => $"urn:hip:test:mfa:{index}")
            .ToList();
        var duplicate = ValidOptions();
        duplicate.TrustedMfaAcrValues = ["urn:hip:test:mfa", "urn:hip:test:mfa"];
        var whitespace = ValidOptions();
        whitespace.TrustedMfaAcrValues = ["urn:hip:test:mfa elevated"];
        var oversized = ValidOptions();
        oversized.TrustedMfaAcrValues =
            [new string('a', HipProductionAuthenticationOptions.MaxTrustedMfaAcrValueLength + 1)];

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, missing).Failed, Is.True);
            Assert.That(validator.Validate(null, tooMany).Failed, Is.True);
            Assert.That(validator.Validate(null, duplicate).Failed, Is.True);
            Assert.That(validator.Validate(null, whitespace).Failed, Is.True);
            Assert.That(validator.Validate(null, oversized).Failed, Is.True);
        });
    }

    [Test]
    public void Recent_authentication_lifetime_has_strict_inclusive_security_bounds()
    {
        var tooShort = ValidOptions();
        tooShort.RecentAuthenticationLifetime =
            HipProductionAuthenticationOptions.MinimumRecentAuthenticationLifetime - TimeSpan.FromTicks(1);
        var tooLong = ValidOptions();
        tooLong.RecentAuthenticationLifetime =
            HipProductionAuthenticationOptions.MaximumRecentAuthenticationLifetime + TimeSpan.FromTicks(1);
        var minimum = ValidOptions();
        minimum.RecentAuthenticationLifetime = HipProductionAuthenticationOptions.MinimumRecentAuthenticationLifetime;
        var maximum = ValidOptions();
        maximum.RecentAuthenticationLifetime = HipProductionAuthenticationOptions.MaximumRecentAuthenticationLifetime;

        Assert.Multiple(() =>
        {
            Assert.That(validator.Validate(null, tooShort).Failed, Is.True);
            Assert.That(validator.Validate(null, tooLong).Failed, Is.True);
            Assert.That(validator.Validate(null, minimum).Succeeded, Is.True);
            Assert.That(validator.Validate(null, maximum).Succeeded, Is.True);
        });
    }

    private static HipProductionAuthenticationOptions ValidOptions() => new()
    {
        Authority = "https://identity.hip.test/tenant/v2.0",
        ClientId = "hip-web",
        ClientSecret = "test-secret-is-not-a-real-credential",
        RoleClaimType = "roles",
        RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hip-owner"] = AdminRoles.Owner,
            ["hip-reader"] = AdminRoles.ReadOnly
        },
        AcceptStandardMfaAmr = true,
        TrustedMfaAcrValues = ["urn:hip:test:mfa"],
        RecentAuthenticationLifetime = TimeSpan.FromMinutes(10),
        IdleSessionLifetime = TimeSpan.FromMinutes(30),
        AbsoluteSessionLifetime = TimeSpan.FromHours(8)
    };
}
