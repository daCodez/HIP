using System.Security.Claims;
using HIP.Web.Security;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies validated external identity claims are reduced to privacy-safe HIP claims.
/// </summary>
public sealed class HipExternalClaimsMapperTests
{
    [Test]
    public void Issuer_and_subject_create_matching_privacy_safe_actor_and_consumer_ids()
    {
        var mapper = CreateMapper();
        var principal = ExternalPrincipal(
            issuer: "https://identity.hip.test/tenant/v2.0",
            subject: "opaque-provider-subject-1001",
            new Claim(ClaimTypes.Email, "person@example.test"),
            new Claim(ClaimTypes.Name, "Private Display Name"));

        var claims = mapper.Map(principal);

        var actorId = claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId).Value;
        Assert.Multiple(() =>
        {
            Assert.That(actorId, Does.StartWith("hip-user:v1:"));
            Assert.That(claims.Single(claim => claim.Type == ClaimTypes.NameIdentifier).Value, Is.EqualTo(actorId));
            Assert.That(claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.ConsumerId).Value, Is.EqualTo(actorId));
            Assert.That(actorId, Does.Not.Contain("identity.hip.test"));
            Assert.That(actorId, Does.Not.Contain("opaque-provider-subject"));
            Assert.That(claims.Any(claim => claim.Value == "person@example.test"), Is.False);
            Assert.That(claims.Any(claim => claim.Value == "Private Display Name"), Is.False);
        });
    }

    [Test]
    public void Email_and_display_name_changes_do_not_change_the_hip_actor_id()
    {
        var mapper = CreateMapper();
        var first = ExternalPrincipal(
            "https://identity.hip.test/tenant/v2.0",
            "opaque-provider-subject-1001",
            new Claim(ClaimTypes.Email, "first@example.test"),
            new Claim(ClaimTypes.Name, "First Name"));
        var second = ExternalPrincipal(
            "https://identity.hip.test/tenant/v2.0",
            "opaque-provider-subject-1001",
            new Claim(ClaimTypes.Email, "renamed@example.test"),
            new Claim(ClaimTypes.Name, "Renamed Person"));

        var firstId = mapper.Map(first).Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId).Value;
        var secondId = mapper.Map(second).Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId).Value;

        Assert.That(secondId, Is.EqualTo(firstId));
    }

    [Test]
    public void Issuer_and_subject_are_both_part_of_the_stable_hip_actor_id()
    {
        var mapper = CreateMapper();

        var baseline = ActorId(mapper, ExternalPrincipal("https://identity.hip.test/tenant-a", "subject-1"));
        var differentIssuer = ActorId(mapper, ExternalPrincipal("https://identity.hip.test/tenant-b", "subject-1"));
        var differentSubject = ActorId(mapper, ExternalPrincipal("https://identity.hip.test/tenant-a", "subject-2"));

        Assert.Multiple(() =>
        {
            Assert.That(differentIssuer, Is.Not.EqualTo(baseline));
            Assert.That(differentSubject, Is.Not.EqualTo(baseline));
        });
    }

    [Test]
    public void Missing_blank_or_ambiguous_identity_claims_are_rejected()
    {
        var mapper = CreateMapper();
        var missingIssuer = Principal(new Claim(HipAuthenticationClaimTypes.Subject, "subject-1"));
        var blankSubject = Principal(
            new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test"),
            new Claim(HipAuthenticationClaimTypes.Subject, "   "));
        var duplicateSubject = Principal(
            new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test"),
            new Claim(HipAuthenticationClaimTypes.Subject, "subject-1"),
            new Claim(HipAuthenticationClaimTypes.Subject, "subject-2"));

        Assert.Multiple(() =>
        {
            Assert.That(() => mapper.Map(missingIssuer), Throws.TypeOf<InvalidOperationException>());
            Assert.That(() => mapper.Map(blankSubject), Throws.TypeOf<InvalidOperationException>());
            Assert.That(() => mapper.Map(duplicateSubject), Throws.TypeOf<InvalidOperationException>());
        });
    }

    [Test]
    public void Only_explicit_role_mappings_create_canonical_hip_roles()
    {
        var mapper = CreateMapper();
        var first = ExternalPrincipal(
            "https://identity.hip.test/tenant/v2.0",
            "subject-1",
            new Claim("roles", "unknown-role"),
            new Claim("roles", "hip-reader"),
            new Claim("roles", "hip-owner"),
            new Claim("roles", "hip-owner"),
            new Claim(ClaimTypes.Role, AdminRoles.Admin));
        var second = ExternalPrincipal(
            "https://identity.hip.test/tenant/v2.0",
            "subject-1",
            new Claim("roles", "hip-owner"),
            new Claim("roles", "hip-reader"));

        var firstRoles = mapper.Map(first).Where(claim => claim.Type == ClaimTypes.Role).Select(claim => claim.Value).ToArray();
        var secondRoles = mapper.Map(second).Where(claim => claim.Type == ClaimTypes.Role).Select(claim => claim.Value).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(firstRoles, Is.EqualTo(new[] { AdminRoles.Owner, AdminRoles.ReadOnly }));
            Assert.That(secondRoles, Is.EqualTo(firstRoles));
        });
    }

    [Test]
    public void Invalid_mapper_options_fail_before_claims_are_processed()
    {
        var options = ValidOptions();
        options.ClientSecret = string.Empty;

        Assert.That(
            () => new HipExternalClaimsMapper(Options.Create(options)),
            Throws.TypeOf<OptionsValidationException>());
    }

    [Test]
    public void Excessive_external_role_claims_are_rejected()
    {
        var mapper = CreateMapper();
        var roles = Enumerable.Range(0, HipProductionAuthenticationOptions.MaxExternalRoleClaims + 1)
            .Select(index => new Claim("roles", $"unknown-{index}"))
            .ToArray();
        var principal = ExternalPrincipal("https://identity.hip.test/tenant/v2.0", "subject-1", roles);

        Assert.That(() => mapper.Map(principal), Throws.TypeOf<InvalidOperationException>());
    }

    private static HipExternalClaimsMapper CreateMapper() =>
        new(Options.Create(ValidOptions()));

    private static HipProductionAuthenticationOptions ValidOptions() => new()
    {
        Authority = "https://identity.hip.test/tenant/v2.0",
        ClientId = "hip-web",
        ClientSecret = "test-secret-is-not-a-real-credential",
        RoleClaimType = "roles",
        RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hip-owner"] = "owner",
            ["hip-reader"] = AdminRoles.ReadOnly
        },
        AcceptStandardMfaAmr = true,
        TrustedMfaAcrValues = ["urn:hip:test:mfa"],
        RecentAuthenticationLifetime = TimeSpan.FromMinutes(10),
        IdleSessionLifetime = TimeSpan.FromMinutes(30),
        AbsoluteSessionLifetime = TimeSpan.FromHours(8)
    };

    private static ClaimsPrincipal ExternalPrincipal(string issuer, string subject, params Claim[] additionalClaims) =>
        Principal(
            new Claim(HipAuthenticationClaimTypes.Issuer, issuer),
            new Claim(HipAuthenticationClaimTypes.Subject, subject),
            additionalClaims);

    private static ClaimsPrincipal Principal(params object[] claimGroups)
    {
        var claims = claimGroups.SelectMany(group => group switch
        {
            Claim claim => [claim],
            Claim[] collection => collection,
            _ => throw new InvalidOperationException("Unsupported test claim group.")
        });

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestOidc"));
    }

    private static string ActorId(HipExternalClaimsMapper mapper, ClaimsPrincipal principal) =>
        mapper.Map(principal).Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId).Value;
}
