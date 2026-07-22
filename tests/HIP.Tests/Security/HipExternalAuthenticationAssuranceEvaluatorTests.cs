using System.Globalization;
using System.Security.Claims;
using HIP.Web.Security;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies untrusted OIDC assurance evidence is reduced to bounded HIP-owned claims only.
/// </summary>
public sealed class HipExternalAuthenticationAssuranceEvaluatorTests
{
    [Test]
    public void Standard_mfa_inside_a_bounded_amr_array_and_auth_time_project_only_normalized_hip_claims()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var authenticationTime = now.AddMinutes(-5);
        var evaluator = CreateEvaluator(now);
        var principal = ExternalPrincipal(
            new Claim("amr", "pwd"),
            new Claim("amr", "mfa"),
            new Claim("amr", "otp"),
            new Claim("auth_time", authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
            new Claim(HipAuthenticationClaimTypes.MultiFactorAuthenticated, "false"),
            new Claim(HipAuthenticationClaimTypes.AuthenticationTime, now.AddDays(1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

        var claims = evaluator.Evaluate(principal).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(claims.Select(claim => claim.Type), Is.EquivalentTo(new[]
            {
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                HipAuthenticationClaimTypes.AuthenticationTime
            }));
            Assert.That(
                claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.MultiFactorAuthenticated).Value,
                Is.EqualTo("true"));
            Assert.That(
                claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.MultiFactorAuthenticated).ValueType,
                Is.EqualTo(ClaimValueTypes.Boolean));
            Assert.That(
                claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.AuthenticationTime).Value,
                Is.EqualTo(authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
            Assert.That(
                claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.AuthenticationTime).ValueType,
                Is.EqualTo(ClaimValueTypes.Integer64));
        });
    }

    [Test]
    public void Exact_trusted_acr_can_supply_mfa_when_standard_amr_is_disabled()
    {
        var options = ValidOptions();
        options.AcceptStandardMfaAmr = false;
        options.TrustedMfaAcrValues = ["urn:hip:test:mfa"];
        var evaluator = CreateEvaluator(
            new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero),
            options);

        var claims = evaluator.Evaluate(ExternalPrincipal(new Claim("acr", "urn:hip:test:mfa")));

        Assert.That(
            claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.MultiFactorAuthenticated).Value,
            Is.EqualTo("true"));
    }

    [Test]
    public void Standard_mfa_does_not_elevate_when_its_trust_switch_is_disabled()
    {
        var options = ValidOptions();
        options.AcceptStandardMfaAmr = false;
        options.TrustedMfaAcrValues = ["urn:hip:test:mfa"];
        var evaluator = CreateEvaluator(
            new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero),
            options);

        var claims = evaluator.Evaluate(ExternalPrincipal(new Claim("amr", "mfa")));

        Assert.That(claims, Is.Empty);
    }

    [Test]
    public void Missing_mfa_evidence_does_not_create_an_mfa_claim()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var evaluator = CreateEvaluator(now);

        var claims = evaluator.Evaluate(ExternalPrincipal(
            new Claim("auth_time", now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))));

        Assert.That(
            claims.Any(claim => claim.Type == HipAuthenticationClaimTypes.MultiFactorAuthenticated),
            Is.False);
    }

    [TestCase("amr", "")]
    [TestCase("amr", "not valid")]
    [TestCase("acr", "")]
    [TestCase("acr", "not valid")]
    [TestCase("auth_time", "not-a-number")]
    [TestCase("auth_time", "-1")]
    [TestCase("auth_time", "01")]
    public void Malformed_assurance_evidence_fails_closed(string claimType, string claimValue)
    {
        var evaluator = CreateEvaluator(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));

        Assert.Throws<InvalidOperationException>(() =>
            evaluator.Evaluate(ExternalPrincipal(new Claim(claimType, claimValue))));
    }

    [Test]
    public void Well_formed_non_mfa_amr_and_untrusted_acr_project_no_mfa_without_rejecting_login()
    {
        var evaluator = CreateEvaluator(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var principal = ExternalPrincipal(
            new Claim("amr", "pwd"),
            new Claim("amr", "otp"),
            new Claim("amr", "MFA"),
            new Claim("acr", "urn:hip:test:unknown"));

        var claims = evaluator.Evaluate(principal);

        Assert.That(claims, Is.Empty);
    }

    [Test]
    public void Excessive_or_oversized_amr_evidence_fails_closed()
    {
        var evaluator = CreateEvaluator(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var excessive = Enumerable
            .Range(0, HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationMethodReferences + 1)
            .Select(index => new Claim("amr", $"method-{index}"))
            .ToArray();
        var oversized = new Claim(
            "amr",
            new string('a', HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationMethodReferenceLength + 1));

        Assert.Multiple(() =>
        {
            Assert.Throws<InvalidOperationException>(() => evaluator.Evaluate(ExternalPrincipal(excessive)));
            Assert.Throws<InvalidOperationException>(() => evaluator.Evaluate(ExternalPrincipal(oversized)));
        });
    }

    [TestCase("amr", "mfa")]
    [TestCase("acr", "urn:hip:test:mfa")]
    [TestCase("auth_time", "1784462400")]
    public void Duplicate_assurance_claims_fail_closed(string claimType, string claimValue)
    {
        var evaluator = CreateEvaluator(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var principal = ExternalPrincipal(
            new Claim(claimType, claimValue),
            new Claim(claimType, claimValue));

        Assert.Throws<InvalidOperationException>(() => evaluator.Evaluate(principal));
    }

    [Test]
    public void Authentication_time_beyond_the_shared_future_skew_fails_closed()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var evaluator = CreateEvaluator(now);
        var withinSkew = now.Add(HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew);
        var beyondSkew = withinSkew.AddSeconds(1);

        var accepted = evaluator.Evaluate(ExternalPrincipal(
            new Claim("auth_time", withinSkew.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))));

        Assert.Multiple(() =>
        {
            Assert.That(accepted, Has.Count.EqualTo(1));
            Assert.Throws<InvalidOperationException>(() => evaluator.Evaluate(ExternalPrincipal(
                new Claim("auth_time", beyondSkew.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)))));
            Assert.That(
                HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew,
                Is.EqualTo(TimeSpan.FromMinutes(1)));
        });
    }

    private static HipExternalAuthenticationAssuranceEvaluator CreateEvaluator(
        DateTimeOffset now,
        HipProductionAuthenticationOptions? options = null) =>
        new(Options.Create(options ?? ValidOptions()), new FixedTimeProvider(now));

    private static ClaimsPrincipal ExternalPrincipal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, HipAuthenticationSchemes.OpenIdConnect));

    private static HipProductionAuthenticationOptions ValidOptions() => new()
    {
        Authority = "https://identity.hip.test/tenant/v2.0",
        ClientId = "hip-web",
        ClientSecret = "test-oidc-secret",
        RoleClaimType = "roles",
        RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hip-owner"] = AdminRoles.Owner
        },
        AcceptStandardMfaAmr = true,
        TrustedMfaAcrValues = ["urn:hip:test:mfa"],
        RecentAuthenticationLifetime = TimeSpan.FromMinutes(10),
        IdleSessionLifetime = TimeSpan.FromMinutes(30),
        AbsoluteSessionLifetime = TimeSpan.FromHours(8)
    };

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
