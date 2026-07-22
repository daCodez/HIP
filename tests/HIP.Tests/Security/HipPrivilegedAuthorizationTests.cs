using System.Globalization;
using System.Security.Claims;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies HIP's privileged MFA and recent-authentication authorization requirements.
/// </summary>
public sealed class HipPrivilegedAuthorizationTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 18, 30, 0, TimeSpan.Zero);

    private static readonly string[] ExistingAdminPolicies =
    [
        AdminPolicies.CanManageRules,
        AdminPolicies.CanReviewReports,
        AdminPolicies.CanApproveOverrides,
        AdminPolicies.CanViewAuditLogs,
        AdminPolicies.CanManageLicenses,
        AdminPolicies.CanManagePlatforms,
        AdminPolicies.CanViewAdminDashboard,
        AdminPolicies.CanManageDomainVerifications,
        AdminPolicies.CanRevokeDomainVerifications
    ];

    [TestCaseSource(nameof(ExistingAdminPolicies))]
    public async Task Every_existing_admin_policy_requires_privileged_mfa(string policyName)
    {
        using var provider = Services(Environments.Production);
        var policies = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policies.GetPolicyAsync(policyName);

        Assert.That(policy, Is.Not.Null);
        Assert.That(
            policy!.Requirements.Count(requirement => requirement is PrivilegedMfaRequirement),
            Is.EqualTo(1));
    }

    [TestCase(AdminRoles.Owner)]
    [TestCase(AdminRoles.Admin)]
    public async Task Privileged_role_with_HIP_MFA_can_use_an_allowed_admin_policy(string role)
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(role, mfa: true),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.True);
    }

    [TestCase(AdminRoles.Owner)]
    [TestCase(AdminRoles.Admin)]
    public async Task Privileged_role_without_HIP_MFA_fails_closed(string role)
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(role, additionalClaims: [new Claim("amr", "mfa")]),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task Staging_privileged_role_without_HIP_MFA_fails_closed()
    {
        using var provider = Services(Environments.Staging);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Owner),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.False);
    }

    [TestCase("false", ClaimValueTypes.Boolean)]
    [TestCase("TRUE", ClaimValueTypes.Boolean)]
    [TestCase("true", ClaimValueTypes.String)]
    public async Task Noncanonical_HIP_MFA_evidence_fails_closed(string value, string valueType)
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var evidence = new Claim(HipAuthenticationClaimTypes.MultiFactorAuthenticated, value, valueType);

        var result = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Owner, additionalClaims: [evidence]),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task Duplicate_HIP_MFA_evidence_fails_closed()
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var evidence = new Claim(
            HipAuthenticationClaimTypes.MultiFactorAuthenticated,
            "true",
            ClaimValueTypes.Boolean);

        var result = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Owner, additionalClaims: [evidence, evidence]),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.False);
    }

    [TestCase(AdminRoles.Moderator, AdminPolicies.CanReviewReports)]
    [TestCase(AdminRoles.Support, AdminPolicies.CanManageLicenses)]
    [TestCase(AdminRoles.ReadOnly, AdminPolicies.CanViewAuditLogs)]
    public async Task Nonprivileged_roles_retain_their_existing_admin_access_without_MFA(
        string role,
        string policyName)
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(role),
            resource: null,
            policyName);

        Assert.That(result.Succeeded, Is.True);
    }

    [TestCase(AdminRoles.Owner)]
    [TestCase(AdminRoles.Admin)]
    public async Task Recent_privileged_policy_accepts_MFA_at_the_exact_age_boundary(string role)
    {
        using var provider = Services(Environments.Production);
        var options = provider.GetRequiredService<IOptions<HipProductionAuthenticationOptions>>().Value;
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(role, mfa: true, authenticationTime: Now - options.RecentAuthenticationLifetime),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task Recent_privileged_policy_rejects_stale_authentication_beyond_the_exact_boundary()
    {
        using var provider = Services(Environments.Production);
        var options = provider.GetRequiredService<IOptions<HipProductionAuthenticationOptions>>().Value;
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(
                AdminRoles.Owner,
                mfa: true,
                authenticationTime: Now - options.RecentAuthenticationLifetime - TimeSpan.FromSeconds(1)),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task Recent_privileged_policy_accepts_authentication_at_the_exact_future_skew_boundary()
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(
                AdminRoles.Admin,
                mfa: true,
                authenticationTime: Now + HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task Recent_privileged_policy_rejects_authentication_beyond_the_future_skew_boundary()
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(
                AdminRoles.Admin,
                mfa: true,
                authenticationTime: Now + HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew + TimeSpan.FromSeconds(1)),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task Recent_privileged_policy_rejects_missing_or_malformed_authentication_time()
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var malformed = new Claim(
            HipAuthenticationClaimTypes.AuthenticationTime,
            "not-a-time",
            ClaimValueTypes.Integer64);

        var missingResult = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Owner, mfa: true),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);
        var malformedResult = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Owner, mfa: true, additionalClaims: [malformed]),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.Multiple(() =>
        {
            Assert.That(missingResult.Succeeded, Is.False);
            Assert.That(malformedResult.Succeeded, Is.False);
        });
    }

    [Test]
    public async Task Recent_privileged_policy_rejects_duplicate_authentication_time()
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var authenticationTime = AuthenticationTimeClaim(Now);

        var result = await authorization.AuthorizeAsync(
            Principal(
                AdminRoles.Owner,
                mfa: true,
                additionalClaims: [authenticationTime, authenticationTime]),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.False);
    }

    [TestCase(AdminRoles.Moderator)]
    [TestCase(AdminRoles.Support)]
    [TestCase(AdminRoles.ReadOnly)]
    public async Task Recent_privileged_policy_rejects_lower_roles(string role)
    {
        using var provider = Services(Environments.Production);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(role, mfa: true, authenticationTime: Now),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.That(result.Succeeded, Is.False);
    }

    [TestCase(AdminRoles.Owner)]
    [TestCase(AdminRoles.Admin)]
    public async Task Development_preserves_privileged_access_without_external_MFA_evidence(string role)
    {
        using var provider = Services(Environments.Development);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var standardResult = await authorization.AuthorizeAsync(
            Principal(role),
            resource: null,
            AdminPolicies.CanManageRules);
        var recentResult = await authorization.AuthorizeAsync(
            Principal(role),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.Multiple(() =>
        {
            Assert.That(standardResult.Succeeded, Is.True);
            Assert.That(recentResult.Succeeded, Is.True);
        });
    }

    [Test]
    public async Task Development_MFA_exemption_does_not_bypass_role_authorization()
    {
        using var provider = Services(Environments.Development);
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            Principal(AdminRoles.Support),
            resource: null,
            AdminPolicies.CanManageRules);

        Assert.That(result.Succeeded, Is.False);
    }

    private static ServiceProvider Services(string environmentName)
    {
        var options = new HipProductionAuthenticationOptions
        {
            Authority = "https://identity.hip.test/tenant/v2.0",
            ClientId = "hip-web",
            ClientSecret = "test-only-secret",
            RoleClaimType = "roles",
            RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["hip-owner"] = AdminRoles.Owner
            },
            AcceptStandardMfaAmr = true,
            IdleSessionLifetime = TimeSpan.FromMinutes(30),
            AbsoluteSessionLifetime = TimeSpan.FromHours(8),
            RecentAuthenticationLifetime = TimeSpan.FromMinutes(10)
        };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(environmentName));
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
        services.AddSingleton<IOptions<HipProductionAuthenticationOptions>>(Options.Create(options));
        services.AddHipAdminAuthorization();
        return services.BuildServiceProvider();
    }

    private static ClaimsPrincipal Principal(
        string role,
        bool mfa = false,
        DateTimeOffset? authenticationTime = null,
        IEnumerable<Claim>? additionalClaims = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "hip-user:v1:test"),
            new(HipAuthenticationClaimTypes.ActorId, "hip-user:v1:test"),
            new(ClaimTypes.Role, role)
        };
        if (mfa)
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                "true",
                ClaimValueTypes.Boolean));
        }

        if (authenticationTime is not null)
        {
            claims.Add(AuthenticationTimeClaim(authenticationTime.Value));
        }

        if (additionalClaims is not null)
        {
            claims.AddRange(additionalClaims);
        }

        return new ClaimsPrincipal(new ClaimsIdentity(
            claims,
            authenticationType: "HIP.Test",
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role));
    }

    private static Claim AuthenticationTimeClaim(DateTimeOffset authenticationTime) =>
        new(
            HipAuthenticationClaimTypes.AuthenticationTime,
            authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "HIP.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
