using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using HIP.Application.Reporting;
using HIP.Application.SecondLife;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace HIP.Tests.Security;

/// <summary>
/// Exercises every HIP named authorization policy against the complete human-principal matrix.
/// </summary>
public sealed class AuthorizationPolicyPrincipalMatrixTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

    private static readonly PrincipalKind[] AllPrincipalKinds = Enum.GetValues<PrincipalKind>();

    private static readonly PolicyExpectation[] AdminPolicyExpectations =
    [
        Admin(AdminPolicies.CanManageRules, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(
            AdminPolicies.CanReviewReports,
            compatibilityPolicy: true,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator),
        Admin(
            AdminPolicies.CanViewReviews,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator,
            PrincipalKind.Support,
            PrincipalKind.ReadOnly),
        Admin(
            AdminPolicies.CanDecideReviews,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator),
        Admin(
            AdminPolicies.CanViewAppeals,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator,
            PrincipalKind.ReadOnly),
        Admin(
            AdminPolicies.CanDecideAppeals,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator),
        Admin(AdminPolicies.CanApproveOverrides, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.CanManageReputation, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(
            AdminPolicies.CanViewAuditLogs,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.ReadOnly),
        Admin(
            AdminPolicies.CanManageLicenses,
            compatibilityPolicy: true,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Support),
        Admin(
            AdminPolicies.CanViewLicenses,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Support,
            PrincipalKind.ReadOnly),
        Admin(
            AdminPolicies.CanSupportLicenses,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Support),
        Admin(AdminPolicies.CanAdministerLicenses, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.CanManagePlatforms, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.CanViewServiceClients, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.CanManageServiceClients, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(
            AdminPolicies.CanViewAdminDashboard,
            PrincipalKind.Owner,
            PrincipalKind.Admin,
            PrincipalKind.Moderator,
            PrincipalKind.Support,
            PrincipalKind.ReadOnly),
        Admin(AdminPolicies.CanManageDomainVerifications, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.CanRevokeDomainVerifications, PrincipalKind.Owner),
        Admin(AdminPolicies.CanRequestPrivilegedStepUp, PrincipalKind.Owner, PrincipalKind.Admin),
        Admin(AdminPolicies.RecentPrivilegedAuthentication, PrincipalKind.Owner, PrincipalKind.Admin)
    ];

    private static readonly PolicyExpectation[] AllPolicyExpectations =
    [
        .. AdminPolicyExpectations,
        new(
            ConsumerPolicies.CanUseConsumerPortal,
            Allowed(PrincipalKind.Consumer),
            IsCompatibilityPolicy: false,
            PolicyResource.None),
        new(
            HudPolicies.CanUseActiveDevice,
            Allowed(AllPrincipalKinds),
            IsCompatibilityPolicy: false,
            PolicyResource.ActiveHudDevice)
    ];

    [Test]
    public async Task Matrix_covers_every_registered_named_policy_and_marks_compatibility_policies()
    {
        using var provider = Services();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();
        var declaredAdminPolicies = typeof(AdminPolicies)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                AdminPolicyExpectations.Select(expectation => expectation.PolicyName),
                Is.EquivalentTo(declaredAdminPolicies));
            Assert.That(
                AdminPolicyExpectations
                    .Where(expectation => expectation.IsCompatibilityPolicy)
                    .Select(expectation => expectation.PolicyName),
                Is.EquivalentTo(new[]
                {
                    AdminPolicies.CanReviewReports,
                    AdminPolicies.CanManageLicenses
                }));
            Assert.That(
                AllPolicyExpectations.Select(expectation => expectation.PolicyName),
                Is.Unique);
        });

        foreach (var expectation in AllPolicyExpectations)
        {
            Assert.That(
                await policyProvider.GetPolicyAsync(expectation.PolicyName),
                Is.Not.Null,
                $"{expectation.PolicyName} must be registered through AddHipAdminAuthorization.");
        }
    }

    [Test]
    public async Task Every_named_policy_enforces_the_exact_eight_principal_matrix()
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var activeHudBinding = CreateActiveHudBinding(scope.ServiceProvider);

        foreach (var expectation in AllPolicyExpectations)
        {
            foreach (var principalKind in AllPrincipalKinds)
            {
                var resource = expectation.Resource switch
                {
                    PolicyResource.ActiveHudDevice => ActiveHudContext(scope.ServiceProvider, activeHudBinding),
                    _ => null
                };
                var result = await authorization.AuthorizeAsync(
                    Principal(principalKind),
                    resource,
                    expectation.PolicyName);
                var expected = expectation.AllowedPrincipals.Contains(principalKind);

                Assert.That(
                    result.Succeeded,
                    Is.EqualTo(expected),
                    $"{expectation.PolicyName} returned an unexpected result for {principalKind}.");
            }
        }
    }

    [TestCase(ActorClaimState.Missing)]
    [TestCase(ActorClaimState.Blank)]
    [TestCase(ActorClaimState.Duplicate)]
    public async Task Every_admin_policy_rejects_a_missing_blank_or_ambiguous_actor(
        ActorClaimState actorClaimState)
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();

        foreach (var expectation in AdminPolicyExpectations)
        {
            var result = await authorization.AuthorizeAsync(
                Principal(PrincipalKind.Owner, actorClaimState),
                resource: null,
                expectation.PolicyName);

            Assert.That(
                result.Succeeded,
                Is.False,
                $"{expectation.PolicyName} accepted {actorClaimState} {HipAuthenticationClaimTypes.ActorId} evidence.");
        }
    }

    [Test]
    public async Task Admin_policy_MFA_requirements_preserve_the_pre_MFA_step_up_entry_policy()
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var policyProvider = scope.ServiceProvider.GetRequiredService<IAuthorizationPolicyProvider>();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();

        foreach (var expectation in AdminPolicyExpectations)
        {
            var policy = await policyProvider.GetPolicyAsync(expectation.PolicyName);
            var isStepUpEntryPolicy = expectation.PolicyName == AdminPolicies.CanRequestPrivilegedStepUp;

            Assert.That(policy, Is.Not.Null);
            Assert.That(
                policy!.Requirements.Count(requirement => requirement is PrivilegedMfaRequirement),
                Is.EqualTo(isStepUpEntryPolicy ? 0 : 1),
                expectation.PolicyName);
            Assert.That(
                policy.Requirements.Count(requirement =>
                    requirement is UniqueHipIdentityClaimRequirement unique &&
                    unique.ClaimType == HipAuthenticationClaimTypes.ActorId),
                Is.EqualTo(1),
                expectation.PolicyName);
            Assert.That(
                policy.Requirements.Count(requirement => requirement is RecentPrivilegedMfaRequirement),
                Is.EqualTo(expectation.PolicyName == AdminPolicies.RecentPrivilegedAuthentication ? 1 : 0),
                expectation.PolicyName);

            var withoutMfa = await authorization.AuthorizeAsync(
                Principal(PrincipalKind.Owner, includePrivilegedMfa: false),
                resource: null,
                expectation.PolicyName);
            Assert.That(
                withoutMfa.Succeeded,
                Is.EqualTo(isStepUpEntryPolicy),
                expectation.PolicyName);
        }
    }

    [TestCase(PrincipalKind.Owner)]
    [TestCase(PrincipalKind.Admin)]
    public async Task Recent_privileged_policy_requires_fresh_MFA_backed_authentication(
        PrincipalKind principalKind)
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var configuredLifetime = scope.ServiceProvider
            .GetRequiredService<IOptions<HipProductionAuthenticationOptions>>()
            .Value
            .RecentAuthenticationLifetime;

        var fresh = await authorization.AuthorizeAsync(
            Principal(principalKind, authenticationTime: Now - configuredLifetime),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);
        var stale = await authorization.AuthorizeAsync(
            Principal(principalKind, authenticationTime: Now - configuredLifetime - TimeSpan.FromSeconds(1)),
            resource: null,
            AdminPolicies.RecentPrivilegedAuthentication);

        Assert.Multiple(() =>
        {
            Assert.That(fresh.Succeeded, Is.True);
            Assert.That(stale.Succeeded, Is.False);
        });
    }

    [TestCase(ConsumerClaimState.Missing)]
    [TestCase(ConsumerClaimState.Blank)]
    [TestCase(ConsumerClaimState.Duplicate)]
    public async Task Consumer_policy_rejects_a_missing_blank_or_ambiguous_consumer_identity(
        ConsumerClaimState consumerClaimState)
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();

        var result = await authorization.AuthorizeAsync(
            ConsumerPrincipal(consumerClaimState),
            resource: null,
            ConsumerPolicies.CanUseConsumerPortal);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task Hud_policy_rejects_every_principal_when_the_active_device_resource_is_invalid()
    {
        using var provider = Services();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var activeHudBinding = CreateActiveHudBinding(scope.ServiceProvider);

        foreach (var principalKind in AllPrincipalKinds)
        {
            var result = await authorization.AuthorizeAsync(
                Principal(principalKind),
                ActiveHudContext(scope.ServiceProvider, activeHudBinding with { Credential = "invalid" }),
                HudPolicies.CanUseActiveDevice);

            Assert.That(result.Succeeded, Is.False, principalKind.ToString());
        }
    }

    private static PolicyExpectation Admin(
        string policyName,
        params PrincipalKind[] allowedPrincipals) =>
        Admin(policyName, compatibilityPolicy: false, allowedPrincipals);

    private static PolicyExpectation Admin(
        string policyName,
        bool compatibilityPolicy,
        params PrincipalKind[] allowedPrincipals) =>
        new(policyName, Allowed(allowedPrincipals), compatibilityPolicy, PolicyResource.None);

    private static IReadOnlySet<PrincipalKind> Allowed(params PrincipalKind[] principalKinds) =>
        new HashSet<PrincipalKind>(principalKinds);

    private static ServiceProvider Services()
    {
        var options = new HipProductionAuthenticationOptions
        {
            Authority = "https://identity.hip.test/tenant/v2.0",
            ClientId = "hip-web",
            ClientSecret = "test-only-policy-matrix-secret",
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
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(Environments.Production));
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
        services.AddSingleton<IOptions<HipProductionAuthenticationOptions>>(Options.Create(options));
        services.AddSingleton<EndpointDataSource, EmptyEndpointDataSource>();
        services.AddSingleton<ISetupCodeLicenseService, InMemorySetupCodeLicenseService>();
        services.AddSingleton<IHudDeviceCredentialService>(new HudDeviceCredentialService(
            new PrivacyHashingOptions("test-only-HUD-policy-matrix-key", AllowDevelopmentKey: true)));
        services.AddHipAdminAuthorization();
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
    }

    private static ClaimsPrincipal Principal(
        PrincipalKind principalKind,
        ActorClaimState actorClaimState = ActorClaimState.Valid,
        bool includePrivilegedMfa = true,
        DateTimeOffset? authenticationTime = null)
    {
        if (principalKind == PrincipalKind.Anonymous)
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }

        if (principalKind == PrincipalKind.Consumer)
        {
            return ConsumerPrincipal(ConsumerClaimState.Valid);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, $"matrix-{principalKind.ToString().ToLowerInvariant()}")
        };
        if (principalKind != PrincipalKind.AuthenticatedWithoutRole)
        {
            claims.Add(new Claim(ClaimTypes.Role, principalKind.ToString()));
        }

        AddActorClaims(claims, actorClaimState);
        if (includePrivilegedMfa && principalKind is PrincipalKind.Owner or PrincipalKind.Admin)
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                "true",
                ClaimValueTypes.Boolean));
            claims.Add(AuthenticationTimeClaim(authenticationTime ?? Now));
        }

        return AuthenticatedPrincipal(claims);
    }

    private static ClaimsPrincipal ConsumerPrincipal(ConsumerClaimState consumerClaimState)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "matrix-consumer")
        };
        switch (consumerClaimState)
        {
            case ConsumerClaimState.Valid:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ConsumerId, "matrix-consumer"));
                break;
            case ConsumerClaimState.Blank:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ConsumerId, "   "));
                break;
            case ConsumerClaimState.Duplicate:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ConsumerId, "matrix-consumer"));
                claims.Add(new Claim(HipAuthenticationClaimTypes.ConsumerId, "matrix-consumer"));
                break;
        }

        return AuthenticatedPrincipal(claims);
    }

    private static ClaimsPrincipal AuthenticatedPrincipal(IEnumerable<Claim> claims) =>
        new(new ClaimsIdentity(
            claims,
            authenticationType: "HIP.PolicyMatrix",
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role));

    private static void AddActorClaims(ICollection<Claim> claims, ActorClaimState actorClaimState)
    {
        switch (actorClaimState)
        {
            case ActorClaimState.Valid:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ActorId, "matrix-actor"));
                break;
            case ActorClaimState.Blank:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ActorId, "   "));
                break;
            case ActorClaimState.Duplicate:
                claims.Add(new Claim(HipAuthenticationClaimTypes.ActorId, "matrix-actor"));
                claims.Add(new Claim(HipAuthenticationClaimTypes.ActorId, "matrix-actor"));
                break;
        }
    }

    private static Claim AuthenticationTimeClaim(DateTimeOffset authenticationTime) =>
        new(
            HipAuthenticationClaimTypes.AuthenticationTime,
            authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);

    private static ActiveHudBinding CreateActiveHudBinding(IServiceProvider services)
    {
        var licenses = services.GetRequiredService<ISetupCodeLicenseService>();
        var credentials = services.GetRequiredService<IHudDeviceCredentialService>();
        var created = licenses.CreateSetupCode(new CreateSetupCodeRequest(1, "matrix-owner", "Normal"));
        var deviceId = $"matrix-device-{created.LicenseId}";
        var activation = licenses.ActivateHud(created.SetupCode, deviceId, avatarIdHash: null, hudVersion: "matrix-test");

        Assert.That(activation.Activated, Is.True);
        return new ActiveHudBinding(deviceId, credentials.Issue(created.LicenseId, deviceId));
    }

    private static HttpContext ActiveHudContext(
        IServiceProvider services,
        ActiveHudBinding binding)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services
        };
        context.Request.RouteValues = new RouteValueDictionary
        {
            ["deviceId"] = binding.DeviceId
        };
        context.Request.Headers[HudPolicies.DeviceCredentialHeader] = binding.Credential;
        context.SetEndpoint(new Endpoint(
            static _ => Task.CompletedTask,
            new EndpointMetadataCollection(new HudDeviceAuthorizationMetadata(
                HudDeviceIdentifierLocation.Route,
                "deviceId")),
            "policy-matrix-hud"));
        return context;
    }

    private sealed record PolicyExpectation(
        string PolicyName,
        IReadOnlySet<PrincipalKind> AllowedPrincipals,
        bool IsCompatibilityPolicy,
        PolicyResource Resource);

    private sealed record ActiveHudBinding(string DeviceId, string Credential);

    private enum PolicyResource
    {
        None,
        ActiveHudDevice
    }

    /// <summary>Names the eight distinct human-principal shapes covered by the matrix.</summary>
    public enum PrincipalKind
    {
        Owner,
        Admin,
        Moderator,
        Support,
        ReadOnly,
        Consumer,
        AuthenticatedWithoutRole,
        Anonymous
    }

    /// <summary>Describes valid and fail-closed HIP actor-claim shapes.</summary>
    public enum ActorClaimState
    {
        Valid,
        Missing,
        Blank,
        Duplicate
    }

    /// <summary>Describes valid and fail-closed HIP consumer-claim shapes.</summary>
    public enum ConsumerClaimState
    {
        Valid,
        Missing,
        Blank,
        Duplicate
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class EmptyEndpointDataSource : EndpointDataSource
    {
        public override IReadOnlyList<Endpoint> Endpoints => [];

        public override IChangeToken GetChangeToken() => NullChangeToken.Singleton;
    }

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "HIP.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
