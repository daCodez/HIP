using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using HIP.Application.SecondLife;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies protected HTTP routes fail closed unless their HIP-owned identity claim is unique and nonblank.
/// </summary>
[TestFixture]
public sealed class HipIdentityIntegrityAuthorizationTests
{
    [Test]
    public async Task Admin_and_consumer_policies_require_exactly_one_nonblank_HIP_identity()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHipAuthorizationTestDependencies();
        services.AddSingleton<IHostEnvironment>(new StubHostEnvironment(Environments.Development));
        services.AddSingleton(TimeProvider.System);
        services.AddHipAdminAuthorization();
        await using var provider = services.BuildServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();

        var validAdmin = Principal(
            new Claim(ClaimTypes.Role, AdminRoles.ReadOnly),
            new Claim(HipAuthenticationClaimTypes.ActorId, "privacy-safe-actor"));
        var missingAdmin = Principal(new Claim(ClaimTypes.Role, AdminRoles.ReadOnly));
        var blankAdmin = Principal(
            new Claim(ClaimTypes.Role, AdminRoles.ReadOnly),
            new Claim(HipAuthenticationClaimTypes.ActorId, "   "));
        var duplicateAdmin = Principal(
            new Claim(ClaimTypes.Role, AdminRoles.ReadOnly),
            new Claim(HipAuthenticationClaimTypes.ActorId, "actor-one"),
            new Claim(HipAuthenticationClaimTypes.ActorId, "actor-two"));
        var validConsumer = Principal(new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-one"));
        var missingConsumer = Principal();
        var duplicateConsumer = Principal(
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-one"),
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-two"));

        var validAdminResult = await authorization.AuthorizeAsync(validAdmin, AdminPolicies.CanViewAdminDashboard);
        var missingAdminResult = await authorization.AuthorizeAsync(missingAdmin, AdminPolicies.CanViewAdminDashboard);
        var blankAdminResult = await authorization.AuthorizeAsync(blankAdmin, AdminPolicies.CanViewAdminDashboard);
        var duplicateAdminResult = await authorization.AuthorizeAsync(duplicateAdmin, AdminPolicies.CanViewAdminDashboard);
        var validConsumerResult = await authorization.AuthorizeAsync(validConsumer, ConsumerPolicies.CanUseConsumerPortal);
        var missingConsumerResult = await authorization.AuthorizeAsync(missingConsumer, ConsumerPolicies.CanUseConsumerPortal);
        var duplicateConsumerResult = await authorization.AuthorizeAsync(duplicateConsumer, ConsumerPolicies.CanUseConsumerPortal);

        Assert.Multiple(() =>
        {
            Assert.That(validAdminResult.Succeeded, Is.True);
            Assert.That(missingAdminResult.Succeeded, Is.False);
            Assert.That(blankAdminResult.Succeeded, Is.False);
            Assert.That(duplicateAdminResult.Succeeded, Is.False);
            Assert.That(validConsumerResult.Succeeded, Is.True);
            Assert.That(missingConsumerResult.Succeeded, Is.False);
            Assert.That(duplicateConsumerResult.Succeeded, Is.False);
        });
    }

    [Test]
    public void Identity_resolver_accepts_only_one_authenticated_nonblank_claim()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                HipAuthenticatedIdentity.TryResolveUniqueClaim(
                    Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "  actor-one  ")),
                    HipAuthenticationClaimTypes.ActorId,
                    out var actor),
                Is.True);
            Assert.That(actor, Is.EqualTo("actor-one"));
            Assert.That(
                HipAuthenticatedIdentity.TryResolveUniqueClaim(
                    Principal(
                        new Claim(HipAuthenticationClaimTypes.ActorId, "actor-one"),
                        new Claim(HipAuthenticationClaimTypes.ActorId, "actor-two")),
                    HipAuthenticationClaimTypes.ActorId,
                    out _),
                Is.False);
            Assert.That(
                HipAuthenticatedIdentity.TryResolveUniqueClaim(
                    new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim(HipAuthenticationClaimTypes.ActorId, "unauthenticated")],
                        authenticationType: null)),
                    HipAuthenticationClaimTypes.ActorId,
                    out _),
                Is.False);
            Assert.That(
                HipAuthenticatedIdentity.TryResolveUniqueClaim(
                    new ClaimsPrincipal(
                    [
                        new ClaimsIdentity([new Claim(ClaimTypes.Role, AdminRoles.ReadOnly)], "authenticated"),
                        new ClaimsIdentity(
                            [new Claim(HipAuthenticationClaimTypes.ActorId, "untrusted-secondary-identity")],
                            authenticationType: null)
                    ]),
                    HipAuthenticationClaimTypes.ActorId,
                    out _),
                Is.False);
        });
    }

    [Test]
    public async Task Duplicate_admin_actor_claims_return_forbidden_without_executing_license_mutation()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = AmbiguousAdminAuthenticationHandler.SchemeName;
                        options.DefaultChallengeScheme = AmbiguousAdminAuthenticationHandler.SchemeName;
                        options.DefaultForbidScheme = AmbiguousAdminAuthenticationHandler.SchemeName;
                    })
                    .AddScheme<AuthenticationSchemeOptions, AmbiguousAdminAuthenticationHandler>(
                        AmbiguousAdminAuthenticationHandler.SchemeName,
                        _ => { });
            }));
        var before = await LicenseCountAsync(factory.Services);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await client.PostAsJsonAsync(
            "/api/v1/licenses/setup-codes",
            new CreateSetupCodeRequest(1, "forged-creator", "Normal"));

        var after = await LicenseCountAsync(factory.Services);
        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(after, Is.EqualTo(before));
        });
    }

    [Test]
    public async Task Development_admin_auth_emits_the_HIP_actor_required_by_admin_policies()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.ReadOnly);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "development-actor");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "test", ClaimTypes.Name, ClaimTypes.Role));

    private static async Task<int> LicenseCountAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var licenseService = scope.ServiceProvider.GetRequiredService<ISetupCodeLicenseService>();
        return (await licenseService.ListLicensesAsync(CancellationToken.None)).Count;
    }

    private sealed class AmbiguousAdminAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "AmbiguousAdmin";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, "ambiguous-owner"),
                new Claim(ClaimTypes.Role, AdminRoles.Owner),
                new Claim(HipAuthenticationClaimTypes.ActorId, "actor-one"),
                new Claim(HipAuthenticationClaimTypes.ActorId, "actor-two"),
                new Claim(HipAuthenticationClaimTypes.MultiFactorAuthenticated, bool.TrueString),
                new Claim(HipAuthenticationClaimTypes.AuthenticationTime, now)
            };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
        }
    }

    private sealed class StubHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "HIP.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
