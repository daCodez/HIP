using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using HIP.Web.Components;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace HIP.Tests;

/// <summary>
/// Hosts HIP's real Production authentication, endpoints, policies, and Razor UI without database or network startup.
/// </summary>
public sealed class HipProductionAuthenticationTestHost : IAsyncDisposable
{
    public const string CertificatePassword = "temporary-production-test-certificate-password";
    public const string IdentityProviderAuthority = "https://identity.hip.test/tenant/v2.0";
    public const string IdentityProviderAuthorizationEndpoint = "https://identity.hip.test/connect/authorize";
    public const string IdentityProviderEndSessionEndpoint = "https://identity.hip.test/connect/logout";

    private readonly WebApplication application;
    private readonly string rootDirectoryPath;

    private HipProductionAuthenticationTestHost(WebApplication application, string rootDirectoryPath)
    {
        this.application = application;
        this.rootDirectoryPath = rootDirectoryPath;
    }

    public string KeyRingDirectoryPath => Path.Combine(rootDirectoryPath, "shared-session-keys");

    public string CertificatePath => Path.Combine(rootDirectoryPath, "session-protection.pfx");

    public IServiceProvider Services => application.Services;

    public static async Task<HipProductionAuthenticationTestHost> CreateAsync()
    {
        var rootDirectoryPath = Path.Combine(
            Path.GetTempPath(),
            "hip-production-auth-tests",
            Guid.NewGuid().ToString("N"));
        var keyRingDirectoryPath = Path.Combine(rootDirectoryPath, "shared-session-keys");
        var certificatePath = Path.Combine(rootDirectoryPath, "session-protection.pfx");
        Directory.CreateDirectory(keyRingDirectoryPath);
        CreateCertificate(certificatePath);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(Program).Assembly.GetName().Name,
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production
        });
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{HipProductionAuthenticationOptions.SectionName}:Authority"] = IdentityProviderAuthority,
            [$"{HipProductionAuthenticationOptions.SectionName}:ClientId"] = "hip-web-test",
            [$"{HipProductionAuthenticationOptions.SectionName}:ClientSecret"] = "test-oidc-secret-from-protected-configuration",
            [$"{HipProductionAuthenticationOptions.SectionName}:RoleClaimType"] = "roles",
            [$"{HipProductionAuthenticationOptions.SectionName}:RoleMappings:hip-owner"] = AdminRoles.Owner,
            [$"{HipProductionAuthenticationOptions.SectionName}:AcceptStandardMfaAmr"] = "true",
            [$"{HipProductionAuthenticationOptions.SectionName}:TrustedMfaAcrValues:0"] = "urn:hip:test:mfa",
            [$"{HipProductionAuthenticationOptions.SectionName}:RecentAuthenticationLifetime"] = "00:10:00",
            [$"{HipProductionAuthenticationOptions.SectionName}:IdleSessionLifetime"] = "00:30:00",
            [$"{HipProductionAuthenticationOptions.SectionName}:AbsoluteSessionLifetime"] = "08:00:00",
            [$"{HipSessionProtectionOptions.SectionName}:KeyRingDirectoryPath"] = keyRingDirectoryPath,
            [$"{HipSessionProtectionOptions.SectionName}:CertificatePath"] = certificatePath,
            [$"{HipSessionProtectionOptions.SectionName}:CertificatePassword"] = CertificatePassword,
            [$"{HipSessionProtectionOptions.SectionName}:ApplicationName"] = "HIP.Web"
        });
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddHipAuthorizationTestDependencies();
        builder.Services.AddHipWebAuthentication(builder.Configuration, builder.Environment);
        builder.Services.AddHipAdminAuthorization();
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddRateLimiter(options =>
            options.AddPolicy(
                RateLimitPolicies.AdminLoginPolicy,
                _ => RateLimitPartition.GetNoLimiter("production-auth-test")));
        builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        builder.Services.PostConfigure<OpenIdConnectOptions>(HipAuthenticationSchemes.OpenIdConnect, options =>
        {
            var configuration = new OpenIdConnectConfiguration
            {
                Issuer = IdentityProviderAuthority,
                AuthorizationEndpoint = IdentityProviderAuthorizationEndpoint,
                TokenEndpoint = "https://identity.hip.test/connect/token",
                EndSessionEndpoint = IdentityProviderEndSessionEndpoint
            };
            options.Configuration = configuration;
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            options.Backchannel = new HttpClient(new RejectNetworkHandler());
        });

        var application = builder.Build();
        application.UseRateLimiter();
        application.UseAuthentication();
        application.UseAuthorization();
        application.UseAntiforgery();
        application.MapHipProductionLogin();
        application.MapGet("/api/v1/admin/roles", () => Results.Ok(AdminRoleCatalog.Roles))
            .RequireAuthorization(AdminPolicies.CanViewAdminDashboard);
        application.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        await application.StartAsync();
        return new HipProductionAuthenticationTestHost(application, rootDirectoryPath);
    }

    public HttpClient CreateClient()
    {
        var client = application.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await application.DisposeAsync();
        if (Directory.Exists(rootDirectoryPath))
        {
            Directory.Delete(rootDirectoryPath, recursive: true);
        }
    }

    private static void CreateCertificate(string certificatePath)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=HIP production authentication tests",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(2));
        File.WriteAllBytes(
            certificatePath,
            certificate.Export(X509ContentType.Pfx, CertificatePassword));
    }

    private sealed class RejectNetworkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Production authentication tests must not contact an external identity provider.");
    }
}
