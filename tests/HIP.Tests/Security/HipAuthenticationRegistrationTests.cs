using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies HIP selects exactly one environment-appropriate authentication stack and hardens production sessions.
/// </summary>
public sealed class HipAuthenticationRegistrationTests
{
    [Test]
    public async Task Development_registers_only_the_existing_local_authentication_scheme()
    {
        var services = BaseServices();
        var environment = new TestHostEnvironment(Environments.Development);

        services.AddHipWebAuthentication(new ConfigurationBuilder().Build(), environment);

        using var provider = services.BuildServiceProvider();
        var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        var defaults = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        Assert.Multiple(() =>
        {
            Assert.That(schemes.Select(scheme => scheme.Name), Is.EqualTo(new[] { HipDevHeaderAuthenticationHandler.SchemeName }));
            Assert.That(defaults.DefaultAuthenticateScheme, Is.EqualTo(HipDevHeaderAuthenticationHandler.SchemeName));
            Assert.That(defaults.DefaultChallengeScheme, Is.EqualTo(HipDevHeaderAuthenticationHandler.SchemeName));
            Assert.That(schemes.Any(scheme => scheme.Name == HipAuthenticationSchemes.SessionCookie), Is.False);
            Assert.That(schemes.Any(scheme => scheme.Name == HipAuthenticationSchemes.OpenIdConnect), Is.False);
        });
    }

    [Test]
    public async Task Production_registers_only_hardened_cookie_and_confidential_oidc_schemes()
    {
        using var sessionFiles = TestSessionFiles.Create();
        var services = BaseServices();

        services.AddHipWebAuthentication(ProductionConfiguration(sessionFiles), new TestHostEnvironment(Environments.Production));

        using var provider = services.BuildServiceProvider();
        var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        var defaults = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        var cookie = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(HipAuthenticationSchemes.SessionCookie);
        var oidc = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(HipAuthenticationSchemes.OpenIdConnect);
        var challengeRouter = provider.GetRequiredService<IOptionsMonitor<PolicySchemeOptions>>()
            .Get(HipAuthenticationSchemes.Challenge);
        var apiContext = new DefaultHttpContext();
        apiContext.Request.Path = "/api/v1/admin/rules";
        var pageContext = new DefaultHttpContext();
        pageContext.Request.Path = "/admin";

        Assert.Multiple(() =>
        {
            Assert.That(schemes.Select(scheme => scheme.Name), Is.EquivalentTo(new[]
            {
                HipAuthenticationSchemes.SessionCookie,
                HipAuthenticationSchemes.Challenge,
                HipAuthenticationSchemes.OpenIdConnect
            }));
            Assert.That(schemes.Any(scheme => scheme.Name == HipDevHeaderAuthenticationHandler.SchemeName), Is.False);
            Assert.That(defaults.DefaultAuthenticateScheme, Is.EqualTo(HipAuthenticationSchemes.SessionCookie));
            Assert.That(defaults.DefaultSignInScheme, Is.EqualTo(HipAuthenticationSchemes.SessionCookie));
            Assert.That(defaults.DefaultChallengeScheme, Is.EqualTo(HipAuthenticationSchemes.Challenge));
            Assert.That(defaults.DefaultForbidScheme, Is.EqualTo(HipAuthenticationSchemes.SessionCookie));
            Assert.That(defaults.DefaultSignOutScheme, Is.EqualTo(HipAuthenticationSchemes.OpenIdConnect));
            Assert.That(challengeRouter.ForwardDefaultSelector!(apiContext), Is.EqualTo(HipAuthenticationSchemes.SessionCookie));
            Assert.That(challengeRouter.ForwardDefaultSelector!(pageContext), Is.EqualTo(HipAuthenticationSchemes.OpenIdConnect));

            Assert.That(cookie.Cookie.Name, Is.EqualTo("__Host-HIP.Session"));
            Assert.That(cookie.Cookie.HttpOnly, Is.True);
            Assert.That(cookie.Cookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.Always));
            Assert.That(cookie.Cookie.SameSite, Is.EqualTo(SameSiteMode.Lax));
            Assert.That(cookie.Cookie.Path, Is.EqualTo("/"));
            Assert.That(cookie.Cookie.Domain, Is.Null);
            Assert.That(cookie.SlidingExpiration, Is.False);
            Assert.That(cookie.ExpireTimeSpan, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(cookie.EventsType, Is.EqualTo(typeof(HipSessionCookieEvents)));

            Assert.That(oidc.Authority, Is.EqualTo("https://identity.hip.test/tenant/v2.0"));
            Assert.That(oidc.ClientId, Is.EqualTo("hip-web"));
            Assert.That(oidc.ClientSecret, Is.EqualTo("test-oidc-secret"));
            Assert.That(oidc.ResponseType, Is.EqualTo(OpenIdConnectResponseType.Code));
            Assert.That(oidc.ResponseMode, Is.EqualTo(OpenIdConnectResponseMode.Query));
            Assert.That(oidc.UsePkce, Is.True);
            Assert.That(oidc.RequireHttpsMetadata, Is.True);
            Assert.That(oidc.MapInboundClaims, Is.False);
            Assert.That(oidc.SaveTokens, Is.False);
            Assert.That(oidc.UseTokenLifetime, Is.False);
            Assert.That(oidc.MaxAge, Is.EqualTo(TimeSpan.FromHours(8)));
            Assert.That(oidc.Scope, Is.EqualTo(new[] { OpenIdConnectScope.OpenId }));
            Assert.That(oidc.EventsType, Is.EqualTo(typeof(HipOpenIdConnectEvents)));
            Assert.That(oidc.CorrelationCookie.Name, Is.EqualTo("__Host-HIP.Oidc.Correlation."));
            Assert.That(oidc.CorrelationCookie.HttpOnly, Is.True);
            Assert.That(oidc.CorrelationCookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.Always));
            Assert.That(oidc.CorrelationCookie.SameSite, Is.EqualTo(SameSiteMode.Lax));
            Assert.That(oidc.CorrelationCookie.Path, Is.EqualTo("/"));
            Assert.That(oidc.CorrelationCookie.Domain, Is.Null);
            Assert.That(oidc.NonceCookie.Name, Is.EqualTo("__Host-HIP.Oidc.Nonce."));
            Assert.That(oidc.NonceCookie.HttpOnly, Is.True);
            Assert.That(oidc.NonceCookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.Always));
            Assert.That(oidc.NonceCookie.SameSite, Is.EqualTo(SameSiteMode.Lax));
            Assert.That(oidc.NonceCookie.Path, Is.EqualTo("/"));
            Assert.That(oidc.NonceCookie.Domain, Is.Null);
            Assert.That(oidc.TokenValidationParameters.ValidateIssuer, Is.True);
            Assert.That(oidc.TokenValidationParameters.ValidateAudience, Is.True);
            Assert.That(oidc.TokenValidationParameters.ValidateLifetime, Is.True);
            Assert.That(oidc.TokenValidationParameters.ValidateIssuerSigningKey, Is.True);
            Assert.That(oidc.TokenValidationParameters.RequireExpirationTime, Is.True);
            Assert.That(oidc.TokenValidationParameters.RequireSignedTokens, Is.True);
            Assert.That(oidc.TokenValidationParameters.ValidAudience, Is.EqualTo("hip-web"));
            Assert.That(
                oidc.TokenValidationParameters.ClockSkew,
                Is.EqualTo(HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew));
            Assert.That(provider.GetService<HipExternalAuthenticationAssuranceEvaluator>(), Is.Not.Null);
        });
    }

    [Test]
    public void Production_configures_shared_certificate_protected_data_protection()
    {
        using var sessionFiles = TestSessionFiles.Create();
        var services = BaseServices();

        services.AddHipWebAuthentication(ProductionConfiguration(sessionFiles), new TestHostEnvironment(Environments.Production));

        using var provider = services.BuildServiceProvider();
        var dataProtection = provider.GetRequiredService<IOptions<DataProtectionOptions>>().Value;
        var keyManagement = provider.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        var certificate = provider.GetRequiredService<X509Certificate2>();

        Assert.Multiple(() =>
        {
            Assert.That(dataProtection.ApplicationDiscriminator, Is.EqualTo("HIP.Web"));
            Assert.That(keyManagement.XmlRepository?.GetType().Name, Is.EqualTo("FileSystemXmlRepository"));
            Assert.That(keyManagement.XmlEncryptor?.GetType().Name, Is.EqualTo("CertificateXmlEncryptor"));
            Assert.That(certificate.HasPrivateKey, Is.True);
        });
    }

    [Test]
    public void Invalid_pkcs12_fails_registration_without_echoing_path_or_password()
    {
        using var sessionFiles = TestSessionFiles.Create(invalidCertificate: true);
        var configuration = ProductionConfiguration(sessionFiles);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            BaseServices().AddHipWebAuthentication(configuration, new TestHostEnvironment(Environments.Production)));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Not.Contain(sessionFiles.CertificatePath));
            Assert.That(exception.Message, Does.Not.Contain(TestSessionFiles.CertificatePassword));
        });
    }

    [Test]
    public void Rsa_certificate_smaller_than_2048_bits_fails_registration_without_echoing_secrets()
    {
        using var sessionFiles = TestSessionFiles.Create(rsaKeySize: 1024);
        var configuration = ProductionConfiguration(sessionFiles);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            BaseServices().AddHipWebAuthentication(configuration, new TestHostEnvironment(Environments.Production)));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Is.EqualTo("HIP session protection certificate could not be loaded."));
            Assert.That(exception.Message, Does.Not.Contain(sessionFiles.CertificatePath));
            Assert.That(exception.Message, Does.Not.Contain(TestSessionFiles.CertificatePassword));
        });
    }

    [Test]
    public void Production_probes_the_key_ring_and_removes_the_temporary_probe()
    {
        using var sessionFiles = TestSessionFiles.Create();

        BaseServices().AddHipWebAuthentication(
            ProductionConfiguration(sessionFiles),
            new TestHostEnvironment(Environments.Production));

        Assert.That(
            Directory.EnumerateFiles(sessionFiles.KeyRingDirectoryPath, ".hip-session-probe-*"),
            Is.Empty);
    }

    [Test]
    public void Unavailable_key_ring_storage_fails_registration_without_echoing_path_or_password()
    {
        using var sessionFiles = TestSessionFiles.Create();
        var unavailableKeyRingPath = Path.Combine(sessionFiles.RootDirectoryPath, "not-a-directory");
        File.WriteAllText(unavailableKeyRingPath, "blocks key-ring directory creation");

        var exception = Assert.Throws<InvalidOperationException>(() =>
            BaseServices().AddHipWebAuthentication(
                ProductionConfiguration(sessionFiles, unavailableKeyRingPath),
                new TestHostEnvironment(Environments.Production)));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Is.EqualTo("HIP session key-ring storage is unavailable."));
            Assert.That(exception.Message, Does.Not.Contain(unavailableKeyRingPath));
            Assert.That(exception.Message, Does.Not.Contain(TestSessionFiles.CertificatePassword));
        });
    }

    private static ServiceCollection BaseServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    private static IConfiguration ProductionConfiguration(
        TestSessionFiles sessionFiles,
        string? keyRingDirectoryPath = null) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{HipProductionAuthenticationOptions.SectionName}:Authority"] = "https://identity.hip.test/tenant/v2.0",
                [$"{HipProductionAuthenticationOptions.SectionName}:ClientId"] = "hip-web",
                [$"{HipProductionAuthenticationOptions.SectionName}:ClientSecret"] = "test-oidc-secret",
                [$"{HipProductionAuthenticationOptions.SectionName}:RoleClaimType"] = "roles",
                [$"{HipProductionAuthenticationOptions.SectionName}:RoleMappings:hip-owner"] = AdminRoles.Owner,
                [$"{HipProductionAuthenticationOptions.SectionName}:RoleMappings:hip-reader"] = AdminRoles.ReadOnly,
                [$"{HipProductionAuthenticationOptions.SectionName}:AcceptStandardMfaAmr"] = "true",
                [$"{HipProductionAuthenticationOptions.SectionName}:TrustedMfaAcrValues:0"] = "urn:hip:test:mfa",
                [$"{HipProductionAuthenticationOptions.SectionName}:RecentAuthenticationLifetime"] = "00:10:00",
                [$"{HipProductionAuthenticationOptions.SectionName}:IdleSessionLifetime"] = "00:30:00",
                [$"{HipProductionAuthenticationOptions.SectionName}:AbsoluteSessionLifetime"] = "08:00:00",
                [$"{HipSessionProtectionOptions.SectionName}:KeyRingDirectoryPath"] =
                    keyRingDirectoryPath ?? sessionFiles.KeyRingDirectoryPath,
                [$"{HipSessionProtectionOptions.SectionName}:CertificatePath"] = sessionFiles.CertificatePath,
                [$"{HipSessionProtectionOptions.SectionName}:CertificatePassword"] = TestSessionFiles.CertificatePassword,
                [$"{HipSessionProtectionOptions.SectionName}:ApplicationName"] = "HIP.Web"
            })
            .Build();

    private sealed class TestSessionFiles : IDisposable
    {
        public const string CertificatePassword = "temporary-test-certificate-password";

        private TestSessionFiles(string rootDirectoryPath)
        {
            RootDirectoryPath = rootDirectoryPath;
            KeyRingDirectoryPath = Path.Combine(rootDirectoryPath, "shared-keys");
            CertificatePath = Path.Combine(rootDirectoryPath, "session-protection.pfx");
        }

        public string RootDirectoryPath { get; }

        public string KeyRingDirectoryPath { get; }

        public string CertificatePath { get; }

        public static TestSessionFiles Create(bool invalidCertificate = false, int rsaKeySize = 2048)
        {
            var files = new TestSessionFiles(Path.Combine(Path.GetTempPath(), "hip-auth-registration", Guid.NewGuid().ToString("N")));
            Directory.CreateDirectory(files.RootDirectoryPath);
            Directory.CreateDirectory(files.KeyRingDirectoryPath);

            if (invalidCertificate)
            {
                File.WriteAllBytes(files.CertificatePath, [0x01, 0x02, 0x03]);
                return files;
            }

            using var rsa = RSA.Create(rsaKeySize);
            var request = new CertificateRequest(
                "CN=HIP authentication tests",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddHours(1));
            File.WriteAllBytes(
                files.CertificatePath,
                certificate.Export(X509ContentType.Pfx, CertificatePassword));
            return files;
        }

        public void Dispose()
        {
            if (Directory.Exists(RootDirectoryPath))
            {
                Directory.Delete(RootDirectoryPath, recursive: true);
            }
        }
    }

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "HIP.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
