using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace HIP.Web.Security;

/// <summary>Registers HIP's isolated Development scheme or hardened production cookie and OIDC schemes.</summary>
public static class HipAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Adds environment-appropriate web authentication without registering API bearer credentials.
    /// </summary>
    /// <param name="services">Host services.</param>
    /// <param name="configuration">Host configuration.</param>
    /// <param name="environment">Current host environment.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddHipWebAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        if (environment.IsDevelopment())
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = HipDevHeaderAuthenticationHandler.SchemeName;
                options.DefaultAuthenticateScheme = HipDevHeaderAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = HipDevHeaderAuthenticationHandler.SchemeName;
                options.DefaultForbidScheme = HipDevHeaderAuthenticationHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, HipDevHeaderAuthenticationHandler>(
                HipDevHeaderAuthenticationHandler.SchemeName,
                _ => { });
            return services;
        }

        var authenticationSection = configuration.GetSection(HipProductionAuthenticationOptions.SectionName);
        var authentication = authenticationSection.Get<HipProductionAuthenticationOptions>() ?? new();
        ThrowIfInvalid(
            new HipProductionAuthenticationOptionsValidator().Validate(Options.DefaultName, authentication),
            typeof(HipProductionAuthenticationOptions));

        var sessionSection = configuration.GetSection(HipSessionProtectionOptions.SectionName);
        var sessionProtection = sessionSection.Get<HipSessionProtectionOptions>() ?? new();
        ThrowIfInvalid(
            new HipSessionProtectionOptionsValidator(environment).Validate(Options.DefaultName, sessionProtection),
            typeof(HipSessionProtectionOptions));

        var certificate = LoadSessionProtectionCertificate(sessionProtection);
        EnsureKeyRingAvailable(sessionProtection);

        services.AddSingleton<IValidateOptions<HipProductionAuthenticationOptions>, HipProductionAuthenticationOptionsValidator>();
        services.AddSingleton<IValidateOptions<HipSessionProtectionOptions>>(
            _ => new HipSessionProtectionOptionsValidator(environment));
        services.AddOptions<HipProductionAuthenticationOptions>()
            .Bind(authenticationSection)
            .ValidateOnStart();
        services.AddOptions<HipSessionProtectionOptions>()
            .Bind(sessionSection)
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<HipExternalClaimsMapper>();
        services.AddSingleton<HipExternalAuthenticationAssuranceEvaluator>();
        services.AddScoped<HipSessionCookieEvents>();
        services.AddScoped<HipOpenIdConnectEvents>();
        services.AddSingleton(certificate);

        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(sessionProtection.KeyRingDirectoryPath))
            .ProtectKeysWithCertificate(certificate)
            .SetApplicationName(sessionProtection.ApplicationName);

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = HipAuthenticationSchemes.SessionCookie;
            options.DefaultAuthenticateScheme = HipAuthenticationSchemes.SessionCookie;
            options.DefaultSignInScheme = HipAuthenticationSchemes.SessionCookie;
            options.DefaultChallengeScheme = HipAuthenticationSchemes.Challenge;
            options.DefaultForbidScheme = HipAuthenticationSchemes.SessionCookie;
            options.DefaultSignOutScheme = HipAuthenticationSchemes.OpenIdConnect;
        })
        .AddCookie(HipAuthenticationSchemes.SessionCookie, options =>
        {
            options.Cookie.Name = "__Host-HIP.Session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = "/";
            options.Cookie.Domain = null;
            options.ExpireTimeSpan = authentication.IdleSessionLifetime;
            options.SlidingExpiration = false;
            options.LoginPath = "/login";
            options.AccessDeniedPath = "/forbidden";
            options.ReturnUrlParameter = "returnUrl";
            options.EventsType = typeof(HipSessionCookieEvents);
        })
        .AddPolicyScheme(HipAuthenticationSchemes.Challenge, displayName: null, options =>
        {
            options.ForwardDefaultSelector = context =>
                context.Request.Path.StartsWithSegments("/api")
                    ? HipAuthenticationSchemes.SessionCookie
                    : HipAuthenticationSchemes.OpenIdConnect;
        })
        .AddOpenIdConnect(HipAuthenticationSchemes.OpenIdConnect, options =>
        {
            options.Authority = authentication.Authority;
            options.ClientId = authentication.ClientId;
            options.ClientSecret = authentication.ClientSecret;
            options.SignInScheme = HipAuthenticationSchemes.SessionCookie;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.ResponseMode = OpenIdConnectResponseMode.FormPost;
            options.UsePkce = true;
            options.RequireHttpsMetadata = true;
            options.MapInboundClaims = false;
            options.GetClaimsFromUserInfoEndpoint = false;
            options.SaveTokens = false;
            options.UseTokenLifetime = false;
            options.MaxAge = authentication.AbsoluteSessionLifetime;
            options.Scope.Clear();
            options.Scope.Add(OpenIdConnectScope.OpenId);
            options.EventsType = typeof(HipOpenIdConnectEvents);
            options.CorrelationCookie.Name = "__Host-HIP.Oidc.Correlation.";
            options.CorrelationCookie.HttpOnly = true;
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.CorrelationCookie.SameSite = SameSiteMode.None;
            options.CorrelationCookie.Path = "/";
            options.CorrelationCookie.IsEssential = true;
            options.NonceCookie.Name = "__Host-HIP.Oidc.Nonce.";
            options.NonceCookie.HttpOnly = true;
            options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.NonceCookie.SameSite = SameSiteMode.None;
            options.NonceCookie.Path = "/";
            options.NonceCookie.IsEssential = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireAudience = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidAudience = authentication.ClientId,
                NameClaimType = HipAuthenticationClaimTypes.Subject,
                RoleClaimType = authentication.RoleClaimType,
                ClockSkew = HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew
            };
        });

        return services;
    }

    private static X509Certificate2 LoadSessionProtectionCertificate(HipSessionProtectionOptions options)
    {
        try
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                options.CertificatePath,
                options.CertificatePassword,
                X509KeyStorageFlags.EphemeralKeySet);
            using var publicKey = certificate.GetRSAPublicKey();
            using var privateKey = certificate.GetRSAPrivateKey();
            var now = DateTimeOffset.UtcNow;
            if (certificate.HasPrivateKey &&
                publicKey is not null &&
                privateKey is not null &&
                privateKey.KeySize >= 2048 &&
                now >= certificate.NotBefore.ToUniversalTime() &&
                now <= certificate.NotAfter.ToUniversalTime())
            {
                return certificate;
            }

            certificate.Dispose();
        }
        catch (Exception exception) when (
            exception is CryptographicException or IOException or UnauthorizedAccessException)
        {
            // Configuration values and provider errors may contain secrets or local paths, so fail without an inner exception.
        }

        throw new InvalidOperationException("HIP session protection certificate could not be loaded.");
    }

    private static void EnsureKeyRingAvailable(HipSessionProtectionOptions options)
    {
        try
        {
            Directory.CreateDirectory(options.KeyRingDirectoryPath);
            var probePath = Path.Combine(
                options.KeyRingDirectoryPath,
                $".hip-session-probe-{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}");
            using var probe = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough | FileOptions.DeleteOnClose);
            probe.WriteByte(0x48);
            probe.Flush(flushToDisk: true);
            probe.Position = 0;
            if (probe.ReadByte() != 0x48)
            {
                throw new IOException("The HIP session key-ring probe could not be read back.");
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException or
                System.Security.SecurityException)
        {
            throw new InvalidOperationException("HIP session key-ring storage is unavailable.");
        }
    }

    private static void ThrowIfInvalid(ValidateOptionsResult validation, Type optionsType)
    {
        if (validation.Failed)
        {
            throw new OptionsValidationException(Options.DefaultName, optionsType, validation.Failures);
        }
    }
}
