using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text;
using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Security;

/// <summary>Names the standalone API host's exclusive authentication schemes.</summary>
internal static class ApiServiceAuthenticationSchemes
{
    public const string Router = "HipApiServiceAuthentication";
    public const string ServiceClient = "HIP-Service";
}

/// <summary>Stable claim names emitted only by verified HIP service-client authentication.</summary>
internal static class ApiServiceClientClaimTypes
{
    public const string TrustedServiceClient = "hip_service_client";
    public const string ClientId = "hip_service_client_id";
    public const string Scope = "hip_service_scope";
    public const string DomainGrant = "hip_service_domain";
    public const string OwnerScope = "hip_service_owner_scope";
    public const string CredentialVersion = "hip_service_credential_version";
}

/// <summary>
/// Holds one startup-generated verifier used to make canonical unknown-client attempts perform the same KDF work.
/// </summary>
internal sealed class ApiServiceClientDummyVerifier
{
    public ApiServiceClientDummyVerifier(
        IServiceClientCredentialGenerator generator,
        IServiceClientSecretProtector protector)
    {
        var dummyClientId = generator.GenerateClientId();
        var dummySecret = generator.GenerateSecret();
        CredentialVerifier = protector.Protect(dummyClientId, dummySecret);
    }

    public string CredentialVerifier { get; }
}

/// <summary>Authenticates one exact version-one HIP service credential.</summary>
internal sealed class ApiServiceClientAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    IServiceClientAuthenticationAttemptLimiter attemptLimiter,
    IServiceClientRepository repository,
    IServiceClientSecretProtector secretProtector,
    ApiServiceClientDummyVerifier dummyVerifier,
    TimeProvider timeProvider)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    private const string InvalidCredentialMessage = "Invalid HIP service credential.";
    private const string MalformedApparentClient = "malformed-service-credential-v1";
    private const string UnavailableSource = "source-unavailable-v1";
    private const int MaximumAuthorizationHeaderCharacters = 256;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var parsed = TryParseCredential(Request, out var credential)
            ? credential
            : null;
        var sourceIdentity = ResolveExactSourceIdentity(Context.Connection.RemoteIpAddress);
        var apparentClientId = parsed?.ClientId ?? MalformedApparentClient;

        try
        {
            if (!await attemptLimiter.TryAcquireAsync(
                    sourceIdentity,
                    apparentClientId,
                    Context.RequestAborted)
                .ConfigureAwait(false))
            {
                return Fail(ServiceClientAuthenticationOutcome.Throttled);
            }
        }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Fail(ServiceClientAuthenticationOutcome.Unavailable);
        }

        if (parsed is null)
        {
            return Fail(ServiceClientAuthenticationOutcome.InvalidCredential);
        }

        ServiceClientRegistration? initial;
        try
        {
            initial = await repository.GetAsync(parsed.ClientId, Context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Fail(ServiceClientAuthenticationOutcome.Unavailable);
        }

        if (initial is null)
        {
            try
            {
                _ = secretProtector.Verify(
                    parsed.ClientId,
                    parsed.Secret,
                    dummyVerifier.CredentialVerifier);
            }
            catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return Fail(ServiceClientAuthenticationOutcome.Unavailable);
            }

            return Fail(ServiceClientAuthenticationOutcome.InvalidCredential);
        }

        bool secretVerified;
        try
        {
            secretVerified = secretProtector.Verify(
                parsed.ClientId,
                parsed.Secret,
                initial.CredentialVerifier);
        }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Fail(ServiceClientAuthenticationOutcome.Unavailable);
        }

        var verifiedAtUtc = timeProvider.GetUtcNow();
        if (!secretVerified ||
            !string.Equals(initial.ClientId, parsed.ClientId, StringComparison.Ordinal) ||
            initial.Status != ServiceClientStatus.Active ||
            initial.IsExpired(verifiedAtUtc))
        {
            return Fail(ServiceClientAuthenticationOutcome.InvalidCredential);
        }

        ServiceClientRegistration? current;
        try
        {
            current = await repository.GetAsync(parsed.ClientId, Context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Fail(ServiceClientAuthenticationOutcome.Unavailable);
        }

        var issuedAtUtc = timeProvider.GetUtcNow();
        if (current is null ||
            !SecurityStateIsUnchanged(initial, current) ||
            current.Status != ServiceClientStatus.Active ||
            current.IsExpired(issuedAtUtc))
        {
            return Fail(ServiceClientAuthenticationOutcome.InvalidCredential);
        }

        var scope = ServiceClientScopeValues.ToExternalValue(current.Scope);
        var identity = new ClaimsIdentity(
            CreateClaims(current, scope),
            ApiServiceAuthenticationSchemes.ServiceClient);
        ServiceClientTelemetry.RecordAuthentication(
            ServiceClientAuthenticationOutcome.Succeeded,
            current.Scope);
        return AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            ApiServiceAuthenticationSchemes.ServiceClient));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = ApiServiceAuthenticationSchemes.ServiceClient;
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    private static IReadOnlyCollection<Claim> CreateClaims(
        ServiceClientRegistration registration,
        string scope)
    {
        var claims = new List<Claim>(6 + registration.DomainGrants.Count)
        {
            new(ApiServiceClientClaimTypes.TrustedServiceClient, "true", ClaimValueTypes.Boolean),
            new(ApiServiceClientClaimTypes.ClientId, registration.ClientId),
            new(ApiServiceClientClaimTypes.Scope, scope),
            new(ApiServiceClientClaimTypes.OwnerScope, registration.OwnerScopeId),
            new(
                ApiServiceClientClaimTypes.CredentialVersion,
                registration.CredentialVersion.ToString(CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64)
        };
        claims.AddRange(registration.DomainGrants.Select(domain =>
            new Claim(ApiServiceClientClaimTypes.DomainGrant, domain)));
        return claims;
    }

    private static bool TryParseCredential(
        HttpRequest request,
        out ParsedServiceClientCredential? credential)
    {
        credential = null;
        if (!request.Headers.TryGetValue("Authorization", out var values) ||
            values.Count != 1 ||
            values[0] is not { } authorization ||
            authorization.Length is 0 or > MaximumAuthorizationHeaderCharacters)
        {
            return false;
        }

        var separator = authorization.IndexOf(' ');
        if (separator <= 0 ||
            authorization.IndexOf(' ', separator + 1) >= 0 ||
            !authorization[..separator].Equals(
                ApiServiceAuthenticationSchemes.ServiceClient,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var wireCredential = authorization[(separator + 1)..];
        var credentialSeparator = wireCredential.IndexOf('.');
        if (credentialSeparator <= 0 ||
            wireCredential.IndexOf('.', credentialSeparator + 1) >= 0)
        {
            return false;
        }

        var clientId = wireCredential[..credentialSeparator];
        var secretValue = wireCredential[(credentialSeparator + 1)..];
        if (!ServiceClientCredentialFormat.IsCanonicalClientId(clientId) ||
            !ServiceClientCredentialFormat.IsCanonicalSecret(secretValue))
        {
            return false;
        }

        credential = new ParsedServiceClientCredential(
            clientId,
            new ServiceClientSecret(secretValue));
        return true;
    }

    private static string ResolveExactSourceIdentity(IPAddress? remoteAddress)
    {
        if (remoteAddress is null)
        {
            return UnavailableSource;
        }

        var canonicalAddress = remoteAddress.IsIPv4MappedToIPv6
            ? remoteAddress.MapToIPv4()
            : remoteAddress;
        var source = canonicalAddress.ToString();
        return Encoding.UTF8.GetByteCount(source) <=
               ServiceClientAuthenticationAttemptLimiterOptions.MaximumSourceIdentityUtf8Bytes
            ? source
            : UnavailableSource;
    }

    private static bool SecurityStateIsUnchanged(
        ServiceClientRegistration initial,
        ServiceClientRegistration current) =>
        string.Equals(initial.ClientId, current.ClientId, StringComparison.Ordinal) &&
        string.Equals(initial.OwnerScopeId, current.OwnerScopeId, StringComparison.Ordinal) &&
        initial.Status == current.Status &&
        initial.Scope == current.Scope &&
        initial.ExpiresAtUtc == current.ExpiresAtUtc &&
        initial.CredentialVersion == current.CredentialVersion &&
        initial.AggregateVersion == current.AggregateVersion &&
        string.Equals(
            initial.CredentialVerifier,
            current.CredentialVerifier,
            StringComparison.Ordinal) &&
        initial.DomainGrants.SequenceEqual(current.DomainGrants, StringComparer.Ordinal);

    private static AuthenticateResult Fail(ServiceClientAuthenticationOutcome outcome)
    {
        ServiceClientTelemetry.RecordAuthentication(outcome);
        return AuthenticateResult.Fail(InvalidCredentialMessage);
    }

    private sealed record ParsedServiceClientCredential(
        string ClientId,
        ServiceClientSecret Secret);
}
