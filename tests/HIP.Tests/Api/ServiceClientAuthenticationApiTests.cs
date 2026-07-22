extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Application.ServiceClients;
using HIP.Application.SiteSafety;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.ServiceClients;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using System.Reflection;

namespace HIP.Tests.Api;

/// <summary>Exercises HIP-0205's standalone non-cookie service-client authentication boundary.</summary>
[TestFixture]
public sealed class ServiceClientAuthenticationApiTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);
    private const string OwnerScope =
        "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// <summary>Proves a valid exact-scope credential reaches the domain-control check without exposing its secret.</summary>
    [Test]
    public async Task Valid_service_client_can_check_an_exact_granted_domain()
    {
        var setup = ServiceClientSetup.Active(
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("EXAMPLE.COM.", setup.Credential);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("example.com"));
            Assert.That(body, Does.Contain("does not establish safety"));
            Assert.That(body, Does.Not.Contain(setup.Secret.Reveal()));
            Assert.That(setup.DomainService.LastDomain, Is.EqualTo("example.com"));
        });
    }

    /// <summary>Collapses unknown, wrong, expired, revoked, and storage-failure states into one challenge contract.</summary>
    [TestCase("unknown")]
    [TestCase("wrong-secret")]
    [TestCase("expired")]
    [TestCase("revoked")]
    [TestCase("storage-unavailable")]
    public async Task Invalid_or_unavailable_credentials_return_the_same_stable_401(string scenario)
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        var credential = setup.Credential;
        switch (scenario)
        {
            case "unknown":
                setup.Repository.SetSnapshots((ServiceClientRegistration?)null);
                break;
            case "wrong-secret":
                var wrongSecret = new CryptographicServiceClientCredentialGenerator().GenerateSecret();
                credential = $"{setup.ClientId}.{wrongSecret.Reveal()}";
                break;
            case "expired":
                setup.Repository.SetSnapshots(setup.RegistrationWithLifetime(Now.AddDays(-10), Now.AddSeconds(-1)));
                break;
            case "revoked":
                setup.Repository.SetSnapshots(setup.Registration.Revoke(Now.AddSeconds(-1)));
                break;
            case "storage-unavailable":
                setup.Repository.Failure = new InvalidOperationException("test storage failure");
                break;
        }

        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", credential);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        AssertStableUnauthorized(response, body, setup);
        Assert.Multiple(() =>
        {
            Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
            Assert.That(
                setup.Protector.VerifyCalls,
                Is.EqualTo(scenario == "storage-unavailable" ? 0 : 1),
                "Canonical unknown, wrong, expired, and revoked credentials must each perform one verifier call.");
        });
    }

    /// <summary>Rejects malformed and ambiguous header forms only after reserving the pre-verification budget.</summary>
    [TestCase("Bearer abc")]
    [TestCase("HIP-Service")]
    [TestCase("HIP-Service  value")]
    [TestCase("HIP-Service hipc_v1_invalid.hips_v1_invalid")]
    [TestCase("HIP-Service hipc_v1_AAAAAAAAAAAAAAAAAAAAAA.hips_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.extra")]
    [TestCase("HIP-Service hipc_v1_AAAAAAAAAAAAAAAAAAAAAA.HIPS_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Malformed_authorization_is_generic_and_never_reaches_storage_or_verification(string authorization)
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com");
        request.Headers.TryAddWithoutValidation("Authorization", authorization);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        AssertStableUnauthorized(response, body, setup);
        Assert.Multiple(() =>
        {
            Assert.That(setup.Limiter.Calls, Is.EqualTo(1));
            Assert.That(setup.Repository.Reads, Is.EqualTo(0));
            Assert.That(setup.Protector.VerifyCalls, Is.EqualTo(0));
        });
    }

    /// <summary>Rejects duplicate Authorization values without selecting a more permissive credential.</summary>
    [Test]
    public async Task Duplicate_authorization_headers_are_rejected_as_ambiguous()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            [$"HIP-Service {setup.Credential}", $"HIP-Service {setup.Credential}"]);

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(setup.Limiter.Calls, Is.EqualTo(1));
        Assert.That(setup.Repository.Reads, Is.EqualTo(0));
    }

    /// <summary>Prevents arbitrary Authorization input from falling back to powerful local Development headers.</summary>
    [Test]
    public async Task Any_authorization_header_exclusively_pins_the_service_scheme()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer not-a-service-credential");
        request.Headers.TryAddWithoutValidation("X-HIP-Admin-Role", "Admin");
        request.Headers.TryAddWithoutValidation("X-HIP-Admin-User", "api-admin");

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
    }

    /// <summary>Confirms cookies and legacy-looking API-key headers are never service credentials.</summary>
    [Test]
    public async Task Cookies_and_x_hip_api_key_do_not_authenticate()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com");
        request.Headers.TryAddWithoutValidation("Cookie", "hip-session=fake");
        request.Headers.TryAddWithoutValidation("X-HIP-API-Key", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(response.Headers.WwwAuthenticate.Single().Scheme, Is.EqualTo("HIP-Service"));
            Assert.That(setup.Limiter.Calls, Is.EqualTo(0));
            Assert.That(setup.Repository.Reads, Is.EqualTo(0));
        });
    }

    /// <summary>Uses case-insensitive scheme matching while keeping the complete credential case-sensitive.</summary>
    [Test]
    public async Task Scheme_is_case_insensitive_but_credential_is_case_sensitive()
    {
        var valid = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var validHost = CreateHost(valid);
        using var validClient = validHost.Factory.CreateClient();
        using var validRequest = DomainCheckRequest("example.com");
        validRequest.Headers.TryAddWithoutValidation("Authorization", $"hip-service {valid.Credential}");
        var validResponse = await validClient.SendAsync(validRequest);

        var invalid = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        var changedSecretCharacters = invalid.Secret.Reveal().ToCharArray();
        changedSecretCharacters[^1] = changedSecretCharacters[^1] == 'A' ? 'Q' : 'A';
        var changedSecret = new string(changedSecretCharacters);
        await using var invalidHost = CreateHost(invalid);
        using var invalidClient = invalidHost.Factory.CreateClient();
        using var invalidRequest = DomainCheckRequest(
            "example.com",
            $"{invalid.ClientId}.{changedSecret}");
        var invalidResponse = await invalidClient.SendAsync(invalidRequest);

        Assert.Multiple(() =>
        {
            Assert.That(validResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(invalidResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        });
    }

    /// <summary>Returns 403 for authenticated clients that lack the route's exact operation scope.</summary>
    [Test]
    public async Task Wrong_scope_is_forbidden_after_successful_authentication()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.SiteSafetyExternalEvidenceCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
    }

    /// <summary>Makes the second advertised least-privilege scope usable without treating provider evidence as a score.</summary>
    [Test]
    public async Task Valid_external_evidence_scope_can_check_an_exact_granted_domain()
    {
        var setup = ServiceClientSetup.Active(
            ServiceClientScope.SiteSafetyExternalEvidenceCheck,
            ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = ExternalEvidenceRequest(
            "https://EXAMPLE.COM/path?private=test-secret",
            setup.Credential);
        request.Headers.TryAddWithoutValidation("X-HIP-Instance-Id", "attacker-selected-settings-scope");

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("example.com"));
            Assert.That(body, Does.Not.Contain("test-secret"));
            Assert.That(setup.EvidenceCollector.Calls, Is.EqualTo(1));
            Assert.That(
                setup.EvidenceSettingsStore.GetCalls,
                Is.EqualTo(0),
                "Service credentials must use host provider defaults rather than client-selected settings scopes.");
        });
    }

    /// <summary>Allows a scoped service client to enqueue durable work without executing providers on the request path.</summary>
    [Test]
    public async Task Valid_external_evidence_scope_can_queue_and_read_owner_scoped_job()
    {
        var setup = ServiceClientSetup.Active(
            ServiceClientScope.SiteSafetyExternalEvidenceCheck,
            ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = ExternalEvidenceJobRequest(
            "https://EXAMPLE.COM/private?password=secret",
            setup.Credential);
        request.Headers.TryAddWithoutValidation("X-HIP-Instance-Id", "attacker-selected-settings-scope");

        var accepted = await client.SendAsync(request);
        var acceptedBody = await accepted.Content.ReadAsStringAsync();
        using var lookup = new HttpRequestMessage(HttpMethod.Get, accepted.Headers.Location);
        lookup.Headers.TryAddWithoutValidation("Authorization", $"HIP-Service {setup.Credential}");
        var stored = await client.SendAsync(lookup);

        Assert.Multiple(() =>
        {
            Assert.That(accepted.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
            Assert.That(acceptedBody, Does.Contain("example.com"));
            Assert.That(acceptedBody, Does.Not.Contain("password=secret"));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(setup.EvidenceCollector.Calls, Is.Zero);
            Assert.That(setup.EvidenceSettingsStore.GetCalls, Is.Zero);
        });
    }

    /// <summary>Rejects an external-evidence client before provider settings or provider work for the wrong resource.</summary>
    [TestCase(ServiceClientScope.SiteSafetyExternalEvidenceCheck, "https://www.example.com/")]
    [TestCase(ServiceClientScope.DomainVerificationCheck, "https://example.com/")]
    public async Task External_evidence_wrong_domain_or_wrong_scope_is_forbidden(
        ServiceClientScope scope,
        string url)
    {
        var setup = ServiceClientSetup.Active(scope, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = ExternalEvidenceRequest(url, setup.Credential);

        var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(setup.EvidenceCollector.Calls, Is.EqualTo(0));
        });
    }

    /// <summary>Applies ordinal exact resource grants after canonical request normalization.</summary>
    [TestCase("example.com", "other.com")]
    [TestCase("example.com", "www.example.com")]
    [TestCase("www.example.com", "example.com")]
    public async Task Unrelated_parent_and_child_domains_are_forbidden(
        string grantedDomain,
        string requestedDomain)
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, [grantedDomain]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest(requestedDomain, setup.Credential);

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
    }

    /// <summary>Invalidates the old secret immediately after a successful credential rotation.</summary>
    [Test]
    public async Task Old_secret_after_rotation_is_unauthorized()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        var replacement = new CryptographicServiceClientCredentialGenerator().GenerateSecret();
        var rotated = setup.Registration.RotateCredential(
            setup.Protector.Protect(setup.ClientId, replacement),
            Now.AddSeconds(-1));
        setup.Repository.SetSnapshots(rotated);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
    }

    /// <summary>Rejects a request when rotation or revocation wins between verification and the security-state re-read.</summary>
    [TestCase("rotate")]
    [TestCase("revoke")]
    public async Task Verify_then_lifecycle_change_is_unauthorized(string transition)
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        var changed = transition == "rotate"
            ? setup.Registration.RotateCredential(
                setup.Protector.Protect(
                    setup.ClientId,
                    new CryptographicServiceClientCredentialGenerator().GenerateSecret()),
                Now.AddSeconds(-1))
            : setup.Registration.Revoke(Now.AddSeconds(-1));
        setup.Repository.SetSnapshots(setup.Registration, changed);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(setup.Repository.Reads, Is.EqualTo(2));
            Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
        });
    }

    /// <summary>Rejects a repository snapshot whose aggregate identifier does not match the presented client ID.</summary>
    [Test]
    public async Task Misbound_repository_snapshot_is_unauthorized_after_equal_verification_work()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        var misbound = ServiceClientRegistration.Create(
            new CryptographicServiceClientCredentialGenerator().GenerateClientId(),
            OwnerScope,
            setup.Registration.DisplayName,
            setup.Registration.Scope,
            setup.Registration.DomainGrants,
            setup.Registration.CredentialVerifier,
            setup.Registration.CreatedAtUtc,
            setup.Registration.ExpiresAtUtc);
        setup.Repository.SetSnapshots(misbound);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(setup.Protector.VerifyCalls, Is.EqualTo(1));
            Assert.That(setup.DomainService.Calls, Is.EqualTo(0));
        });
    }

    /// <summary>Fails closed before repository or PBKDF work when the distributed budget rejects or is unavailable.</summary>
    [TestCase(false)]
    [TestCase(true)]
    public async Task Limiter_rejection_or_backend_failure_precedes_repository_and_verifier(bool backendFailure)
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        setup.Limiter.Allowed = false;
        setup.Limiter.Failure = backendFailure ? new InvalidOperationException("test limiter failure") : null;
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(setup.Limiter.Calls, Is.EqualTo(1));
            Assert.That(setup.Repository.Reads, Is.EqualTo(0));
            Assert.That(setup.Protector.VerifyCalls, Is.EqualTo(0));
        });
    }

    /// <summary>Emits only the bounded service claims and no human administrator identity claims.</summary>
    [Test]
    public async Task Service_identity_contains_only_protocol_claims_and_no_human_roles_or_actor()
    {
        var setup = ServiceClientSetup.Active(
            ServiceClientScope.DomainVerificationCheck,
            ["example.com", "example.net"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com", setup.Credential);

        var response = await client.SendAsync(request);
        var identity = setup.DomainService.LastPrincipal!.Identities.Single(item => item.IsAuthenticated);
        var claimTypes = identity.Claims.Select(claim => claim.Type).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(identity.AuthenticationType, Is.EqualTo("HIP-Service"));
            Assert.That(claimTypes, Is.EquivalentTo(new[]
            {
                "hip_service_client",
                "hip_service_client_id",
                "hip_service_scope",
                "hip_service_domain",
                "hip_service_domain",
                "hip_service_owner_scope",
                "hip_service_credential_version"
            }));
            Assert.That(claimTypes, Does.Not.Contain(ClaimTypes.Role));
            Assert.That(claimTypes, Does.Not.Contain("hip_actor_id"));
            Assert.That(claimTypes, Does.Not.Contain("hip_mfa"));
        });
    }

    /// <summary>Preserves the exact existing local Development administrator policy as the alternative branch.</summary>
    [Test]
    public async Task Development_admin_remains_compatible_without_an_authorization_header()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        using var client = host.Factory.CreateClient();
        using var request = DomainCheckRequest("example.com");
        request.Headers.TryAddWithoutValidation("X-HIP-Admin-Role", "Admin");
        request.Headers.TryAddWithoutValidation("X-HIP-Admin-User", "api-admin");

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(setup.Limiter.Calls, Is.EqualTo(0));
    }

    /// <summary>Confirms a production-like standalone host never treats a missing header as an administrator identity.</summary>
    [Test]
    public async Task Production_no_header_returns_the_service_challenge()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        using var host = await new HostBuilder()
            .UseEnvironment(Environments.Production)
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    RegisterApiServiceAuthorizationByReflection(services);
                    services.RemoveAll<IServiceClientRepository>();
                    services.RemoveAll<IServiceClientSecretProtector>();
                    services.RemoveAll<IServiceClientAuthenticationAttemptLimiter>();
                    services.RemoveAll<TimeProvider>();
                    services.AddSingleton<IServiceClientRepository>(setup.Repository);
                    services.AddSingleton<IServiceClientSecretProtector>(setup.Protector);
                    services.AddSingleton<IServiceClientAuthenticationAttemptLimiter>(setup.Limiter);
                    services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
                });
                webHost.Configure(application =>
                {
                    application.UseRouting();
                    application.UseAuthentication();
                    application.UseAuthorization();
                    application.UseEndpoints(endpoints => endpoints.MapGet(
                            "/protected",
                            () => Results.Ok())
                        .RequireAuthorization("CanCheckDomainVerification"));
                });
            })
            .StartAsync();
        using var client = host.GetTestClient();

        var response = await client.GetAsync("/protected");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(response.Headers.WwwAuthenticate.Select(item => item.ToString()),
                Is.EqualTo(new[] { "HIP-Service" }));
            Assert.That(setup.Limiter.Calls, Is.EqualTo(0));
        });
    }

    /// <summary>Pins endpoint metadata and public documentation to the composite operation policy.</summary>
    [Test]
    public async Task Domain_check_metadata_documents_authentication_scope_and_failure_contracts()
    {
        var setup = ServiceClientSetup.Active(ServiceClientScope.DomainVerificationCheck, ["example.com"]);
        await using var host = CreateHost(setup);
        var endpoint = host.Factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(item => string.Equals(
                "/" + item.RoutePattern.RawText?.TrimStart('/'),
                "/api/v1/domain-verification/check",
                StringComparison.Ordinal));
        var policies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(item => item.Policy)
            .Where(item => item is not null)
            .ToArray();
        var statuses = endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>()
            .Select(item => item.StatusCode)
            .ToArray();
        var description = endpoint.Metadata.GetMetadata<IEndpointDescriptionMetadata>()?.Description;

        Assert.Multiple(() =>
        {
            Assert.That(policies, Is.EqualTo(new[] { "CanCheckDomainVerification" }));
            Assert.That(statuses, Does.Contain(StatusCodes.Status401Unauthorized));
            Assert.That(statuses, Does.Contain(StatusCodes.Status403Forbidden));
            Assert.That(description, Does.Contain(ServiceClientScopeValues.DomainVerificationCheck));
            Assert.That(description, Does.Contain("exact").IgnoreCase);
            Assert.That(description, Does.Contain("does not mark a website safe or trusted"));
        });
    }

    /// <summary>Guards against adding untrusted credential material to explicit API authentication logs or bodies.</summary>
    [Test]
    public void Authentication_source_has_no_explicit_credential_logging_or_response_echo()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "HIP.ApiService",
            "Security",
            "ApiServiceServiceClientAuthentication.cs"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Not.Contain(".Log"));
            Assert.That(source, Does.Not.Contain("Response.Write"));
            Assert.That(source, Does.Not.Contain("Request.Headers.Authorization"));
            Assert.That(source, Does.Not.Contain("X-HIP-API-Key"));
            Assert.That(source, Does.Not.Contain("Cookie"));
        });
    }

    private static ConfiguredApiHost CreateHost(ServiceClientSetup setup)
    {
        var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        var configuredFactory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IServiceClientRepository>();
                services.RemoveAll<IServiceClientSecretProtector>();
                services.RemoveAll<IServiceClientAuthenticationAttemptLimiter>();
                services.RemoveAll<IDomainVerificationService>();
                services.RemoveAll<IExternalSiteEvidenceSettingsStore>();
                services.RemoveAll<IExternalSiteEvidenceCollector>();
                services.RemoveAll<TimeProvider>();
                services.AddHttpContextAccessor();
                services.AddSingleton<IServiceClientRepository>(setup.Repository);
                services.AddSingleton<IServiceClientSecretProtector>(setup.Protector);
                services.AddSingleton<IServiceClientAuthenticationAttemptLimiter>(setup.Limiter);
                services.AddSingleton<IDomainVerificationService>(provider =>
                {
                    setup.DomainService.HttpContextAccessor = provider.GetRequiredService<IHttpContextAccessor>();
                    return setup.DomainService;
                });
                services.AddSingleton<IExternalSiteEvidenceSettingsStore>(setup.EvidenceSettingsStore);
                services.AddSingleton<IExternalSiteEvidenceCollector>(setup.EvidenceCollector);
                services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
            }));
        return new ConfiguredApiHost(baseFactory, configuredFactory);
    }

    private static HttpRequestMessage DomainCheckRequest(string domain, string? credential = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/domain-verification/check")
        {
            Content = JsonContent.Create(new { Domain = domain, ExpectedToken = "test-token" })
        };
        if (credential is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"HIP-Service {credential}");
        }

        return request;
    }

    private static HttpRequestMessage ExternalEvidenceRequest(string url, string credential)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/site-safety/external-evidence/check")
        {
            Content = JsonContent.Create(new { Url = url })
        };
        request.Headers.TryAddWithoutValidation("Authorization", $"HIP-Service {credential}");
        return request;
    }

    private static HttpRequestMessage ExternalEvidenceJobRequest(string url, string credential)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/site-safety/external-evidence/jobs")
        {
            Content = JsonContent.Create(new { Url = url })
        };
        request.Headers.TryAddWithoutValidation("Authorization", $"HIP-Service {credential}");
        return request;
    }

    private static void AssertStableUnauthorized(
        HttpResponseMessage response,
        string body,
        ServiceClientSetup setup)
    {
        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(response.Headers.WwwAuthenticate.Select(item => item.ToString()),
                Is.EqualTo(new[] { "HIP-Service" }));
            Assert.That(body, Does.Not.Contain(setup.ClientId));
            Assert.That(body, Does.Not.Contain(setup.Secret.Reveal()));
            Assert.That(body, Does.Not.Contain(setup.Registration.CredentialVerifier));
        });
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("HIP repository root was not found.");
    }

    private static void RegisterApiServiceAuthorizationByReflection(IServiceCollection services)
    {
        var extensions = typeof(ApiServiceAlias::ApiServiceProgram).Assembly.GetType(
            "HIP.ApiService.Security.ApiServiceAuthorizationExtensions",
            throwOnError: true)!;
        var registration = extensions.GetMethod(
            "AddHipApiServiceAuthorization",
            BindingFlags.Public | BindingFlags.Static) ??
            throw new MissingMethodException(extensions.FullName, "AddHipApiServiceAuthorization");
        _ = registration.Invoke(null, [services]);
    }

    private sealed record ServiceClientSetup(
        string ClientId,
        ServiceClientSecret Secret,
        string Credential,
        SequencedServiceClientRepository Repository,
        FastSecretProtector Protector,
        RecordingAttemptLimiter Limiter,
        CapturingDomainVerificationService DomainService,
        RecordingExternalEvidenceSettingsStore EvidenceSettingsStore,
        RecordingExternalEvidenceCollector EvidenceCollector,
        ServiceClientRegistration Registration)
    {
        public static ServiceClientSetup Active(
            ServiceClientScope scope,
            IReadOnlyList<string> domains)
        {
            var generator = new CryptographicServiceClientCredentialGenerator();
            var clientId = generator.GenerateClientId();
            var secret = generator.GenerateSecret();
            var protector = new FastSecretProtector();
            var registration = ServiceClientRegistration.Create(
                clientId,
                OwnerScope,
                "API integration test",
                scope,
                domains,
                protector.Protect(clientId, secret),
                Now.AddDays(-1),
                Now.AddDays(30));
            return new ServiceClientSetup(
                clientId,
                secret,
                $"{clientId}.{secret.Reveal()}",
                new SequencedServiceClientRepository(registration),
                protector,
                new RecordingAttemptLimiter(),
                new CapturingDomainVerificationService(),
                new RecordingExternalEvidenceSettingsStore(),
                new RecordingExternalEvidenceCollector(),
                registration);
        }

        public ServiceClientRegistration RegistrationWithLifetime(
            DateTimeOffset createdAtUtc,
            DateTimeOffset expiresAtUtc) =>
            ServiceClientRegistration.Create(
                ClientId,
                OwnerScope,
                Registration.DisplayName,
                Registration.Scope,
                Registration.DomainGrants,
                Registration.CredentialVerifier,
                createdAtUtc,
                expiresAtUtc);
    }

    private sealed class FastSecretProtector : IServiceClientSecretProtector
    {
        public int VerifyCalls { get; private set; }

        public string Protect(string clientId, ServiceClientSecret secret) =>
            "test-sha256-v1$" + Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(clientId + "\0" + secret.Reveal())));

        public bool Verify(
            string clientId,
            ServiceClientSecret presentedSecret,
            string credentialVerifier)
        {
            VerifyCalls++;
            return string.Equals(
                Protect(clientId, presentedSecret),
                credentialVerifier,
                StringComparison.Ordinal);
        }
    }

    private sealed class RecordingAttemptLimiter : IServiceClientAuthenticationAttemptLimiter
    {
        public int Calls { get; private set; }
        public bool Allowed { get; set; } = true;
        public Exception? Failure { get; set; }

        public ValueTask<bool> TryAcquireAsync(
            string sourceIdentity,
            string apparentClientId,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            return Failure is null
                ? ValueTask.FromResult(Allowed)
                : ValueTask.FromException<bool>(Failure);
        }
    }

    private sealed class SequencedServiceClientRepository(params ServiceClientRegistration?[] registrations)
        : IServiceClientRepository
    {
        private ServiceClientRegistration?[] snapshots = registrations;
        private int reads;

        public int Reads => reads;
        public Exception? Failure { get; set; }

        public void SetSnapshots(params ServiceClientRegistration?[] values)
        {
            snapshots = values;
            reads = 0;
        }

        public Task<ServiceClientRegistration?> GetAsync(string clientId, CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                return Task.FromException<ServiceClientRegistration?>(Failure);
            }

            var index = Math.Min(Interlocked.Increment(ref reads) - 1, snapshots.Length - 1);
            return Task.FromResult(snapshots[index]);
        }

        public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
            string ownerScopeId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ServiceClientSaveOutcome> TrySaveAsync(
            ServiceClientTransitionBatch transition,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class CapturingDomainVerificationService : IDomainVerificationService
    {
        public IHttpContextAccessor? HttpContextAccessor { get; set; }
        public string? LastDomain { get; private set; }
        public ClaimsPrincipal? LastPrincipal { get; private set; }
        public int Calls { get; private set; }

        public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(
            string domain,
            string expectedToken,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastDomain = domain;
            LastPrincipal = HttpContextAccessor?.HttpContext?.User;
            return Task.FromResult(new DomainVerificationCheckResult(
                domain,
                $"_hip.{domain}",
                DomainVerificationCheckStatus.Verified,
                Now,
                "Domain control was verified; this does not establish safety or trust."));
        }

        public Task<DomainVerificationRequest> StartAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest> GetOrStartAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest?> GetAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest> VerifyAsync(
            string domain,
            VerificationMethod method,
            string token,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRetryResult> RetryAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest> RevokeAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingExternalEvidenceCollector : IExternalSiteEvidenceCollector
    {
        public int Calls { get; private set; }

        public Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<IReadOnlyCollection<SiteSafetyEvidence>>([]);
        }
    }

    private sealed class RecordingExternalEvidenceSettingsStore : IExternalSiteEvidenceSettingsStore
    {
        public int GetCalls { get; private set; }

        public Task<ExternalSiteEvidenceOptions?> GetAsync(
            string scopeKey,
            CancellationToken cancellationToken)
        {
            GetCalls++;
            return Task.FromResult<ExternalSiteEvidenceOptions?>(null);
        }

        public Task<ExternalSiteEvidenceOptions> SaveAsync(
            string scopeKey,
            ExternalSiteEvidenceOptions options,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class ConfiguredApiHost(
        HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram> baseFactory,
        WebApplicationFactory<ApiServiceAlias::ApiServiceProgram> factory) : IAsyncDisposable
    {
        public WebApplicationFactory<ApiServiceAlias::ApiServiceProgram> Factory { get; } = factory;

        public async ValueTask DisposeAsync()
        {
            await Factory.DisposeAsync();
            await baseFactory.DisposeAsync();
        }
    }
}
