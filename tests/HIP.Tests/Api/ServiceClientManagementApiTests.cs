using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;
using HIP.Web;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Api;

/// <summary>Exercises the privileged, owner-bound service-client management HTTP boundary.</summary>
[TestFixture]
public sealed class ServiceClientManagementApiTests
{
    private const string OwnerA = "service-client-owner-a";
    private const string OwnerB = "service-client-owner-b";
    private const string MutationRateLimitPolicy = "ServiceClientMutationPolicy";
    private const long MaximumCreateBodyBytes = 8 * 1024;
    private const long MaximumTransitionBodyBytes = 1024;

    private static readonly CreateServiceClientRequest ValidCreateRequest = new(
        "DNS verification worker",
        [ServiceClientScopeValues.DomainVerificationCheck],
        ["example.test"],
        30);

    private static readonly EndpointExpectation[] EndpointExpectations =
    [
        new(HttpMethods.Get, "/api/v1/admin/service-clients", "ListAdminServiceClients",
            [200, 400, 401, 403, 503], null, null, false,
            [AdminPolicies.CanViewServiceClients]),
        new(HttpMethods.Post, "/api/v1/admin/service-clients", "CreateAdminServiceClient",
            [201, 400, 401, 403, 409, 413, 429, 503], MaximumCreateBodyBytes, MutationRateLimitPolicy, true,
            [AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication]),
        new(HttpMethods.Post, "/api/v1/admin/service-clients/{clientId}/credentials/rotate",
            "RotateAdminServiceClientCredential",
            [200, 400, 401, 403, 404, 409, 410, 413, 429, 503], MaximumTransitionBodyBytes,
            MutationRateLimitPolicy, true,
            [AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication]),
        new(HttpMethods.Post, "/api/v1/admin/service-clients/{clientId}/revoke", "RevokeAdminServiceClient",
            [200, 400, 401, 403, 404, 409, 413, 429, 503], MaximumTransitionBodyBytes,
            MutationRateLimitPolicy, true,
            [AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication])
    ];

    [Test]
    public async Task Management_routes_enforce_the_owner_admin_view_and_manage_matrix()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var moderator = AdminClient(factory, AdminRoles.Moderator, "moderator-a");
        using var readOnly = AdminClient(factory, AdminRoles.ReadOnly, "readonly-a");
        using var owner = AdminClient(factory, AdminRoles.Owner, OwnerA);
        using var admin = AdminClient(factory, AdminRoles.Admin, OwnerB);

        using var anonymousList = await anonymous.GetAsync("/api/v1/admin/service-clients");
        using var moderatorList = await moderator.GetAsync("/api/v1/admin/service-clients");
        using var readOnlyList = await readOnly.GetAsync("/api/v1/admin/service-clients");
        using var ownerList = await owner.GetAsync("/api/v1/admin/service-clients");
        using var adminList = await admin.GetAsync("/api/v1/admin/service-clients");
        using var moderatorCreate = await moderator.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var readOnlyCreate = await readOnly.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var ownerCreate = await owner.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var adminCreate = await admin.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);

        Assert.Multiple(() =>
        {
            Assert.That(anonymousList.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(moderatorList.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(readOnlyList.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(ownerList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(adminList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(moderatorCreate.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(readOnlyCreate.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(ownerCreate.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(adminCreate.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(anonymousList.Headers.Location, Is.Null);
            Assert.That(moderatorList.Headers.Location, Is.Null);
        });
    }

    [Test]
    public async Task Create_uses_only_the_unique_principal_actor_and_returns_the_secret_once_with_no_store()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var client = AdminClient(factory, AdminRoles.Owner, OwnerA);
        const string spoofedJson = """
            {
              "displayName": "DNS verification worker",
              "scopes": ["domain-verification:check"],
              "domainGrants": ["example.test"],
              "lifetimeDays": 30,
              "actorId": "spoofed-actor",
              "ownerId": "spoofed-owner"
            }
            """;
        using var request = new StringContent(spoofedJson, Encoding.UTF8, "application/json");

        using var created = await client.PostAsync("/api/v1/admin/service-clients", request);
        var createdBody = await created.Content.ReadAsStringAsync();
        using var createdJson = JsonDocument.Parse(createdBody);
        var createdModel = JsonSerializer.Deserialize<ServiceClientOneTimeCredentialResponse>(
            createdBody,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var credential = createdJson.RootElement.GetProperty("credential").GetString();
        var clientId = createdJson.RootElement.GetProperty("client").GetProperty("clientId").GetString();
        using var listed = await client.GetAsync("/api/v1/admin/service-clients?limit=25");
        var listedBody = await listed.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(lifecycle.LastActorId, Is.EqualTo(OwnerA));
            Assert.That(lifecycle.LastOwnerId, Is.EqualTo(OwnerA));
            Assert.That(credential, Is.EqualTo($"{clientId}.test-only-one-time-value-1"));
            Assert.That(CountOccurrences(createdBody, "test-only-one-time-value-1"), Is.EqualTo(1));
            Assert.That(createdJson.RootElement.EnumerateObject().Count(property => property.NameEquals("credential")),
                Is.EqualTo(1));
            Assert.That(createdBody, Does.Not.Contain("spoofed-actor"));
            Assert.That(createdBody, Does.Not.Contain("spoofed-owner"));
            Assert.That(createdBody, Does.Not.Contain("credentialVerifier"));
            Assert.That(createdBody, Does.Not.Contain("ownerScope"));
            Assert.That(createdModel, Is.Not.Null);
            Assert.That(createdModel!.ToString(), Does.Not.Contain("test-only-one-time-value"));
            Assert.That(created.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(created.Headers.Pragma.Any(value => value.Name == "no-cache"), Is.True);
            Assert.That(listed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(listedBody, Does.Not.Contain("\"credential\":"));
            Assert.That(listedBody, Does.Not.Contain("test-only-one-time-value"));
            Assert.That(listedBody, Does.Not.Contain(OwnerA));
        });
    }

    [Test]
    public async Task Owner_lists_are_isolated_and_cross_owner_identifiers_are_non_disclosing()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var ownerA = AdminClient(factory, AdminRoles.Owner, OwnerA);
        using var ownerB = AdminClient(factory, AdminRoles.Owner, OwnerB);
        using var created = await ownerA.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var createdJson = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var clientId = createdJson.RootElement.GetProperty("client").GetProperty("clientId").GetString()!;

        using var ownerAList = await ownerA.GetAsync("/api/v1/admin/service-clients");
        using var ownerBList = await ownerB.GetAsync("/api/v1/admin/service-clients");
        using var ownerAListJson = JsonDocument.Parse(await ownerAList.Content.ReadAsStringAsync());
        using var ownerBListJson = JsonDocument.Parse(await ownerBList.Content.ReadAsStringAsync());
        using var wrongOwner = await ownerB.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/credentials/rotate",
            new { expectedAggregateVersion = 1 });
        using var unknown = await ownerB.PostAsJsonAsync(
            "/api/v1/admin/service-clients/hipc_v1_AAAAAAAAAAAAAAAAAAAAAA/credentials/rotate",
            new { expectedAggregateVersion = 1 });
        var wrongOwnerBody = await wrongOwner.Content.ReadAsStringAsync();
        var unknownBody = await unknown.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(ownerAList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(ownerBList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(ownerAListJson.RootElement.GetProperty("items").GetArrayLength(), Is.EqualTo(1));
            Assert.That(ownerBListJson.RootElement.GetProperty("items").GetArrayLength(), Is.Zero);
            Assert.That(wrongOwner.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(unknown.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(wrongOwnerBody, Is.EqualTo(unknownBody));
            Assert.That(wrongOwnerBody, Does.Not.Contain(clientId));
        });
    }

    [Test]
    public async Task Rotation_and_revocation_require_the_current_aggregate_version()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var client = AdminClient(factory, AdminRoles.Admin, OwnerA);
        using var created = await client.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var createdJson = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var clientId = createdJson.RootElement.GetProperty("client").GetProperty("clientId").GetString()!;

        using var rotated = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/credentials/rotate",
            new { expectedAggregateVersion = 1, actorId = "spoofed", ownerId = "spoofed" });
        var rotatedBody = await rotated.Content.ReadAsStringAsync();
        using var staleRotation = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/credentials/rotate",
            new { expectedAggregateVersion = 1 });
        using var revoked = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/revoke",
            new { expectedAggregateVersion = 2 });
        using var repeatedRevoke = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/revoke",
            new { expectedAggregateVersion = 3 });

        Assert.Multiple(() =>
        {
            Assert.That(rotated.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(rotated.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(rotatedBody, Does.Contain("test-only-one-time-value-2"));
            Assert.That(CountOccurrences(rotatedBody, "test-only-one-time-value-2"), Is.EqualTo(1));
            Assert.That(rotatedBody, Does.Not.Contain("test-only-one-time-value-1"));
            Assert.That(staleRotation.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(revoked.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(repeatedRevoke.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(lifecycle.LastActorId, Is.EqualTo(OwnerA));
            Assert.That(lifecycle.LastOwnerId, Is.EqualTo(OwnerA));
        });
    }

    [Test]
    public async Task Stable_lifecycle_outcomes_map_to_non_sensitive_http_statuses()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var client = AdminClient(factory, AdminRoles.Owner, OwnerA);
        using var created = await client.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var createdJson = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var clientId = createdJson.RootElement.GetProperty("client").GetProperty("clientId").GetString()!;

        lifecycle.RotationOutcome = ServiceClientLifecycleOutcome.Expired;
        using var expired = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/credentials/rotate",
            new { expectedAggregateVersion = 1 });
        lifecycle.RotationOutcome = ServiceClientLifecycleOutcome.Throttled;
        using var throttled = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/credentials/rotate",
            new { expectedAggregateVersion = 1 });
        var throttledBody = await throttled.Content.ReadAsStringAsync();
        lifecycle.RotationOutcome = null;
        lifecycle.RevocationOutcome = ServiceClientLifecycleOutcome.Conflict;
        using var conflict = await client.PostAsJsonAsync(
            $"/api/v1/admin/service-clients/{Uri.EscapeDataString(clientId)}/revoke",
            new { expectedAggregateVersion = 1 });
        lifecycle.ListOutcome = ServiceClientLifecycleOutcome.InvalidRequest;
        using var invalid = await client.GetAsync("/api/v1/admin/service-clients?limit=101");

        Assert.Multiple(() =>
        {
            Assert.That(expired.StatusCode, Is.EqualTo(HttpStatusCode.Gone));
            Assert.That(throttled.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
            Assert.That(throttledBody, Does.Contain(ServiceClientLifecycleMessages.Throttled));
            Assert.That(conflict.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(invalid.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        });
    }

    [Test]
    public async Task Cookie_session_mutations_require_antiforgery_and_list_bootstraps_the_token()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = CookieServiceClientFactory(baseFactory, lifecycle);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(CookieAdminAuthenticationHandler.ActorHeader, OwnerA);

        using var rejected = await client.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        using var tokenResponse = await client.GetAsync("/api/v1/admin/service-clients");
        var tokenHeader = tokenResponse.Headers.Single(header =>
            header.Key.Contains("VerificationToken", StringComparison.OrdinalIgnoreCase));
        using var acceptedRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/admin/service-clients")
        {
            Content = JsonContent.Create(ValidCreateRequest)
        };
        acceptedRequest.Headers.TryAddWithoutValidation(tokenHeader.Key, tokenHeader.Value.Single());
        using var accepted = await client.SendAsync(acceptedRequest);

        Assert.Multiple(() =>
        {
            Assert.That(rejected.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(tokenResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(tokenResponse.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(accepted.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        });
    }

    [Test]
    public async Task Unexpected_service_failures_return_one_generic_unavailable_response()
    {
        const string sensitiveMarker = "sensitive-service-client-storage-detail";
        var lifecycle = new FakeServiceClientLifecycleService
        {
            ExceptionToThrow = new InvalidOperationException(sensitiveMarker)
        };
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var client = AdminClient(factory, AdminRoles.Owner, OwnerA);

        using var listed = await client.GetAsync("/api/v1/admin/service-clients");
        using var created = await client.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
        var listBody = await listed.Content.ReadAsStringAsync();
        var createBody = await created.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(listed.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
            Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
            Assert.That(listBody, Is.EqualTo(createBody));
            Assert.That(listBody, Does.Contain(ServiceClientLifecycleMessages.Unavailable));
            Assert.That(listBody, Does.Not.Contain(sensitiveMarker));
        });
    }

    [Test]
    public async Task Endpoint_contracts_are_bounded_rate_limited_and_document_the_trust_boundary()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, new FakeServiceClientLifecycleService());
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => Normalize(endpoint.RoutePattern.RawText).StartsWith(
                "/api/v1/admin/service-clients",
                StringComparison.Ordinal))
            .ToArray();

        Assert.That(endpoints, Has.Length.EqualTo(EndpointExpectations.Length));
        foreach (var expectation in EndpointExpectations)
        {
            var endpoint = endpoints.Single(candidate =>
                Normalize(candidate.RoutePattern.RawText) == Normalize(expectation.Route) &&
                candidate.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(
                    expectation.Method,
                    StringComparer.OrdinalIgnoreCase) == true);
            var policies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
                .Select(metadata => metadata.Policy)
                .Where(policy => policy is not null)
                .ToArray();
            var statuses = endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>()
                .Select(metadata => metadata.StatusCode)
                .Order()
                .ToArray();

            Assert.Multiple(() =>
            {
                Assert.That(endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName,
                    Is.EqualTo(expectation.Name), expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IEndpointSummaryMetadata>()?.Summary,
                    Is.Not.Empty, expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IEndpointDescriptionMetadata>()?.Description,
                    Is.Not.Empty, expectation.Route);
                Assert.That(policies, Is.EquivalentTo(expectation.Policies), expectation.Route);
                Assert.That(statuses, Is.EqualTo(expectation.ProducedStatuses.Order()), expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize,
                    Is.EqualTo(expectation.MaximumBodyBytes), expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName,
                    Is.EqualTo(expectation.RateLimitPolicy), expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IAcceptsMetadata>() is not null,
                    Is.EqualTo(expectation.HasBody), expectation.Route);
            });
        }

        var descriptions = string.Join(' ', endpoints.Select(endpoint =>
            endpoint.Metadata.GetMetadata<IEndpointDescriptionMetadata>()?.Description));
        Assert.Multiple(() =>
        {
            Assert.That(descriptions, Does.Contain(ServiceClientScopeValues.DomainVerificationCheck));
            Assert.That(descriptions, Does.Contain(ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck));
            Assert.That(descriptions, Does.Contain("exact domain").IgnoreCase);
            Assert.That(descriptions, Does.Contain("one-time").IgnoreCase);
            Assert.That(descriptions, Does.Contain("does not prove safety").IgnoreCase);
            Assert.That(typeof(CreateServiceClientRequest).GetProperties().Select(property => property.Name),
                Is.EquivalentTo(new[] { "DisplayName", "Scopes", "DomainGrants", "LifetimeDays" }));
            Assert.That(typeof(ServiceClientExpectedVersionRequest).GetProperties().Select(property => property.Name),
                Is.EqualTo(new[] { "ExpectedAggregateVersion" }));
        });
    }

    [Test]
    public async Task Mutation_budget_is_actor_partitioned_and_rejects_the_eleventh_request()
    {
        var lifecycle = new FakeServiceClientLifecycleService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ServiceClientFactory(baseFactory, lifecycle);
        using var ownerA = AdminClient(factory, AdminRoles.Owner, OwnerA);
        using var ownerB = AdminClient(factory, AdminRoles.Owner, OwnerB);
        var statuses = new List<HttpStatusCode>();

        for (var index = 0; index < 11; index++)
        {
            using var response = await ownerA.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);
            statuses.Add(response.StatusCode);
        }

        using var otherOwner = await ownerB.PostAsJsonAsync("/api/v1/admin/service-clients", ValidCreateRequest);

        Assert.Multiple(() =>
        {
            Assert.That(statuses.Take(10), Is.All.EqualTo(HttpStatusCode.Created));
            Assert.That(statuses[10], Is.EqualTo(HttpStatusCode.TooManyRequests));
            Assert.That(otherOwner.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        });
    }

    private static HttpClient AdminClient(
        WebApplicationFactory<Program> factory,
        string role,
        string actorId)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, actorId);
        return client;
    }

    private static WebApplicationFactory<Program> ServiceClientFactory(
        HipWebApplicationFactory<Program> baseFactory,
        IServiceClientLifecycleService lifecycle) =>
        baseFactory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IServiceClientLifecycleService>();
            services.AddSingleton(lifecycle);
        }));

    private static WebApplicationFactory<Program> CookieServiceClientFactory(
        HipWebApplicationFactory<Program> baseFactory,
        IServiceClientLifecycleService lifecycle) =>
        baseFactory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IServiceClientLifecycleService>();
            services.AddSingleton(lifecycle);
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultAuthenticateScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultChallengeScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultForbidScheme = HipAuthenticationSchemes.SessionCookie;
                })
                .AddScheme<AuthenticationSchemeOptions, CookieAdminAuthenticationHandler>(
                    HipAuthenticationSchemes.SessionCookie,
                    _ => { });
        }));

    private static int CountOccurrences(string value, string marker) =>
        value.Split(marker, StringSplitOptions.None).Length - 1;

    private static string Normalize(string? route) => $"/{(route ?? string.Empty).Trim().Trim('/')}";

    private sealed record EndpointExpectation(
        string Method,
        string Route,
        string Name,
        int[] ProducedStatuses,
        long? MaximumBodyBytes,
        string? RateLimitPolicy,
        bool HasBody,
        string[] Policies);

    private sealed class CookieAdminAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string ActorHeader = "X-HIP-Test-Cookie-Actor";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(ActorHeader, out var values) ||
                string.IsNullOrWhiteSpace(values.ToString()))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var actor = values.ToString();
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, actor),
                    new Claim(ClaimTypes.Role, AdminRoles.Owner),
                    new Claim(HipAuthenticationClaimTypes.ActorId, actor)
                ],
                HipAuthenticationSchemes.OpenIdConnect,
                ClaimTypes.Name,
                ClaimTypes.Role));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(
                principal,
                HipAuthenticationSchemes.SessionCookie)));
        }
    }

    private sealed class FakeServiceClientLifecycleService : IServiceClientLifecycleService
    {
        private readonly Dictionary<string, List<ServiceClientResponse>> clientsByOwner =
            new(StringComparer.Ordinal);
        private int nextId;
        private int nextSecret;

        public Exception? ExceptionToThrow { get; set; }

        public ServiceClientLifecycleOutcome? ListOutcome { get; set; }

        public ServiceClientLifecycleOutcome? RotationOutcome { get; set; }

        public ServiceClientLifecycleOutcome? RevocationOutcome { get; set; }

        public string? LastActorId { get; private set; }

        public string? LastOwnerId { get; private set; }

        public Task<ServiceClientCreateResult> CreateAsync(
            string actorId,
            string ownerId,
            CreateServiceClientRequest request,
            CancellationToken cancellationToken)
        {
            ThrowIfConfigured();
            LastActorId = actorId;
            LastOwnerId = ownerId;
            var now = new DateTimeOffset(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);
            var opaqueIdBytes = new byte[16];
            nextId++;
            opaqueIdBytes[^1] = checked((byte)nextId);
            var client = new ServiceClientResponse(
                $"hipc_v1_{Encode(opaqueIdBytes)}",
                request.DisplayName,
                request.Scopes.Single(),
                request.DomainGrants.Order(StringComparer.Ordinal).ToArray(),
                ServiceClientStatus.Active,
                1,
                1,
                now,
                now,
                now.AddDays(request.LifetimeDays ?? 90),
                null);
            GetOwnerClients(ownerId).Add(client);
            var registration = new ServiceClientRegistrationResult(
                client,
                new ServiceClientSecret($"test-only-one-time-value-{++nextSecret}"));
            return Task.FromResult(new ServiceClientCreateResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                registration));
        }

        public Task<ServiceClientListResult> ListAsync(
            string ownerId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken)
        {
            ThrowIfConfigured();
            LastOwnerId = ownerId;
            if (ListOutcome is { } outcome)
            {
                return Task.FromResult(new ServiceClientListResult(outcome, Message(outcome), []));
            }

            var items = GetOwnerClients(ownerId).Take(pageSize).ToArray();
            return Task.FromResult(new ServiceClientListResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                items));
        }

        public Task<ServiceClientRotationResult> RotateCredentialAsync(
            string actorId,
            string ownerId,
            string clientId,
            long expectedAggregateVersion,
            CancellationToken cancellationToken)
        {
            ThrowIfConfigured();
            LastActorId = actorId;
            LastOwnerId = ownerId;
            if (RotationOutcome is { } outcome)
            {
                return Task.FromResult(new ServiceClientRotationResult(outcome, Message(outcome)));
            }

            var ownerClients = GetOwnerClients(ownerId);
            var index = ownerClients.FindIndex(client => string.Equals(client.ClientId, clientId, StringComparison.Ordinal));
            if (index < 0)
            {
                return Task.FromResult(new ServiceClientRotationResult(
                    ServiceClientLifecycleOutcome.NotFound,
                    ServiceClientLifecycleMessages.ResourceUnavailable));
            }

            var current = ownerClients[index];
            if (current.Status == ServiceClientStatus.Revoked)
            {
                return Task.FromResult(new ServiceClientRotationResult(
                    ServiceClientLifecycleOutcome.Revoked,
                    ServiceClientLifecycleMessages.Revoked));
            }

            if (current.AggregateVersion != expectedAggregateVersion)
            {
                return Task.FromResult(new ServiceClientRotationResult(
                    ServiceClientLifecycleOutcome.Conflict,
                    ServiceClientLifecycleMessages.Conflict));
            }

            var rotated = current with
            {
                CredentialVersion = current.CredentialVersion + 1,
                AggregateVersion = current.AggregateVersion + 1,
                CredentialChangedAtUtc = current.CredentialChangedAtUtc.AddMinutes(1)
            };
            ownerClients[index] = rotated;
            var registration = new ServiceClientRegistrationResult(
                rotated,
                new ServiceClientSecret($"test-only-one-time-value-{++nextSecret}"));
            return Task.FromResult(new ServiceClientRotationResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                registration));
        }

        public Task<ServiceClientRevocationResult> RevokeAsync(
            string actorId,
            string ownerId,
            string clientId,
            long expectedAggregateVersion,
            CancellationToken cancellationToken)
        {
            ThrowIfConfigured();
            LastActorId = actorId;
            LastOwnerId = ownerId;
            if (RevocationOutcome is { } outcome)
            {
                return Task.FromResult(new ServiceClientRevocationResult(outcome, Message(outcome)));
            }

            var ownerClients = GetOwnerClients(ownerId);
            var index = ownerClients.FindIndex(client => string.Equals(client.ClientId, clientId, StringComparison.Ordinal));
            if (index < 0)
            {
                return Task.FromResult(new ServiceClientRevocationResult(
                    ServiceClientLifecycleOutcome.NotFound,
                    ServiceClientLifecycleMessages.ResourceUnavailable));
            }

            var current = ownerClients[index];
            if (current.Status == ServiceClientStatus.Revoked)
            {
                return Task.FromResult(new ServiceClientRevocationResult(
                    ServiceClientLifecycleOutcome.Revoked,
                    ServiceClientLifecycleMessages.Revoked));
            }

            if (current.AggregateVersion != expectedAggregateVersion)
            {
                return Task.FromResult(new ServiceClientRevocationResult(
                    ServiceClientLifecycleOutcome.Conflict,
                    ServiceClientLifecycleMessages.Conflict));
            }

            var revokedAt = current.CredentialChangedAtUtc.AddMinutes(2);
            var revoked = current with
            {
                Status = ServiceClientStatus.Revoked,
                AggregateVersion = current.AggregateVersion + 1,
                RevokedAtUtc = revokedAt
            };
            ownerClients[index] = revoked;
            return Task.FromResult(new ServiceClientRevocationResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                revoked));
        }

        private List<ServiceClientResponse> GetOwnerClients(string ownerId)
        {
            if (!clientsByOwner.TryGetValue(ownerId, out var clients))
            {
                clients = [];
                clientsByOwner.Add(ownerId, clients);
            }

            return clients;
        }

        private void ThrowIfConfigured()
        {
            if (ExceptionToThrow is not null)
            {
                throw ExceptionToThrow;
            }
        }

        private static string Message(ServiceClientLifecycleOutcome outcome) => outcome switch
        {
            ServiceClientLifecycleOutcome.InvalidRequest => ServiceClientLifecycleMessages.InvalidRequest,
            ServiceClientLifecycleOutcome.NotFound => ServiceClientLifecycleMessages.ResourceUnavailable,
            ServiceClientLifecycleOutcome.Conflict => ServiceClientLifecycleMessages.Conflict,
            ServiceClientLifecycleOutcome.Expired => ServiceClientLifecycleMessages.Expired,
            ServiceClientLifecycleOutcome.Revoked => ServiceClientLifecycleMessages.Revoked,
            ServiceClientLifecycleOutcome.Throttled => ServiceClientLifecycleMessages.Throttled,
            _ => ServiceClientLifecycleMessages.Unavailable
        };

        private static string Encode(ReadOnlySpan<byte> value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
