using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using HIP.Application.Devices;
using HIP.Domain.Devices;
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

[TestFixture]
public sealed class ConsumerDeviceRegistrationApiTests
{
    private const string OwnerA = "consumer-device-owner-a";
    private const string OwnerB = "consumer-device-owner-b";
    private const string MutationRateLimitPolicy = "ConsumerDeviceMutationPolicy";
    private const long MaximumMutationBodyBytes = 8 * 1024;
    private static readonly DateTimeOffset TestNow =
        new(2026, 7, 20, 16, 0, 0, TimeSpan.Zero);

    private static readonly EndpointExpectation[] EndpointExpectations =
    [
        new(
            HttpMethods.Post,
            "/api/v1/consumer/devices/registration-challenges",
            "IssueConsumerDeviceRegistrationChallenge",
            [201, 400, 401, 403, 409, 413, 429, 503],
            HasRequestBody: true),
        new(
            HttpMethods.Post,
            "/api/v1/consumer/devices/registration-challenges/{challengeId}/responses",
            "CompleteConsumerDeviceRegistration",
            [200, 400, 401, 403, 404, 409, 410, 413, 422, 429, 503],
            HasRequestBody: true),
        new(
            HttpMethods.Get,
            "/api/v1/consumer/devices",
            "ListConsumerDevices",
            [200, 401, 403, 503],
            HasRequestBody: false),
        new(
            HttpMethods.Post,
            "/api/v1/consumer/devices/{deviceId}/revoke",
            "RevokeConsumerDevice",
            [200, 400, 401, 403, 404, 409, 413, 429, 503],
            HasRequestBody: false)
    ];

    [Test]
    public async Task Device_routes_require_the_consumer_policy_without_redirects()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory);
        using var anonymousClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        using var adminClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        adminClient.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Admin);
        adminClient.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "wrong-principal-admin");

        foreach (var endpoint in EndpointExpectations)
        {
            using var anonymousRequest = RequestFor(endpoint);
            using var adminRequest = RequestFor(endpoint);
            using var anonymousResponse = await anonymousClient.SendAsync(anonymousRequest);
            using var adminResponse = await adminClient.SendAsync(adminRequest);

            Assert.Multiple(() =>
            {
                Assert.That(anonymousResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), endpoint.Route);
                Assert.That(adminResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden), endpoint.Route);
                Assert.That(anonymousResponse.Headers.Location, Is.Null, endpoint.Route);
                Assert.That(adminResponse.Headers.Location, Is.Null, endpoint.Route);
            });
        }
    }

    [Test]
    public async Task Start_complete_list_and_revoke_are_owner_bound_and_privacy_safe()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Encode(key.ExportSubjectPublicKeyInfo());
        var startRequest = StartRequest(publicKey);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory);
        using var ownerA = ConsumerClient(factory, OwnerA);
        using var ownerB = ConsumerClient(factory, OwnerB);

        using var invalidStart = await ownerA.PostAsJsonAsync(
            "/api/v1/consumer/devices/registration-challenges",
            startRequest with { FriendlyName = string.Empty });
        using var started = await ownerA.PostAsJsonAsync(
            "/api/v1/consumer/devices/registration-challenges",
            startRequest);
        var challenge = await started.Content.ReadFromJsonAsync<DeviceRegistrationChallengeResponse>();
        Assert.That(challenge, Is.Not.Null);

        var signingInput = Decode(challenge!.SigningInput);
        var signature = Encode(key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var completionRequest = new CompleteDeviceRegistrationRequest(challenge.SigningInput, signature);
        var unknownChallengeId = DifferentOpaqueId(challenge.ChallengeId);

        using var wrongOwner = await ownerB.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}/responses",
            completionRequest);
        using var unknown = await ownerB.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(unknownChallengeId)}/responses",
            completionRequest);
        var wrongOwnerBody = await wrongOwner.Content.ReadAsStringAsync();
        var unknownBody = await unknown.Content.ReadAsStringAsync();

        using var invalidProof = await ownerA.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}/responses",
            completionRequest with { Signature = DifferentOpaqueId(signature) });
        using var completed = await ownerA.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}/responses",
            completionRequest);
        var completedBody = await completed.Content.ReadAsStringAsync();
        using var replay = await ownerA.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}/responses",
            completionRequest);

        using var ownerAList = await ownerA.GetAsync("/api/v1/consumer/devices");
        using var ownerBList = await ownerB.GetAsync("/api/v1/consumer/devices");
        var ownerAListBody = await ownerAList.Content.ReadAsStringAsync();
        var ownerBListBody = await ownerBList.Content.ReadAsStringAsync();
        using var ownerAListJson = JsonDocument.Parse(ownerAListBody);
        using var ownerBListJson = JsonDocument.Parse(ownerBListBody);

        using var wrongRevoke = await ownerB.PostAsync(
            $"/api/v1/consumer/devices/{Uri.EscapeDataString(challenge.DeviceId)}/revoke",
            content: null);
        using var unknownRevoke = await ownerB.PostAsync(
            $"/api/v1/consumer/devices/{Uri.EscapeDataString(DifferentOpaqueId(challenge.DeviceId))}/revoke",
            content: null);
        var wrongRevokeBody = await wrongRevoke.Content.ReadAsStringAsync();
        var unknownRevokeBody = await unknownRevoke.Content.ReadAsStringAsync();
        using var revoked = await ownerA.PostAsync(
            $"/api/v1/consumer/devices/{Uri.EscapeDataString(challenge.DeviceId)}/revoke",
            content: null);
        var revokedBody = await revoked.Content.ReadAsStringAsync();
        using var repeatedRevoke = await ownerA.PostAsync(
            $"/api/v1/consumer/devices/{Uri.EscapeDataString(challenge.DeviceId)}/revoke",
            content: null);

        Assert.Multiple(() =>
        {
            Assert.That(invalidStart.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(started.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(wrongOwner.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(unknown.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(wrongOwnerBody, Is.EqualTo(unknownBody));
            Assert.That(invalidProof.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
            Assert.That(completed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(replay.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(ownerAList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(ownerAListJson.RootElement.GetArrayLength(), Is.EqualTo(1));
            Assert.That(ownerBList.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(ownerBListJson.RootElement.GetArrayLength(), Is.Zero);
            Assert.That(wrongRevoke.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(unknownRevoke.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(wrongRevokeBody, Is.EqualTo(unknownRevokeBody));
            Assert.That(revoked.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(repeatedRevoke.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        foreach (var deviceBody in new[] { completedBody, ownerAListBody, revokedBody })
        {
            Assert.Multiple(() =>
            {
                Assert.That(deviceBody, Does.Not.Contain(OwnerA));
                Assert.That(deviceBody, Does.Not.Contain(publicKey));
                Assert.That(deviceBody, Does.Not.Contain(challenge.SigningInput));
                Assert.That(deviceBody, Does.Not.Contain(signature));
            });
        }
    }

    [Test]
    public async Task Expired_challenge_maps_to_gone()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var clock = new MutableTimeProvider(TestNow);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory, services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(clock);
        });
        using var client = ConsumerClient(factory, OwnerA);

        using var started = await client.PostAsJsonAsync(
            "/api/v1/consumer/devices/registration-challenges",
            StartRequest(Encode(key.ExportSubjectPublicKeyInfo())));
        var challenge = await started.Content.ReadFromJsonAsync<DeviceRegistrationChallengeResponse>();
        Assert.That(challenge, Is.Not.Null);
        clock.UtcNow = challenge!.ExpiresAtUtc;
        var signingInput = Decode(challenge.SigningInput);
        var signature = Encode(key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        using var response = await client.PostAsJsonAsync(
            $"/api/v1/consumer/devices/registration-challenges/{Uri.EscapeDataString(challenge.ChallengeId)}/responses",
            new CompleteDeviceRegistrationRequest(challenge.SigningInput, signature));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Gone));
    }

    [Test]
    public async Task Device_service_failures_return_one_safe_unavailable_body_without_exception_details()
    {
        const string sensitiveMarker = "sensitive-device-storage-detail-must-not-escape";
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory, services =>
        {
            services.RemoveAll<IDeviceRegistrationService>();
            services.AddSingleton<IDeviceRegistrationService>(
                new ThrowingDeviceRegistrationService(new InvalidOperationException(sensitiveMarker)));
        });
        using var client = ConsumerClient(factory, OwnerA);
        var requests = new[]
        {
            new HttpRequestMessage(HttpMethod.Post, "/api/v1/consumer/devices/registration-challenges")
            {
                Content = JsonContent.Create(new StartDeviceRegistrationRequest(
                    "Safe name",
                    DevicePlatformType.BrowserExtension,
                    "1.0",
                    Es256DeviceProofVerifier.Algorithm,
                    "public-key-placeholder"))
            },
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/v1/consumer/devices/registration-challenges/challenge-placeholder/responses")
            {
                Content = JsonContent.Create(new CompleteDeviceRegistrationRequest(
                    "signing-input-placeholder",
                    "signature-placeholder"))
            },
            new HttpRequestMessage(HttpMethod.Get, "/api/v1/consumer/devices"),
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/v1/consumer/devices/device-placeholder/revoke")
        };
        var bodies = new List<string>();

        foreach (var request in requests)
        {
            using (request)
            using (var response = await client.SendAsync(request))
            {
                bodies.Add(await response.Content.ReadAsStringAsync());
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
            }
        }

        Assert.Multiple(() =>
        {
            Assert.That(bodies.Distinct(StringComparer.Ordinal).ToArray(), Has.Length.EqualTo(1));
            Assert.That(bodies.All(body => body.Contains(
                DeviceRegistrationMessages.Unavailable,
                StringComparison.Ordinal)), Is.True);
            Assert.That(bodies.All(body => !body.Contains(sensitiveMarker, StringComparison.Ordinal)), Is.True);
        });
    }

    [Test]
    public async Task Cookie_authenticated_mutations_require_antiforgery_and_list_bootstraps_a_token()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = CookieConsumerFactory(baseFactory);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(CookieConsumerAuthenticationHandler.ConsumerHeader, OwnerA);
        var startRequest = StartRequest(Encode(key.ExportSubjectPublicKeyInfo()));

        using var rejected = await client.PostAsJsonAsync(
            "/api/v1/consumer/devices/registration-challenges",
            startRequest);
        using var tokenResponse = await client.GetAsync("/api/v1/consumer/devices");
        var tokenHeader = tokenResponse.Headers
            .Single(header => header.Key.Contains("VerificationToken", StringComparison.OrdinalIgnoreCase));
        var token = tokenHeader.Value.Single();
        using var acceptedRequest = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/v1/consumer/devices/registration-challenges")
        {
            Content = JsonContent.Create(startRequest)
        };
        acceptedRequest.Headers.TryAddWithoutValidation(tokenHeader.Key, token);
        using var accepted = await client.SendAsync(acceptedRequest);
        var rejectedBody = await rejected.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(rejected.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(rejectedBody, Does.Contain("antiforgery").IgnoreCase);
            Assert.That(tokenResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(tokenResponse.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(accepted.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        });
    }

    [Test]
    public async Task Device_route_metadata_is_complete_bounded_and_rate_limited()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory);
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => Normalize(endpoint.RoutePattern.RawText).StartsWith(
                "/api/v1/consumer/devices",
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
            var authorization = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
            var producedStatuses = endpoint.Metadata.GetOrderedMetadata<IProducesResponseTypeMetadata>()
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
                Assert.That(authorization.Select(metadata => metadata.Policy),
                    Does.Contain(ConsumerPolicies.CanUseConsumerPortal), expectation.Route);
                Assert.That(producedStatuses, Is.EqualTo(expectation.ProducedStatuses.Order()), expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize,
                    Is.EqualTo(expectation.Method == HttpMethods.Post ? MaximumMutationBodyBytes : null),
                    expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName,
                    Is.EqualTo(expectation.Method == HttpMethods.Post ? MutationRateLimitPolicy : null),
                    expectation.Route);
                Assert.That(endpoint.Metadata.GetMetadata<IAcceptsMetadata>() is not null,
                    Is.EqualTo(expectation.HasRequestBody), expectation.Route);
            });
        }
    }

    [Test]
    public async Task Mutation_rate_limit_rejects_the_eleventh_request_for_one_route_and_authenticated_owner()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory);
        using var client = ConsumerClient(factory, OwnerA);
        var invalidRequest = new StartDeviceRegistrationRequest(
            string.Empty,
            DevicePlatformType.BrowserExtension,
            string.Empty,
            Es256DeviceProofVerifier.Algorithm,
            string.Empty);
        var statuses = new List<HttpStatusCode>();

        for (var index = 0; index < 11; index++)
        {
            using var response = await client.PostAsJsonAsync(
                "/api/v1/consumer/devices/registration-challenges",
                invalidRequest);
            statuses.Add(response.StatusCode);
        }

        Assert.Multiple(() =>
        {
            Assert.That(statuses.Take(10), Is.All.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(statuses[10], Is.EqualTo(HttpStatusCode.TooManyRequests));
        });
    }

    [Test]
    public async Task Anonymous_and_other_consumer_requests_do_not_consume_an_authenticated_owners_budget()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = DeviceFactory(baseFactory);
        using var anonymousClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        using var ownerAClient = ConsumerClient(factory, OwnerA);
        using var ownerBClient = ConsumerClient(factory, OwnerB);
        var invalidRequest = new StartDeviceRegistrationRequest(
            string.Empty,
            DevicePlatformType.BrowserExtension,
            string.Empty,
            Es256DeviceProofVerifier.Algorithm,
            string.Empty);
        var anonymousStatuses = new List<HttpStatusCode>();
        var ownerAStatuses = new List<HttpStatusCode>();

        for (var index = 0; index < 10; index++)
        {
            using var anonymousResponse = await anonymousClient.PostAsJsonAsync(
                "/api/v1/consumer/devices/registration-challenges",
                invalidRequest);
            anonymousStatuses.Add(anonymousResponse.StatusCode);

            using var ownerAResponse = await ownerAClient.PostAsJsonAsync(
                "/api/v1/consumer/devices/registration-challenges",
                invalidRequest);
            ownerAStatuses.Add(ownerAResponse.StatusCode);
        }

        using var ownerBResponse = await ownerBClient.PostAsJsonAsync(
            "/api/v1/consumer/devices/registration-challenges",
            invalidRequest);

        Assert.Multiple(() =>
        {
            Assert.That(anonymousStatuses, Is.All.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(ownerAStatuses, Is.All.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(ownerBResponse.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        });
    }

    private static HttpClient ConsumerClient(WebApplicationFactory<Program> factory, string consumerId)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.ConsumerHeaderName, consumerId);
        return client;
    }

    private static WebApplicationFactory<Program> CookieConsumerFactory(
        HipWebApplicationFactory<Program> baseFactory) =>
        DeviceFactory(baseFactory, services =>
        {
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultAuthenticateScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultChallengeScheme = HipAuthenticationSchemes.SessionCookie;
                    options.DefaultForbidScheme = HipAuthenticationSchemes.SessionCookie;
                })
                .AddScheme<AuthenticationSchemeOptions, CookieConsumerAuthenticationHandler>(
                    HipAuthenticationSchemes.SessionCookie,
                    _ => { });
        });

    private static WebApplicationFactory<Program> DeviceFactory(
        HipWebApplicationFactory<Program> baseFactory,
        Action<IServiceCollection>? configureServices = null) =>
        baseFactory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IDeviceRegistrationRepository>();
            services.AddSingleton<IDeviceRegistrationRepository, InMemoryDeviceRegistrationRepository>();
            configureServices?.Invoke(services);
        }));

    private static StartDeviceRegistrationRequest StartRequest(string publicKey) => new(
        "Work browser",
        DevicePlatformType.BrowserExtension,
        "1.0.0",
        Es256DeviceProofVerifier.Algorithm,
        publicKey);

    private static HttpRequestMessage RequestFor(EndpointExpectation endpoint)
    {
        var path = endpoint.Route
            .Replace("{challengeId}", "challenge-matrix-value", StringComparison.Ordinal)
            .Replace("{deviceId}", "device-matrix-value", StringComparison.Ordinal);
        var request = new HttpRequestMessage(new HttpMethod(endpoint.Method), path);
        if (endpoint.Method == HttpMethods.Post && endpoint.HasRequestBody)
        {
            request.Content = JsonContent.Create(new { });
        }

        return request;
    }

    private static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(
            base64.Length + ((4 - base64.Length % 4) % 4),
            '='));
    }

    private static string DifferentOpaqueId(string value) =>
        value[..^1] + (value[^1] == 'a' ? "b" : "a");

    private static string Normalize(string? route) => $"/{(route ?? string.Empty).Trim().Trim('/')}";

    private sealed record EndpointExpectation(
        string Method,
        string Route,
        string Name,
        int[] ProducedStatuses,
        bool HasRequestBody);

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class CookieConsumerAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string ConsumerHeader = "X-HIP-Test-Cookie-Consumer";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(ConsumerHeader, out var values) ||
                string.IsNullOrWhiteSpace(values.ToString()))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var consumerId = values.ToString();
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, consumerId),
                    new Claim(HipAuthenticationClaimTypes.ConsumerId, consumerId)
                ],
                HipAuthenticationSchemes.OpenIdConnect));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(
                principal,
                HipAuthenticationSchemes.SessionCookie)));
        }
    }

    private sealed class ThrowingDeviceRegistrationService(Exception exception) : IDeviceRegistrationService
    {
        public Task<DeviceRegistrationChallengeResult> IssueChallengeAsync(
            string ownerId,
            StartDeviceRegistrationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromException<DeviceRegistrationChallengeResult>(exception);

        public Task<DeviceRegistrationCompletionResult> CompleteAsync(
            string ownerId,
            string challengeId,
            CompleteDeviceRegistrationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromException<DeviceRegistrationCompletionResult>(exception);

        public Task<IReadOnlyCollection<DeviceRegistrationDeviceResponse>> ListAsync(
            string ownerId,
            CancellationToken cancellationToken) =>
            Task.FromException<IReadOnlyCollection<DeviceRegistrationDeviceResponse>>(exception);

        public Task<DeviceRegistrationRevocationResult> RevokeAsync(
            string ownerId,
            string deviceId,
            CancellationToken cancellationToken) =>
            Task.FromException<DeviceRegistrationRevocationResult>(exception);
    }
}
