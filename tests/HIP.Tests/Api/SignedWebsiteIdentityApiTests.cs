using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

public sealed class SignedWebsiteIdentityApiTests
{
    [Test]
    public async Task Website_register_api_requires_admin()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/identity/websites/register", new WebsiteIdentityRegistrationRequest(
            "signed-api.example",
            "Signed API",
            VerificationMethod.WellKnownHipJson));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Website_identity_can_be_registered_and_read_by_domain()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/identity/websites/register", new WebsiteIdentityRegistrationRequest(
            "signed-api.example",
            "Signed API",
            VerificationMethod.WellKnownHipJson));
        var registered = await response.Content.ReadFromJsonAsync<WebsiteIdentityRegistrationResponse>();
        var read = await client.GetFromJsonAsync<WebsiteIdentity>("/api/v1/identity/websites/signed-api.example");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(registered!.WebsiteIdentity.Domain, Is.EqualTo("signed-api.example"));
        Assert.That(read!.HipIdentityId, Is.EqualTo("hip:web:signed-api.example"));
    }

    [Test]
    public async Task Website_pending_duplicate_registration_returns_safe_recovery_without_reissuing_private_key()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var first = await client.PostAsJsonAsync(
            "/api/v1/identity/websites/register",
            new WebsiteIdentityRegistrationRequest(
                "duplicate-registration.example",
                "First registration",
                VerificationMethod.WellKnownHipJson));
        var winner = await first.Content.ReadFromJsonAsync<WebsiteIdentityRegistrationResponse>();

        var duplicate = await client.PostAsJsonAsync(
            "/api/v1/identity/websites/register",
            new WebsiteIdentityRegistrationRequest(
                "duplicate-registration.example",
                "Replacement attempt",
                VerificationMethod.WellKnownHipJson));
        var recovery = await duplicate.Content.ReadFromJsonAsync<WebsiteIdentityRegistrationResponse>();
        var stored = await client.GetFromJsonAsync<WebsiteIdentity>(
            "/api/v1/identity/websites/duplicate-registration.example");

        Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(duplicate.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(recovery!.IsRecovery, Is.True);
        Assert.That(recovery.RequiresSigningKeyRotation, Is.True);
        Assert.That(recovery.DevelopmentPrivateKey, Is.Null);
        Assert.That(
            stored!.PublicKeys.Single().PublicKey,
            Is.EqualTo(winner!.WebsiteIdentity.PublicKeys.Single().PublicKey));
    }

    [Test]
    public async Task Concurrent_website_registration_elects_one_key_and_writes_one_activation_audit()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var attempts = Enumerable.Range(0, 8)
            .Select(index => client.PostAsJsonAsync(
                "/api/v1/identity/websites/register",
                new WebsiteIdentityRegistrationRequest(
                    "concurrent-registration.example",
                    $"Concurrent registration {index}",
                    VerificationMethod.WellKnownHipJson)))
            .ToArray();

        var responses = await Task.WhenAll(attempts);
        var successes = responses.Where(response => response.StatusCode == HttpStatusCode.OK).ToArray();
        var conflicts = responses.Where(response => response.StatusCode == HttpStatusCode.Conflict).ToArray();
        var unexpected = responses
            .Where(response => response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Conflict))
            .ToArray();
        var successfulRegistrations = (await Task.WhenAll(successes.Select(response =>
                response.Content.ReadFromJsonAsync<WebsiteIdentityRegistrationResponse>())))
            .Select(registration => registration ?? throw new InvalidOperationException(
                "A successful website-registration response did not contain its registration payload."))
            .ToArray();
        var winner = successfulRegistrations.Single(registration => !registration.IsRecovery);
        var recoveries = successfulRegistrations.Where(registration => registration.IsRecovery).ToArray();
        var website = await client.GetFromJsonAsync<WebsiteIdentity>(
            "/api/v1/identity/websites/concurrent-registration.example");

        await using var scope = factory.Services.CreateAsyncScope();
        var identityRepository = scope.ServiceProvider.GetRequiredService<IHipIdentityRepository>();
        var keyRepository = scope.ServiceProvider.GetRequiredService<ISigningKeyLifecycleRepository>();
        var auditLogService = scope.ServiceProvider.GetRequiredService<IAuditLogService>();
        var identity = await identityRepository.GetAsync(
            "hip:web:concurrent-registration.example",
            CancellationToken.None);
        var keyRing = await keyRepository.GetAsync(
            "hip:web:concurrent-registration.example",
            CancellationToken.None);
        var activationAudits = (await auditLogService.ListAsync(CancellationToken.None))
            .Where(entry =>
                entry.Action == "IdentityAndSigningKeyRegistered" &&
                entry.Metadata.TryGetValue("identityId", out var identityId) &&
                identityId == "hip:web:concurrent-registration.example")
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(unexpected, Is.Empty);
            Assert.That(successes.Length + conflicts.Length, Is.EqualTo(attempts.Length));
            Assert.That(recoveries.Length + conflicts.Length, Is.EqualTo(attempts.Length - 1));
            Assert.That(recoveries, Has.All.Matches<WebsiteIdentityRegistrationResponse>(registration =>
                registration.RequiresSigningKeyRotation && registration.DevelopmentPrivateKey is null));
            Assert.That(identity, Is.Not.Null);
            Assert.That(keyRing, Is.Not.Null);
            Assert.That(website, Is.Not.Null);
            Assert.That(
                identity!.PublicKey,
                Is.EqualTo(winner.WebsiteIdentity.PublicKeys.Single().PublicKey));
            Assert.That(
                website!.PublicKeys.Single().PublicKey,
                Is.EqualTo(identity.PublicKey));
            Assert.That(
                keyRing!.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKey,
                Is.EqualTo(identity.PublicKey));
            Assert.That(activationAudits, Has.Length.EqualTo(1));
        });

        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [Test]
    public async Task Website_verification_api_requires_a_matching_signed_well_known_document()
    {
        var fetcher = new MutableWellKnownDocumentFetcher();
        await using var factory = new HipWebApplicationFactory<Program>()
            .WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IWellKnownHipDocumentFetcher>();
                services.AddSingleton<IWellKnownHipDocumentFetcher>(fetcher);
            }));
        using var client = AdminClient(factory);
        var registered = await RegisterAsync(client, "verify-api.example", VerificationMethod.WellKnownHipJson);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var websiteService = scope.ServiceProvider.GetRequiredService<IWebsiteIdentityService>();
            var canonicalizer = scope.ServiceProvider.GetRequiredService<ICanonicalJsonService>();
            var unsigned = await websiteService.BuildWellKnownDocumentAsync(
                registered.WebsiteIdentity.Domain,
                CancellationToken.None);
            var crypto = new DevelopmentHipCryptoProvider();
            var canonical = WellKnownHipDocumentVerifier.CreateCanonicalSigningPayload(unsigned, canonicalizer);
            var hash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
            fetcher.Document = unsigned with
            {
                Signature = new HipProtocolSignature(
                    HipProtocolSignature.OriginAndIntegrityScope,
                    HipIdentityService.InitialSigningKeyId,
                    DevelopmentHipCryptoProvider.Algorithm,
                    SignatureAlgorithmFamily.Unknown,
                    HipProtocolSignature.Rfc8785Canonicalization,
                    crypto.SignHash(hash, registered.DevelopmentPrivateKey!))
            };
        }

        var response = await client.PostAsJsonAsync("/api/v1/identity/websites/verify", new WebsiteVerificationRequest(
            "verify-api.example",
            VerificationMethod.WellKnownHipJson,
            registered.VerificationRequest.Token));
        var verified = await response.Content.ReadFromJsonAsync<WebsiteIdentity>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(verified!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
    }

    [Test]
    public async Task Website_verification_api_returns_conflict_for_a_different_registration_method()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        await RegisterAsync(client, "method-conflict.example", VerificationMethod.DnsTxt);

        var response = await client.PostAsJsonAsync(
            "/api/v1/identity/websites/verify",
            new WebsiteVerificationRequest(
                "method-conflict.example",
                VerificationMethod.WellKnownHipJson,
                "unrelated-token"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task Domain_verification_start_api_returns_conflict_instead_of_replacing_existing_challenge()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var request = new DomainVerificationApiRequest(
            "duplicate-challenge.example",
            VerificationMethod.DnsTxt,
            null);

        var first = await client.PostAsJsonAsync("/api/v1/identity/domain-verification/start", request);
        var duplicate = await client.PostAsJsonAsync("/api/v1/identity/domain-verification/start", request);

        Assert.That(first.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(duplicate.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task Domain_verification_verify_api_returns_conflict_for_terminal_or_concurrent_state()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDomainVerificationService>();
                services.AddSingleton<IDomainVerificationService, ConflictDomainVerificationService>();
            }));
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync(
            "/api/v1/identity/domain-verification/verify",
            new DomainVerificationApiRequest(
                "revoked-challenge.example",
                VerificationMethod.DnsTxt,
                "challenge-token"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task Website_retry_api_uses_stored_challenge()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        await RegisterAsync(client, "retry-api.example", VerificationMethod.DnsTxt);

        var response = await client.PostAsync(
            "/api/v1/identity/websites/retry-api.example/retry", null);
        var retried = await response.Content.ReadFromJsonAsync<WebsiteIdentity>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(retried!.LastCheckedAtUtc, Is.Not.Null);
    }

    [Test]
    public async Task Website_revoke_api_is_owner_only_and_revokes_domain_verification()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var admin = AdminClient(factory);
        using var owner = OwnerClient(factory);
        await RegisterAsync(admin, "revoke-api.example", VerificationMethod.DnsTxt);
        var request = new DomainVerificationRevokeRequest("Domain ownership changed");

        var forbidden = await admin.PostAsJsonAsync(
            "/api/v1/identity/websites/revoke-api.example/revoke", request);
        var response = await owner.PostAsJsonAsync(
            "/api/v1/identity/websites/revoke-api.example/revoke", request);
        var revoked = await response.Content.ReadFromJsonAsync<WebsiteIdentity>();

        Assert.That(forbidden.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(revoked!.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
    }

    [Test]
    public async Task Website_revoke_api_returns_conflict_when_concurrent_state_cannot_be_reconciled()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IWebsiteIdentityService>();
                services.AddSingleton<IWebsiteIdentityService, ConflictWebsiteIdentityService>();
            }));
        using var owner = OwnerClient(factory);

        var response = await owner.PostAsJsonAsync(
            "/api/v1/identity/websites/revocation-conflict.example/revoke",
            new DomainVerificationRevokeRequest("Concurrent ownership change"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task Signature_verify_api_returns_public_safe_result()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var admin = AdminClient(factory);
        var registered = await RegisterAsync(admin, "signature-api.example", VerificationMethod.WellKnownHipJson);
        var crypto = new DevelopmentHipCryptoProvider();
        var contentHash = crypto.HashContent("demo");
        var signature = crypto.SignHash(contentHash, registered.DevelopmentPrivateKey!);

        var response = await client.PostAsJsonAsync("/api/v1/identity/signature/verify", new HipSignatureVerificationRequest(
            registered.WebsiteIdentity.HipIdentityId,
            contentHash,
            signature,
            "Low",
            HipIdentityService.InitialSigningKeyId));
        var result = await response.Content.ReadFromJsonAsync<SignatureVerificationResult>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(result!.IsValid, Is.True);
        Assert.That(result.FinalRiskStatus, Is.EqualTo("Caution"));
        Assert.That(result.Reason, Does.Contain("does not automatically mean safe"));
    }

    private static async Task<WebsiteIdentityRegistrationResponse> RegisterAsync(HttpClient client, string domain, VerificationMethod method)
    {
        var response = await client.PostAsJsonAsync("/api/v1/identity/websites/register", new WebsiteIdentityRegistrationRequest(domain, domain, method));
        return (await response.Content.ReadFromJsonAsync<WebsiteIdentityRegistrationResponse>())!;
    }

    private static HttpClient AdminClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "signed-website-test");
        return client;
    }

    private static HttpClient OwnerClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Owner");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "signed-website-owner-test");
        return client;
    }

    private sealed class MutableWellKnownDocumentFetcher : IWellKnownHipDocumentFetcher
    {
        public HipWellKnownDocument? Document { get; set; }

        public Task<HipWellKnownDocument?> FetchAsync(
            string normalizedDomain,
            CancellationToken cancellationToken) => Task.FromResult(Document);
    }

    private sealed class ConflictDomainVerificationService : IDomainVerificationService
    {
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
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Domain verification state changed concurrently.");

        public Task<DomainVerificationRetryResult> RetryAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest> RevokeAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(
            string domain,
            string expectedToken,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class ConflictWebsiteIdentityService : IWebsiteIdentityService
    {
        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
            WebsiteIdentityRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
            WebsiteIdentityRegistrationRequest request,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity> VerifyAsync(
            WebsiteVerificationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity> VerifyAsync(
            WebsiteVerificationRequest request,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity?> GetAsync(
            string domain,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity?> GetAsync(
            string domain,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity> RetryVerificationAsync(
            string domain,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentityRegistrationResponse> RenewExpiredVerificationAsync(
            string domain,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentity> RevokeVerificationAsync(
            string domain,
            string reason,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Website revocation state changed concurrently.");

        public Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(
            string domain,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
