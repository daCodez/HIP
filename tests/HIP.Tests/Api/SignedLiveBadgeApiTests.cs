extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

[TestFixture]
[NonParallelizable]
public sealed class SignedLiveBadgeApiTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Web_host_returns_and_verifies_the_same_signed_live_badge_contract()
    {
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory);
        using var client = factory.CreateClient();

        await AssertContractAsync(
            client,
            "/api/v1/badge/example.com",
            "/api/v1/badge/verify");

        var script = await client.GetStringAsync("/api/v1/badge/example.com/script");
        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("/api/v1/badge/verify"));
            Assert.That(script, Does.Contain("badge.isAvailable !== true"));
            Assert.That(script, Does.Contain("payload.score !== badge.score"));
            Assert.That(script, Does.Contain("expiresAt <= Date.now()"));
            Assert.That(script, Does.Contain("HIP Unavailable"));
        });
    }

    [Test]
    public async Task Api_service_returns_and_verifies_the_same_signed_live_badge_contract()
    {
        await using var rootFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = Configure(rootFactory);
        using var client = factory.CreateClient();

        await AssertContractAsync(
            client,
            "/api/v1/public/badge/domain/example.com",
            "/api/v1/public/badge/verify");
    }

    [Test]
    public async Task Default_runtime_fails_closed_when_no_managed_signer_is_configured()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/v1/badge/example.com");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(json.RootElement.GetProperty("isAvailable").GetBoolean(), Is.False);
            Assert.That(json.RootElement.GetProperty("signatureStatus").GetString(), Is.EqualTo("SignerUnavailable"));
            Assert.That(json.RootElement.GetProperty("signedBadge").ValueKind, Is.EqualTo(JsonValueKind.Null));
            Assert.That(json.RootElement.GetProperty("responseSignature").ValueKind, Is.EqualTo(JsonValueKind.Null));
        });
    }

    private static async Task AssertContractAsync(HttpClient client, string badgePath, string verifyPath)
    {
        using var badgeResponse = await client.GetAsync(badgePath);
        var body = await badgeResponse.Content.ReadAsStringAsync();
        using var badgeJson = JsonDocument.Parse(body);
        var root = badgeJson.RootElement;
        var signedBadge = root.GetProperty("signedBadge");

        Assert.Multiple(() =>
        {
            Assert.That(badgeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(root.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(root.GetProperty("score").GetInt32(), Is.EqualTo(73));
            Assert.That(StatusText(root.GetProperty("status")), Is.EqualTo("MostlyTrusted"));
            Assert.That(root.GetProperty("signatureStatus").GetString(), Is.EqualTo("Verified"));
            Assert.That(root.GetProperty("isAvailable").GetBoolean(), Is.True);
            Assert.That(root.GetProperty("responseSignature").GetString(), Is.EqualTo("badge-signature-value"));
            Assert.That(signedBadge.GetProperty("payload").GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(signedBadge.GetProperty("payload").GetProperty("score").GetInt32(), Is.EqualTo(73));
            Assert.That(signedBadge.GetProperty("signature").GetProperty("keyId").GetString(), Is.EqualTo("badge-key-1"));
            Assert.That(body, Does.Not.Contain("private-marker"));
        });

        using var verifyResponse = await client.PostAsJsonAsync(
            verifyPath,
            JsonSerializer.Deserialize<JsonElement>(signedBadge.GetRawText()));
        using var verifyJson = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());

        Assert.Multiple(() =>
        {
            Assert.That(verifyResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(verifyJson.RootElement.GetProperty("status").GetString(), Is.EqualTo("Verified"));
            Assert.That(verifyJson.RootElement.GetProperty("isVerified").GetBoolean(), Is.True);
            Assert.That(verifyJson.RootElement.GetProperty("establishesSafetyOrReputationBySignatureAlone").GetBoolean(), Is.False);
        });
    }

    private static string StatusText(JsonElement status) =>
        status.ValueKind == JsonValueKind.String
            ? status.GetString()!
            : ((RiskStatus)status.GetInt32()).ToString();

    private static WebApplicationFactory<TProgram> Configure<TProgram>(WebApplicationFactory<TProgram> factory)
        where TProgram : class =>
        factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<ITrustBadgeService>();
            services.RemoveAll<IHipLiveBadgeVerificationService>();
            services.AddSingleton<ITrustBadgeService>(new StubTrustBadgeService(Response()));
            services.AddSingleton<IHipLiveBadgeVerificationService>(new StubVerificationService());
        }));

    private static PublicBadgeResponse Response()
    {
        var verifiedMeaning = "Verified means the domain identity is known; current safety remains separate.";
        var document = new HipLiveBadgeDocument(
            new HipLiveBadgePayload(
                HipLiveBadgePayload.LiveBadgeDocumentType,
                HipProtocolVersion.CurrentValue,
                "example.com",
                73,
                RiskStatus.MostlyTrusted,
                true,
                "Verified",
                verifiedMeaning,
                Now.AddMinutes(-1),
                Now,
                Now.AddMinutes(5)),
            new HipProtocolIssuer("hip:web:badge-issuer.example"),
            new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "badge-key-1",
                "test-signature-v1",
                SignatureAlgorithmFamily.Classical,
                HipProtocolSignature.Rfc8785Canonicalization,
                "badge-signature-value"));
        return new PublicBadgeResponse(
            "example.com",
            73,
            RiskStatus.MostlyTrusted,
            true,
            Now.AddMinutes(-1),
            "/lookup/example.com",
            "/lookup/example.com",
            "HIP Verified - Score: 73/100 - Status: MostlyTrusted. Verified identity does not automatically mean safe.",
            "mostlytrusted",
            "Verified",
            true,
            verifiedMeaning,
            document.Signature.Value,
            document,
            HipLiveBadgeSignatureStatus.Verified.ToString(),
            true);
    }

    private sealed class StubTrustBadgeService(PublicBadgeResponse response) : ITrustBadgeService
    {
        public Task<PublicBadgeResponse> GetDomainBadgeAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(response);
    }

    private sealed class StubVerificationService : IHipLiveBadgeVerificationService
    {
        public Task<HipLiveBadgeVerificationResult> VerifyAsync(
            HipLiveBadgeDocument document,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HipLiveBadgeVerificationResult(HipLiveBadgeSignatureStatus.Verified));
    }
}
