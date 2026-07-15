using System.Net;
using System.Net.Http.Json;
using HIP.Application.Identity;
using HIP.Domain.Identity;
using Microsoft.AspNetCore.Mvc.Testing;

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
    public async Task Website_verification_api_verifies_with_token()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var registered = await RegisterAsync(client, "verify-api.example", VerificationMethod.WellKnownHipJson);

        var response = await client.PostAsJsonAsync("/api/v1/identity/websites/verify", new WebsiteVerificationRequest(
            "verify-api.example",
            VerificationMethod.WellKnownHipJson,
            registered.VerificationRequest.Token));
        var verified = await response.Content.ReadFromJsonAsync<WebsiteIdentity>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(verified!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
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
            "Low"));
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
}
