using System.Net;
using System.Net.Http.Json;
using HIP.Application.Identity;
using HIP.Domain.Identity;
using HIP.Web.Security;

namespace HIP.Tests.Api;

/// <summary>Proves domain onboarding is owner-bound without exposing ownership identifiers.</summary>
public sealed class WebsiteOwnershipIsolationTests
{
    [Test]
    public async Task Admin_claim_is_isolated_while_platform_owner_has_an_explicit_override()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var claimant = Client(factory, AdminRoles.Admin, "domain-admin-a");
        using var otherAdmin = Client(factory, AdminRoles.Admin, "domain-admin-b");
        using var platformOwner = Client(factory, AdminRoles.Owner, "platform-owner");
        var domain = $"owner-{Guid.NewGuid():N}.example";
        var request = new WebsiteIdentityRegistrationRequest(domain, "Owned Website", VerificationMethod.DnsTxt);

        using var registered = await claimant.PostAsJsonAsync("/api/v1/identity/websites/register", request);
        var registrationBody = await registered.Content.ReadAsStringAsync();
        using var claimantGet = await claimant.GetAsync($"/api/v1/identity/websites/{domain}");
        using var otherGet = await otherAdmin.GetAsync($"/api/v1/identity/websites/{domain}");
        using var otherUnknown = await otherAdmin.GetAsync($"/api/v1/identity/websites/unknown-{domain}");
        using var otherRegister = await otherAdmin.PostAsJsonAsync("/api/v1/identity/websites/register", request);
        using var ownerGet = await platformOwner.GetAsync($"/api/v1/identity/websites/{domain}");
        var claimantPage = await claimant.GetStringAsync("/admin/identity/websites");
        var otherPage = await otherAdmin.GetStringAsync("/admin/identity/websites");

        Assert.Multiple(() =>
        {
            Assert.That(registered.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(claimantGet.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(otherGet.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(otherUnknown.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(otherRegister.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(ownerGet.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(claimantPage, Does.Contain(domain));
            Assert.That(otherPage, Does.Not.Contain(domain));
            Assert.That(registrationBody, Does.Not.Contain("domain-admin-a"));
            Assert.That(registrationBody, Does.Not.Contain("ownerScopeHash"));
        });
    }

    private static HttpClient Client(HipWebApplicationFactory<Program> factory, string role, string actor)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, actor);
        return client;
    }
}
