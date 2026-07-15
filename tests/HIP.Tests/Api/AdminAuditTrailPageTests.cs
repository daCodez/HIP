using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class AdminAuditTrailPageTests
{
    /// <summary>
    /// Verifies an authorized operator can reach the canonical audit trail from the shared navigation
    /// and receives the controls needed to inspect privacy-safe audit events.
    /// </summary>
    [Test]
    public async Task Audit_trail_page_loads_for_admin_and_is_linked_from_navigation()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/audit-logs");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain(">Audit Trail</h1>"));
        Assert.That(html, Does.Contain("Search audit trail"));
        Assert.That(html, Does.Contain("Filter by severity"));
        Assert.That(html, Does.Contain("Filter by target"));
        Assert.That(html, Does.Contain("aria-live=\"polite\""));
        Assert.That(html, Does.Contain("class=\"audit-results\""));
        Assert.That(html, Does.Contain("href=\"admin/audit-logs\""));
        Assert.That(html, Does.Contain(">Audit Trail</span>"));
    }

    /// <summary>
    /// Verifies the audit trail remains unavailable without an authenticated admin identity.
    /// </summary>
    [Test]
    public async Task Audit_trail_page_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin/audit-logs");

        Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-audit-page-test");
    }
}
