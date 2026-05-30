using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class AdminRuleBuilderPageTests
{
    [Test]
    public async Task Rule_builder_page_loads_for_admin()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("Admin Rule Builder"));
        Assert.That(html, Does.Contain("Live JSON Preview"));
    }

    [Test]
    public async Task Rule_builder_new_route_loads_for_admin()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules/new");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Rule_builder_id_route_loads_for_admin()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules/new-domain-shortener-high-risk");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_rule_builder_route_is_protected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin/rules");

        Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-rule-builder-test");
    }
}
