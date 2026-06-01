using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Tests public lookup page rendering states that are visible to users.
/// </summary>
[TestFixture]
public sealed class PublicLookupPageTests
{
    /// <summary>
    /// Verifies the lookup page renders a clear no-data state for domains without stored HIP scans.
    /// </summary>
    [Test]
    public async Task Lookup_page_renders_no_data_state()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"lookup-page-{Guid.NewGuid():N}.com";

        var response = await client.GetAsync($"/lookup/{domain}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("Not Enough Data Yet"));
            Assert.That(html, Does.Contain("HIP has not scanned this domain yet"));
            Assert.That(html, Does.Contain("Data source"));
        });
    }
}
