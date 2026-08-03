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
    /// Verifies the lookup entry point uses the current marketing shell and retains its privacy-safe guidance.
    /// </summary>
    [Test]
    public async Task Lookup_entry_page_matches_the_marketing_site_shell()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/lookup");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("hip-marketing-site"));
            Assert.That(html, Does.Contain("Know what"));
            Assert.That(html, Does.Contain("TRUST STACK"));
            Assert.That(html, Does.Contain("no path, account information, or private URL"));
            Assert.That(html, Does.Not.Contain("public-site-shell"));
        });
    }

    /// <summary>
    /// Verifies the lookup page renders a clear no-data state for domains without stored HIP scans.
    /// </summary>
    [Test]
    public async Task Lookup_page_renders_no_data_state()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"lookup-page-{Guid.NewGuid():N}.com";

        var response = await client.GetAsync($"/lookup/{domain}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("hip-marketing-site"));
            Assert.That(html, Does.Contain("hip · trust result"));
            Assert.That(html, Does.Contain("trust-window"));
            Assert.That(html, Does.Contain(">56</strong>"));
            Assert.That(html, Does.Contain(">/ 100</span>"));
            Assert.That(html, Does.Contain("Provisional score · limited evidence"));
            Assert.That(html, Does.Contain("Signals reviewed"));
            Assert.That(html, Does.Contain("signals-disclosure"));
            Assert.That(html, Does.Contain("Score component"));
            Assert.That(html, Does.Contain("Authenticated site-safety scan"));
            Assert.That(html, Does.Contain("Not available"));
            Assert.That(html, Does.Contain("Raw page text, form values, private messages, cookies, and browsing history are never included"));
            Assert.That(html, Does.Contain("Not Enough Data Yet"));
            Assert.That(html, Does.Contain("HIP has no authoritative site-safety assessment for this domain yet"));
            Assert.That(html, Does.Contain("Data source"));
            Assert.That(html, Does.Not.Contain("public-site-shell"));
        });
    }
}
