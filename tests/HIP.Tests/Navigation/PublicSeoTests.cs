using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Navigation;

/// <summary>Verifies public discovery metadata, crawl controls, and indexable marketing routes.</summary>
public sealed class PublicSeoTests
{
    /// <summary>Confirms the homepage exposes the requested title, description, entity definition, and crawlable navigation.</summary>
    [Test]
    public async Task Homepage_exposes_search_metadata_entity_copy_and_real_links()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("<title>HIP Website Trust Scanner | Explainable Security &amp; Risk Scores</title>"));
            Assert.That(html, Does.Contain("<meta name=\"description\" content=\"Scan a website for HTTPS, certificate, DNS, reputation and page-risk signals. HIP explains every trust score in plain language.\""));
            Assert.That(html, Does.Contain("type=\"application/ld+json\""));
            Assert.That(html, Does.Contain("\"sameAs\": [\"https://github.com/daCodez/HIP\"]"));
            Assert.That(html, Does.Contain("HIP (Human-Interactive Protocol) is an open-source website trust and risk-scoring platform at guardwithhip.com"));
            Assert.That(html, Does.Contain("href=\"/platform\""));
            Assert.That(html, Does.Contain("href=\"/how-it-works\""));
            Assert.That(html, Does.Contain("href=\"/verification\""));
            Assert.That(html, Does.Contain("href=\"/developers\""));
            Assert.That(html, Does.Contain("href=\"/signals\""));
            Assert.That(html, Does.Contain("href=\"/score-interpretation\""));
            Assert.That(html, Does.Contain("href=\"/evidence-providers\""));
            Assert.That(html, Does.Not.Contain(">Platform</button>"));
            Assert.That(html, Does.Not.Contain(">How it works</button>"));
            Assert.That(html, Does.Not.Contain("data-hip-badge=\"guardwithhip.com\""));
        });
    }

    /// <summary>Confirms the canonical public hostname renders HIP's signed, domain-bound self-badge embed.</summary>
    [Test]
    public async Task Canonical_public_host_renders_the_live_guardwithhip_badge()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://guardwithhip.com")
        });

        var response = await client.GetAsync("/");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("data-hip-badge=\"guardwithhip.com\""));
            Assert.That(html, Does.Contain("src=\"/api/v1/badge/guardwithhip.com/script\""));
            Assert.That(html, Does.Not.Contain("Protected by HIP"));
        });
    }

    /// <summary>Confirms each new search landing page is directly renderable and self-describing.</summary>
    [TestCase("/website-trust-scanner", "Website Trust Scanner", "Check a website before you")]
    [TestCase("/methodology", "Trust Score Methodology", "Every score keeps its")]
    [TestCase("/privacy", "Privacy Approach", "Collect less. Explain")]
    [TestCase("/appeals", "Appeals Policy", "A finding can be")]
    [TestCase("/signals", "Website Trust Signals", "One score. Named, inspectable")]
    [TestCase("/score-interpretation", "How to Interpret a HIP Trust Score", "A score is a summary")]
    [TestCase("/evidence-providers", "Website Evidence Providers", "Sources contribute facts")]
    public async Task Search_landing_page_is_indexable(string path, string titleFragment, string headingFragment)
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync(path);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain($"<title>{titleFragment}"));
            Assert.That(html, Does.Contain("<meta name=\"description\""));
            Assert.That(html, Does.Contain(headingFragment));
        });
    }

    /// <summary>Confirms crawlers receive explicit policy and canonical sitemap endpoints.</summary>
    [Test]
    public async Task Robots_and_sitemap_are_public_and_reference_canonical_routes()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var robotsResponse = await client.GetAsync("/robots.txt");
        var sitemapResponse = await client.GetAsync("/sitemap.xml");
        var robots = await robotsResponse.Content.ReadAsStringAsync();
        var sitemap = await sitemapResponse.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(robotsResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(robots, Does.Contain("User-agent: *"));
            Assert.That(robots, Does.Contain("Sitemap: https://guardwithhip.com/sitemap.xml"));
            Assert.That(sitemapResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/website-trust-scanner"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/methodology"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/signals"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/score-interpretation"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/evidence-providers"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/privacy"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/appeals"));
        });
    }

    /// <summary>Confirms repeated marketing footers point to specific destinations rather than the repository root.</summary>
    [Test]
    public void Marketing_footers_use_specific_product_project_and_policy_links()
    {
        var root = RepositoryRoot();
        var pages = new[]
        {
            "PublicHome.razor",
            "PublicPlatform.razor",
            "PublicHowItWorks.razor",
            "PublicVerification.razor",
            "PublicDevelopers.razor"
        };

        Assert.Multiple(() =>
        {
            foreach (var page in pages)
            {
                var source = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", page));
                Assert.That(source, Does.Contain("href=\"/privacy\""), page);
                Assert.That(source, Does.Contain("href=\"/appeals\""), page);
                Assert.That(source, Does.Contain("href=\"/signals\""), page);
                Assert.That(source, Does.Contain("href=\"/score-interpretation\""), page);
                Assert.That(source, Does.Contain("href=\"/evidence-providers\""), page);
                Assert.That(source, Does.Contain("/blob/master/docs/rules-engine.md"), page);
                Assert.That(source, Does.Contain("/blob/master/docs/project-reference/HIP_Implementation_Backlog.md"), page);
                Assert.That(source, Does.Contain("https://github.com/daCodez/HIP/issues"), page);
                Assert.That(source, Does.Not.Contain("href=\"https://github.com/daCodez/HIP\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"scp7\" style=\"font-size: 14.5px; color: var(--text);\">Detection rules</a>"), page);
            }
        });
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HIP.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("Could not locate the HIP repository root.");
    }
}
