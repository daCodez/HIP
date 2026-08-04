using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Navigation;

/// <summary>Verifies public discovery metadata, crawl controls, and indexable marketing routes.</summary>
public sealed class PublicSeoTests
{
    /// <summary>Confirms the canonical domain publishes its HIP verification document at the standard discovery path.</summary>
    [Test]
    public async Task Well_known_hip_document_is_public_for_canonical_domain()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/.well-known/hip.json");
        var json = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
            Assert.That(json, Does.Contain("\"domain\": \"guardwithhip.com\""));
            Assert.That(json, Does.Contain("\"hipIdentityId\": \"hip:web:guardwithhip.com\""));
        });
    }

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
            Assert.That(html, Does.Contain("HIP (Human Identity Protocol) is an open-source website trust and risk-scoring platform at guardwithhip.com"));
            Assert.That(html, Does.Contain("\"\\u0040type\": \"WebSite\""));
            Assert.That(html, Does.Contain("\"\\u0040id\": \"https://guardwithhip.com/#website\""));
            Assert.That(html, Does.Contain("href=\"/platform\""));
            Assert.That(html, Does.Contain("href=\"/website-trust-scanner\""));
            Assert.That(html, Does.Contain("href=\"/tools/lookalike-detector\""));
            Assert.That(html, Does.Contain("href=\"/browser-extension\""));
            Assert.That(html, Does.Contain("href=\"/domain-verification\""));
            Assert.That(html, Does.Contain("href=\"/signals\""));
            Assert.That(html, Does.Contain("href=\"/score-interpretation\""));
            Assert.That(html, Does.Contain("href=\"/evidence-providers\""));
            Assert.That(html, Does.Contain("src=\"/images/public/marketing/hip-logo.png\""));
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
    [TestCase("/website-trust-scanner", "Website Trust Scanner", "Check the link. Then check the evidence")]
    [TestCase("/tools/lookalike-detector", "Lookalike Domain Detector", "See the domain your eyes can miss")]
    [TestCase("/browser-extension", "HIP Browser Extension", "HIP, where you browse")]
    [TestCase("/domain-verification", "Domain Verification", "Prove it once, then keep it honest")]
    [TestCase("/platform", "Platform", "Six signal families, one readable score")]
    [TestCase("/methodology", "Trust Methodology", "How a HIP score is produced")]
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
            Assert.That(html, Does.Contain($"<link rel=\"canonical\" href=\"https://guardwithhip.com{path}\""));
            Assert.That(html, Does.Contain(headingFragment));
        });

        if (path == "/website-trust-scanner")
        {
            Assert.That(html, Does.Contain("\"\\u0040type\": \"WebApplication\""));
        }
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
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/tools/lookalike-detector"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/browser-extension"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/domain-verification"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/methodology"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/signals"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/score-interpretation"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/evidence-providers"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/privacy"));
            Assert.That(sitemap, Does.Contain("https://guardwithhip.com/appeals"));
            Assert.That(sitemap, Does.Not.Contain("https://guardwithhip.com/verification<"));
            Assert.That(sitemap, Does.Not.Contain("https://guardwithhip.com/verify<"));
            Assert.That(sitemap, Does.Not.Contain("https://guardwithhip.com/how<"));
        });
    }

    [Test]
    public void Production_proxy_obtains_www_tls_and_permanently_consolidates_aliases()
    {
        var root = RepositoryRoot();
        var configurations = new[] { "Caddyfile", "Caddyfile.production" };

        foreach (var configuration in configurations)
        {
            var caddy = File.ReadAllText(Path.Combine(root, "deploy", "vps", configuration));

            Assert.Multiple(() =>
            {
                Assert.That(caddy, Does.Contain("www.{$HIP_PUBLIC_HOST} {"), configuration);
                Assert.That(caddy, Does.Contain("redir https://{$HIP_PUBLIC_HOST}{uri} permanent"), configuration);
                Assert.That(caddy, Does.Contain("@verificationAlias path /verification /verify"), configuration);
                Assert.That(caddy, Does.Contain("redir @verificationAlias /domain-verification permanent"), configuration);
                Assert.That(caddy, Does.Contain("redir @howAlias /how-it-works permanent"), configuration);
                Assert.That(caddy, Does.Contain("redir @developersAlias /developers permanent"), configuration);
            });
        }
    }

    /// <summary>Prevents the removed punctuation style from returning to first-party public content.</summary>
    [Test]
    public void First_party_content_contains_no_em_dashes()
    {
        var root = RepositoryRoot();
        var contentRoots = new[]
        {
            Path.Combine(root, "src", "HIP.Web"),
            Path.Combine(root, "clients", "browser-extension"),
            Path.Combine(root, "docs"),
            Path.Combine(root, "design")
        };
        var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".css", ".html", ".js", ".json", ".md", ".razor"
        };
        var files = contentRoots
            .SelectMany(path => Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            .Where(path => textExtensions.Contains(Path.GetExtension(path)))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}node_modules{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}wwwroot{Path.DirectorySeparatorChar}lib{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .Append(Path.Combine(root, "README.md"));

        Assert.Multiple(() =>
        {
            foreach (var file in files)
            {
                Assert.That(File.ReadAllText(file), Does.Not.Contain("\u2014"), file);
            }
        });
    }

    /// <summary>Confirms repeated marketing footers point to specific destinations rather than the repository root.</summary>
    [Test]
    public void Marketing_footers_use_specific_product_project_and_policy_links()
    {
        var root = RepositoryRoot();
        var footer = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Marketing", "SiteFooter.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(footer, Does.Contain("href=\"/privacy\""));
            Assert.That(footer, Does.Contain("href=\"/appeals\""));
            Assert.That(footer, Does.Contain("href=\"/signals\""));
            Assert.That(footer, Does.Contain("href=\"/score-interpretation\""));
            Assert.That(footer, Does.Contain("href=\"/evidence-providers\""));
            Assert.That(footer, Does.Contain("/blob/master/docs/rules-engine.md"));
            Assert.That(footer, Does.Contain("/blob/master/docs/project-reference/HIP_Implementation_Backlog.md"));
            Assert.That(footer, Does.Contain("https://github.com/daCodez/HIP/issues"));
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
