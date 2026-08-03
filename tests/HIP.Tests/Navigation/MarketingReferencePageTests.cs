namespace HIP.Tests.Navigation;

/// <summary>Guards the integrated, Blazor-hosted copy of the supplied HIP marketing design.</summary>
public sealed class MarketingReferencePageTests
{
    [Test]
    public void Marketing_pages_keep_the_supplied_component_design_and_local_assets()
    {
        var root = RepositoryRoot();
        var pages = new Dictionary<string, string>
        {
            ["PublicHome.razor"] = "Trust is your",
            ["PublicPlatform.razor"] = "Six signal families, one readable score",
            ["PublicHowItWorks.razor"] = "Nothing here is a black box",
            ["PublicVerification.razor"] = "Prove it once, then keep it honest",
            ["PublicDevelopers.razor"] = "Open source, because trust cannot be proprietary",
            ["PublicMethodology.razor"] = "How a HIP score is produced"
        };

        Assert.Multiple(() =>
        {
            foreach (var (file, marker) in pages)
            {
                var source = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", file));
                Assert.That(source, Does.Contain("@layout MarketingLayout"), file);
                Assert.That(source, Does.Contain("@rendermode InteractiveServer"), file);
                Assert.That(source, Does.Contain(marker), file);
                Assert.That(source, Does.Not.Contain("blob:null"), file);
            }

            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "images", "public", "marketing", "hip-logo.png")), Is.True);
            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "images", "public", "marketing", "og-image.png")), Is.True);
            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "fonts", "satoshi-700.woff2")), Is.True);
            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "fonts", "jetbrains-mono-latin.woff2")), Is.True);
        });
    }

    [Test]
    public void Marketing_assets_keep_motion_accessibility_and_portal_styles_isolated()
    {
        var root = RepositoryRoot();
        var script = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "wwwroot", "marketing-site.js"));
        var styles = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "wwwroot", "marketing-site.css"));
        var brandStyles = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "wwwroot", "brand-compliance.css"));
        var layout = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Layout", "MarketingLayout.razor"));
        var home = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", "PublicHome.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("requestAnimationFrame"));
            Assert.That(script, Does.Contain("prefers-reduced-motion"));
            Assert.That(script, Does.Contain("function motionEnabled()"));
            Assert.That(script, Does.Contain("if (motionEnabled()) rot +="));
            Assert.That(script, Does.Contain("[data-rise]"));
            Assert.That(script, Does.Contain("[data-tilt]"));
            Assert.That(script, Does.Contain("[data-spot]"));
            Assert.That(script, Does.Contain("[data-count]"));
            Assert.That(script, Does.Contain("window.hip"));
            Assert.That(script, Does.Contain("not a full external HIP scan"));
            Assert.That(styles, Does.Contain(".hip-marketing-site[data-theme=\"dark\"]"));
            Assert.That(styles, Does.Not.Contain(":root{"));
            Assert.That(styles, Does.Contain("@media (max-width:520px)"));
            Assert.That(styles, Does.Contain("[data-domain-cta]{display:none !important}"));
            Assert.That(brandStyles, Does.Contain("*:not(.hip-marketing-site[data-motion=full],.hip-marketing-site[data-motion=full] *)"));
            Assert.That(layout, Does.Contain("href=\"/website-trust-scanner\""));
            Assert.That(layout, Does.Contain("data-motion=\"full\""));
            Assert.That(layout, Does.Contain("https://github.com/daCodez/HIP"));
            Assert.That(home, Does.Contain("data-signal-marquee"));
        });
    }

    /// <summary>Confirms the static layout controls remain operable and examples are not presented as live HIP evidence.</summary>
    [Test]
    public void Marketing_interactions_use_real_lookup_and_label_illustrative_evidence()
    {
        var root = RepositoryRoot();
        var webRoot = Path.Combine(root, "src", "HIP.Web");
        var script = File.ReadAllText(Path.Combine(webRoot, "wwwroot", "marketing-site.js"));
        var layout = File.ReadAllText(Path.Combine(webRoot, "Components", "Layout", "MarketingLayout.razor"));
        var home = File.ReadAllText(Path.Combine(webRoot, "Components", "Pages", "PublicHome.razor"));
        var simulator = File.ReadAllText(Path.Combine(webRoot, "Components", "Marketing", "ScoreSimulator.razor"));
        var receipt = File.ReadAllText(Path.Combine(webRoot, "Components", "Marketing", "TrustReceipt.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(layout, Does.Contain("data-theme-toggle"));
            Assert.That(layout, Does.Not.Contain("data-register-toggle"));
            Assert.That(layout, Does.Not.Contain("<LinkCheckBar />"));
            Assert.That(layout, Does.Not.Contain("@onclick"));
            Assert.That(script, Does.Contain("initChrome()"));
            Assert.That(script, Does.Contain("window.location.assign(nav.value)"));
            Assert.That(script, Does.Contain("data-register-copy"));
            Assert.That(home, Does.Contain("/lookup/{Uri.EscapeDataString(domain)}"));
            Assert.That(home, Does.Contain("ILLUSTRATIVE EXAMPLE"));
            Assert.That(simulator, Does.Contain("PublishedRuleCatalog.CurrentVersion"));
            Assert.That(receipt, Does.Contain("not a live scan or an issued HIP receipt"));
        });
    }

    [Test]
    public void Interactive_features_live_on_focused_routes_with_complete_metadata()
    {
        var root = RepositoryRoot();
        var webRoot = Path.Combine(root, "src", "HIP.Web");
        var pagesRoot = Path.Combine(webRoot, "Components", "Pages");
        var expected = new Dictionary<string, (string Route, string Marker)>
        {
            ["PublicWebsiteTrustScanner.razor"] = ("/website-trust-scanner", "<LinkCheckBar"),
            ["PublicLookalikeDetector.razor"] = ("/tools/lookalike-detector", "<LookalikeDetector />"),
            ["PublicBrowserExtension.razor"] = ("/browser-extension", "<ExtensionSimulator />"),
            ["PublicVerification.razor"] = ("/domain-verification", "<TrustReceipt />"),
            ["PublicMethodology.razor"] = ("/methodology", "<ScoreSimulator />"),
            ["PublicPlatform.razor"] = ("/platform", "<ScanPulse />")
        };

        Assert.Multiple(() =>
        {
            foreach (var (file, expectation) in expected)
            {
                var source = File.ReadAllText(Path.Combine(pagesRoot, file));
                Assert.That(source, Does.Contain($"@page \"{expectation.Route}\""), file);
                Assert.That(source, Does.Contain(expectation.Marker), file);
                Assert.That(source, Does.Contain("<PageTitle>"), file);
                Assert.That(source, Does.Contain("name=\"description\""), file);
                Assert.That(source, Does.Contain("property=\"og:title\""), file);
                Assert.That(source, Does.Contain("rel=\"canonical\""), file);
            }

            var home = File.ReadAllText(Path.Combine(pagesRoot, "PublicHome.razor"));
            Assert.That(home, Does.Not.Contain("<ScoreSimulator />"));
            Assert.That(home, Does.Not.Contain("<ExtensionSimulator />"));
            Assert.That(home, Does.Not.Contain("<LookalikeDetector />"));
            Assert.That(home, Does.Not.Contain("<TrustReceipt />"));

            var sitemap = File.ReadAllText(Path.Combine(webRoot, "wwwroot", "sitemap.xml"));
            foreach (var route in expected.Values.Select(value => value.Route))
            {
                Assert.That(sitemap, Does.Contain($"https://guardwithhip.com{route}"), route);
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
