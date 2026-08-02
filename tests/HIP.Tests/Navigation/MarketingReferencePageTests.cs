namespace HIP.Tests.Navigation;

/// <summary>Guards the local, Blazor-hosted copy of the supplied HIP marketing design.</summary>
public sealed class MarketingReferencePageTests
{
    [Test]
    public void Marketing_pages_keep_the_supplied_reference_markup_and_local_assets()
    {
        var root = RepositoryRoot();
        var pages = new Dictionary<string, string>
        {
            ["PublicHome.razor"] = "data-sc-name=\"index\"",
            ["PublicPlatform.razor"] = "data-sc-name=\"platform\"",
            ["PublicHowItWorks.razor"] = "data-sc-name=\"how\"",
            ["PublicVerification.razor"] = "data-sc-name=\"verify\"",
            ["PublicDevelopers.razor"] = "data-sc-name=\"dev\""
        };

        Assert.Multiple(() =>
        {
            foreach (var (file, marker) in pages)
            {
                var source = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "Components", "Pages", file));
                Assert.That(source, Does.Contain("@layout PublicLayout"), file);
                Assert.That(source, Does.Contain(marker), file);
                Assert.That(source, Does.Contain("/images/public/reference/hip-shield.png"), file);
                Assert.That(source, Does.Not.Contain("blob:null"), file);
            }

            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "images", "public", "reference", "trust-globe.png")), Is.True);
            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "fonts", "satoshi-700.woff2")), Is.True);
            Assert.That(File.Exists(Path.Combine(root, "src", "HIP.Web", "wwwroot", "fonts", "jetbrains-mono-latin.woff2")), Is.True);
        });
    }

    [Test]
    public void Marketing_reference_script_keeps_navigation_theme_and_lookup_controls_operable()
    {
        var root = RepositoryRoot();
        var source = File.ReadAllText(Path.Combine(root, "src", "HIP.Web", "wwwroot", "marketing-reference.js"));

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("[\"Platform\", \"/platform\"]"));
            Assert.That(source, Does.Contain("[\"How it works\", \"/how-it-works\"]"));
            Assert.That(source, Does.Contain("openLookup(root)"));
            Assert.That(source, Does.Contain("button.title === \"Toggle theme\""));
            Assert.That(source, Does.Contain("aria-expanded"));
            Assert.That(source, Does.Contain("IntersectionObserver"));
            Assert.That(source, Does.Contain("[data-rise]"));
            Assert.That(source, Does.Contain("[data-tilt]"));
            Assert.That(source, Does.Contain("[data-spot]"));
            Assert.That(source, Does.Contain("[data-count]"));
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
