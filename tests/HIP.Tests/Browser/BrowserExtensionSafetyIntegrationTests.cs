namespace HIP.Tests.Browser;

[TestFixture]
public sealed class BrowserExtensionSafetyIntegrationTests
{
    [Test]
    public void Safety_router_uses_browser_source_and_does_not_inject_unsafe_html()
    {
        var source = ExtensionSource("src", "safetyPageRouter.js");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("HIP_SAFETY_URL"));
            Assert.That(source, Does.Contain("event.preventDefault()"));
            Assert.That(source, Does.Not.Contain("innerHTML"));
        });
    }

    [Test]
    public void Api_client_sets_safety_source_to_browser_and_preserves_source_domain_separately()
    {
        var source = ExtensionSource("src", "hipApiClient.js");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("url.searchParams.set(\"source\", \"browser\")"));
            Assert.That(source, Does.Contain("url.searchParams.set(\"sourceDomain\", sourceDomain)"));
            Assert.That(source, Does.Not.Contain("url.searchParams.set(\"source\", sourceDomain)"));
        });
    }

    [Test]
    public void Content_script_routes_only_risky_links_and_does_not_send_page_or_form_text()
    {
        var source = ExtensionSource("src", "content.js");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("riskyStatuses.has(status)"));
            Assert.That(source, Does.Contain("enableSafetyRouting"));
            Assert.That(source, Does.Contain("routeClick(event, anchor, lookup, currentDomain)"));
            Assert.That(source, Does.Not.Contain("document.body.innerText"));
            Assert.That(source, Does.Not.Contain("document.body.textContent"));
            Assert.That(source, Does.Not.Contain("input.value"));
            Assert.That(source, Does.Not.Contain("FormData"));
        });
    }

    [Test]
    public void Link_badges_are_attention_only_not_safe_link_icons()
    {
        var source = ExtensionSource("src", "content.js");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("shouldRenderBadge(status, verified, target.isDownloadCandidate)"));
            Assert.That(source, Does.Contain("status !== \"Trusted\""));
            Assert.That(source, Does.Not.Contain("renderLinkBadge(anchor, \"Trusted\""));
        });
    }

    private static string ExtensionSource(params string[] segments)
    {
        var root = FindRepositoryRoot();
        var pathSegments = new[] { root, "clients", "browser-extension" }.Concat(segments).ToArray();
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP repository root.");
    }
}
