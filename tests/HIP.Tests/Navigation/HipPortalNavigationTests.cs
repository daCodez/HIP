using HIP.Web.Navigation;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace HIP.Tests.Navigation;

/// <summary>Verifies browser navigation stays on HIP's canonical application hosts.</summary>
public sealed class HipPortalNavigationTests
{
    [Test]
    public void Canonical_links_route_every_application_family_to_its_configured_origin()
    {
        var links = new HipPortalLinks(Options.Create(ValidOptions()));

        Assert.Multiple(() =>
        {
            Assert.That(links.Public("/lookup/example.com"), Is.EqualTo("https://guardwithhip.com/lookup/example.com"));
            Assert.That(links.Consumer("/devices"), Is.EqualTo("https://app.guardwithhip.com/devices"));
            Assert.That(links.Admin("/message-shield"), Is.EqualTo("https://admin.guardwithhip.com/message-shield"));
            Assert.That(links.Api("/health"), Is.EqualTo("https://api.guardwithhip.com/health"));
            Assert.That(links.Identity("/realms/hip/account"), Is.EqualTo("https://identity.guardwithhip.com/realms/hip/account"));
            Assert.That(() => links.Public("//outside.example/path"), Throws.ArgumentException);
            Assert.That(() => links.Public("/\\outside.example/path"), Throws.ArgumentException);
            Assert.That(() => links.Public("/lookup\r\noutside.example"), Throws.ArgumentException);
            Assert.That(links.IsConsumer(new Uri("https://app.guardwithhip.com/devices")), Is.True);
            Assert.That(links.IsConsumer(new Uri("https://admin.guardwithhip.com/devices")), Is.False);
        });
    }

    [Test]
    public void Cross_application_navigation_uses_the_canonical_link_builder()
    {
        var root = RepositoryRoot();
        var sources = new Dictionary<string, string>
        {
            ["admin navigation"] = Read(root, "Components", "Layout", "ControlCenterNav.razor"),
            ["consumer home"] = Read(root, "Components", "Pages", "ConsumerHome.razor"),
            ["consumer certificates"] = Read(root, "Components", "Pages", "ConsumerCertificates.razor"),
            ["admin certificates"] = Read(root, "Components", "Pages", "AdminDomainCertificates.razor"),
            ["admin reputation"] = Read(root, "Components", "Pages", "AdminReputationOverview.razor"),
            ["admin website identity"] = Read(root, "Components", "Pages", "AdminWebsiteIdentity.razor"),
            ["admin roles"] = Read(root, "Components", "Pages", "AdminRoles.razor"),
            ["admin dashboard"] = Read(root, "Components", "Pages", "AdminDashboard.razor")
        };

        Assert.Multiple(() =>
        {
            Assert.That(sources["admin navigation"], Does.Contain("PortalLinks.Consumer(\"/devices\")"));
            Assert.That(sources["consumer home"], Does.Contain("PortalLinks.Public(\"/lookup\")"));
            Assert.That(sources["consumer certificates"], Does.Contain("PortalLinks.Public($\"/certificate/"));
            Assert.That(sources["admin certificates"], Does.Contain("PortalLinks.Public($\"/certificate/"));
            Assert.That(sources["admin reputation"], Does.Contain("PortalLinks.Public($\"/lookup/"));
            Assert.That(sources["admin website identity"], Does.Contain("PortalLinks.Public($\"/lookup/domain/"));
            Assert.That(sources["admin roles"], Does.Contain("PortalLinks.Public(\"/access\")"));
            Assert.That(sources["admin dashboard"], Does.Contain("href=\"/reputation\">View all"));
            Assert.That(sources["admin dashboard"], Does.Not.Contain("href=\"/admin/"));
        });
    }

    [Test]
    public void Browser_navigation_never_emits_admin_or_consumer_folder_prefixes()
    {
        var root = RepositoryRoot();
        var componentRoot = Path.Combine(root, "src", "HIP.Web", "Components");
        var failures = Directory.GetFiles(componentRoot, "*.razor", SearchOption.AllDirectories)
            .Where(path => !path.EndsWith("DevLauncher.razor", StringComparison.OrdinalIgnoreCase))
            .SelectMany(path => File.ReadAllLines(path)
                .Where(line => !line.TrimStart().StartsWith("@page", StringComparison.Ordinal))
                .Where(line => Regex.IsMatch(
                    line,
                    "(?:href|action)=\\\"(?:@\\(\\$?\\\")?/?(?:admin|consumer)(?:/|\\\")",
                    RegexOptions.IgnoreCase))
                .Select(line => $"{Path.GetRelativePath(root, path)}: {line.Trim()}"))
            .ToArray();

        Assert.That(failures, Is.Empty);
    }

    [Test]
    public void Every_static_internal_navigation_target_maps_to_a_page_or_auth_endpoint()
    {
        var root = RepositoryRoot();
        var componentRoot = Path.Combine(root, "src", "HIP.Web", "Components");
        var sources = Directory.GetFiles(componentRoot, "*.razor", SearchOption.AllDirectories)
            .Select(path => new { Path = path, Source = File.ReadAllText(path) })
            .ToArray();
        var pageRoutes = sources
            .SelectMany(source => Regex.Matches(source.Source, "@page \\\"(?<route>/[^\\\"]+)\\\"")
                .Select(match => match.Groups["route"].Value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var endpointTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/",
            "/auth/login",
            "/auth/logout",
            "/auth/step-up"
        };
        var failures = sources
            .SelectMany(source => Regex.Matches(
                    source.Source,
                    "(?:href|action)=\\\"(?<target>/[^\\\"@?#]*)\\\"")
                .Select(match => new
                {
                    Source = Path.GetRelativePath(root, source.Path),
                    Target = match.Groups["target"].Value
                }))
            .Where(link =>
                !pageRoutes.Contains(link.Target) &&
                !endpointTargets.Contains(link.Target) &&
                !pageRoutes.Contains($"/admin{(link.Target == "/" ? string.Empty : link.Target)}") &&
                !pageRoutes.Contains($"/consumer{(link.Target == "/" ? string.Empty : link.Target)}"))
            .Select(link => $"{link.Source}: {link.Target}")
            .ToArray();

        Assert.That(failures, Is.Empty);
    }

    private static HipPortalLinkOptions ValidOptions() => new()
    {
        PublicOrigin = "https://guardwithhip.com",
        ConsumerOrigin = "https://app.guardwithhip.com",
        AdminOrigin = "https://admin.guardwithhip.com",
        ApiOrigin = "https://api.guardwithhip.com",
        IdentityOrigin = "https://identity.guardwithhip.com"
    };

    private static string Read(string root, params string[] segments) =>
        File.ReadAllText(Path.Combine([root, "src", "HIP.Web", .. segments]));

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
