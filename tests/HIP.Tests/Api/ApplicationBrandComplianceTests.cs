namespace HIP.Tests.Api;

/// <summary>Protects the application-wide HIP brand-kit contract.</summary>
public sealed class ApplicationBrandComplianceTests
{
    [Test]
    public void Every_route_loads_the_canonical_brand_compliance_layer()
    {
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));
        var routes = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Routes.razor"));
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "brand-compliance.css"));
        Assert.Multiple(() =>
        {
            Assert.That(app, Does.Contain("brand-compliance.css"));
            Assert.That(routes, Does.Contain("DefaultLayout=\"typeof(Layout.ControlCenterLayout)\""));
            Assert.That(css, Does.Contain("HIP application-wide brand kit compliance layer"));
            Assert.That(css, Does.Contain("--brand-primary:#1f6feb"));
            Assert.That(css, Does.Contain("--brand-secondary:#14b8a6"));
            Assert.That(css, Does.Contain("--brand-accent:#7c3aed"));
            Assert.That(css, Does.Contain("--critical:#b91c1c"));
            Assert.That(css, Does.Contain("--space-unit:8px"));
            Assert.That(css, Does.Contain("'Satoshi'"));
            Assert.That(css, Does.Contain("'JetBrains Mono'"));
            Assert.That(css, Does.Contain("[data-theme=dark]"));
            Assert.That(css, Does.Contain(".hip-login-page"));
            Assert.That(css, Does.Contain(".hip-safety-page"));
            Assert.That(css, Does.Contain(".hip-lookup-page"));
            Assert.That(css, Does.Contain("prefers-reduced-motion:reduce"));
        });
    }

    private static string WorkspaceFile(params string[] segments)
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }
        Assert.That(directory, Is.Not.Null, "Unable to locate the HIP repository root.");
        return Path.Combine([directory!.FullName, .. segments]);
    }
}
