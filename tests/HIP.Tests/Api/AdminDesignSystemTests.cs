namespace HIP.Tests.Api;

/// <summary>
/// Protects the approved HIP admin design system and theme behavior from visual regressions.
/// </summary>
public sealed class AdminDesignSystemTests
{
    [Test]
    public void Admin_styles_define_low_glare_light_and_dark_theme_tokens()
    {
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-control-center.css"));

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain("--cc-bg: #d9dfe1"));
            Assert.That(css, Does.Contain("--cc-panel: #edf0f1"));
            Assert.That(css, Does.Contain("[data-theme=\"dark\"]"));
            Assert.That(css, Does.Contain(".hip-panel"));
            Assert.That(css, Does.Contain(".hip-metric-card"));
            Assert.That(css, Does.Contain(".hip-data-table"));
            Assert.That(css, Does.Contain(".hip-toggle"));
        });
    }

    [Test]
    public void Admin_shell_uses_accessible_theme_control_and_persisted_theme_script()
    {
        var layout = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Layout", "MainLayout.razor"));
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));
        var script = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-shell.js"));

        Assert.Multiple(() =>
        {
            Assert.That(layout, Does.Contain("data-hip-theme-toggle"));
            Assert.That(layout, Does.Contain("aria-label=\"Switch to light mode\""));
            Assert.That(app, Does.Contain("admin-shell.js"));
            Assert.That(script, Does.Contain("hip-admin-theme"));
            Assert.That(script, Does.Contain("prefers-color-scheme"));
            Assert.That(script, Does.Contain("aria-label"));
        });
    }

    [Test]
    public void Admin_icon_rules_prevent_browser_default_svg_sizing()
    {
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-control-center.css"));

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain(".hip-nav-icon svg"));
            Assert.That(css, Does.Contain(".hip-mark"));
            Assert.That(css, Does.Contain("width: 16px"));
            Assert.That(css, Does.Contain("height: 16px"));
        });
    }

    [Test]
    public void Admin_shell_loads_only_the_control_center_design_system()
    {
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(app, Does.Contain("admin-control-center.css"));
            Assert.That(app, Does.Contain("admin-control-center-layout.css"));
            Assert.That(app, Does.Not.Contain("admin-design.css"));
            Assert.That(app, Does.Not.Contain("admin-nav-design.css"));
            Assert.That(app, Does.Not.Contain("admin-prototype.css"));
            Assert.That(app, Does.Not.Contain("admin-reference.css"));
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
