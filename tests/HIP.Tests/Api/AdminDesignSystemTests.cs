namespace HIP.Tests.Api;

/// <summary>
/// Protects the approved HIP admin design system and theme behavior from visual regressions.
/// </summary>
public sealed class AdminDesignSystemTests
{
    [Test]
    public void Admin_styles_define_low_glare_light_and_dark_theme_tokens()
    {
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "control-center.css"));

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain("--bg:#f8fafc"));
            Assert.That(css, Does.Contain("--panel:#fff"));
            Assert.That(css, Does.Contain("--elevated:#f1f5f9"));
            Assert.That(css, Does.Contain("--primary:#1f6feb"));
            Assert.That(css, Does.Contain("--accent:#14b8a6"));
            Assert.That(css, Does.Contain("--quantum:#7c3aed"));
            Assert.That(css, Does.Contain("--bg:#0b1220"));
            Assert.That(css, Does.Contain("--panel:#111827"));
            Assert.That(css, Does.Contain("--elevated:#161e2e"));
            Assert.That(css, Does.Contain("'Satoshi'"));
            Assert.That(css, Does.Contain("'JetBrains Mono'"));
            Assert.That(css, Does.Not.Contain("linear-gradient"));
            Assert.That(css, Does.Contain("[data-theme=dark]"));
            Assert.That(css, Does.Contain(".hip-panel"));
            Assert.That(css, Does.Contain(".hip-metric-card"));
            Assert.That(css, Does.Contain(".hip-data-table"));
            Assert.That(css, Does.Contain("background-image:radial-gradient(var(--line) .65px,transparent .65px)"));
            Assert.That(css, Does.Not.Contain("data:image/svg+xml"));
            Assert.That(css, Does.Contain(".hip-two-column"));
        });
    }

    [Test]
    public void Admin_shell_uses_accessible_theme_control_and_persisted_theme_script()
    {
        var layout = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Layout", "ControlCenterLayout.razor"));
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));
        var script = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-shell.js"));

        Assert.Multiple(() =>
        {
            Assert.That(layout, Does.Contain("data-hip-theme-toggle"));
            Assert.That(layout, Does.Contain("aria-label=\"Switch to light mode\""));
            Assert.That(app, Does.Contain("admin-shell.js"));
            Assert.That(script, Does.Contain("hip-admin-theme"));
            Assert.That(script, Does.Contain("prefers-color-scheme"));
            Assert.That(script, Does.Contain("enhancedload"));
            Assert.That(script, Does.Contain("applySavedTheme"));
            Assert.That(script, Does.Contain("aria-label"));
        });
    }

    [Test]
    public void Admin_icon_rules_prevent_browser_default_svg_sizing()
    {
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "control-center.css"));

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain(".nav-item svg"));
            Assert.That(css, Does.Contain(".mark"));
            Assert.That(css, Does.Contain("width:16px"));
            Assert.That(css, Does.Contain("height:16px"));
        });
    }

    [Test]
    public void Admin_shell_loads_only_the_control_center_design_system()
    {
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(app, Does.Contain("control-center.css"));
            Assert.That(app, Does.Not.Contain("admin-control-center.css"));
            Assert.That(app, Does.Not.Contain("admin-design.css"));
            Assert.That(app, Does.Not.Contain("admin-nav-design.css"));
            Assert.That(app, Does.Not.Contain("admin-prototype.css"));
            Assert.That(app, Does.Not.Contain("admin-reference.css"));
        });
    }

    [Test]
    public void Dashboard_uses_reference_logo_neutral_threat_rows_and_no_footer_quick_links()
    {
        var dashboard = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Pages", "AdminDashboard.razor"));
        var navigation = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Layout", "ControlCenterNav.razor"));
        var appCss = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "app.css"));
        var designCss = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "control-center.css"));

        Assert.Multiple(() =>
        {
            Assert.That(dashboard, Does.Contain("HIP Admin · dashboard"));
            Assert.That(dashboard, Does.Contain("<h1>Overview</h1>"));
            Assert.That(dashboard, Does.Not.Contain("Recent Threats"));
            Assert.That(dashboard, Does.Not.Contain("Quick Links"));
            Assert.That(navigation, Does.Contain("src=\"/hip-logo-original.png\""));
            Assert.That(navigation, Does.Contain("alt=\"HIP\""));
            Assert.That(designCss, Does.Contain(".brand .mark{width:40px;height:41px"));
            Assert.That(designCss, Does.Not.Contain(".brand .mark-ring"));
            Assert.That(appCss, Does.Not.Contain(".hip-threat-table tr"));
            Assert.That(appCss, Does.Not.Contain(".hip-threat-table tbody tr:hover"));
            Assert.That(appCss, Does.Not.Contain("background: #122943"));
        });
    }

    [Test]
    public void Brand_kit_updates_ui_without_replacing_original_logo_or_icons()
    {
        var navigation = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Layout", "ControlCenterNav.razor"));
        var logoPath = WorkspaceFile("src", "HIP.Web", "wwwroot", "hip-logo-original.png");
        var logoHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(logoPath)))
            .ToLowerInvariant();

        Assert.Multiple(() =>
        {
            Assert.That(navigation, Does.Contain("alt=\"HIP\""));
            Assert.That(navigation, Does.Not.Contain("mark-ring"));
            Assert.That(navigation, Does.Contain("src=\"/hip-logo-original.png\""));
            Assert.That(navigation, Does.Contain("private static RenderFragment Icon"));
            Assert.That(navigation, Does.Contain("\"shield\" => Svg"));
            Assert.That(navigation, Does.Contain("\"eye\" => Svg"));
            Assert.That(navigation, Does.Contain("\"bolt\" => Svg"));
            Assert.That(navigation, Does.Contain("\"settings\" => Svg"));
            Assert.That(logoHash, Is.EqualTo("44dd2573c0a0bd53b02b8487b70363b559cbf27b232e896eeac40fe8a194640d"));
            Assert.That(navigation, Does.Not.Contain("brand_kit"));
            Assert.That(navigation, Does.Not.Contain("hip_brand_kit"));
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
