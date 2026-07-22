namespace HIP.Tests.Api;

public sealed class AdminEditorialPortalTests
{
    [Test]
    public void Editorial_design_is_scoped_to_admin_routes_only()
    {
        var layout = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "Layout", "ControlCenterLayout.razor"));
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-editorial.css"));
        Assert.Multiple(() =>
        {
            Assert.That(layout, Does.Contain("IsAdminPortal"));
            Assert.That(layout, Does.Contain("route.StartsWith(\"admin/\""));
            Assert.That(layout, Does.Not.Contain("route.StartsWith(\"consumer/\""));
            Assert.That(css, Does.Contain(".app.admin-portal"));
            Assert.That(css, Does.Not.Contain(".consumer-portal"));
        });
    }

    [Test]
    public void Editorial_design_supports_theme_responsiveness_and_accessibility()
    {
        var app = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "Components", "App.razor"));
        var css = File.ReadAllText(WorkspaceFile("src", "HIP.Web", "wwwroot", "admin-editorial.css"));
        Assert.Multiple(() =>
        {
            Assert.That(app, Does.Contain("admin-editorial.css"));
            Assert.That(css, Does.Contain("[data-theme=\"dark\"] .app.admin-portal"));
            Assert.That(css, Does.Contain("@media(max-width:1100px)"));
            Assert.That(css, Does.Contain("@media(max-width:720px)"));
            Assert.That(css, Does.Contain("overflow-x:auto"));
            Assert.That(css, Does.Contain(":focus-visible"));
            Assert.That(css, Does.Contain("@media(prefers-reduced-motion:reduce)"));
        });
    }

    private static string WorkspaceFile(params string[] segments)
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            directory = directory.Parent;
        Assert.That(directory, Is.Not.Null, "Unable to locate the HIP repository root.");
        return Path.Combine([directory!.FullName, .. segments]);
    }
}
