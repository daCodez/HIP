namespace HIP.Tests.Api;

/// <summary>
/// Verifies the Second Life HUD simulator is reachable and its result panel remains readable in the dark admin shell.
/// </summary>
public sealed class AdminSecondLifeHudSimulatorPageTests
{
    /// <summary>
    /// Verifies the simulator page keeps the expected admin route and result panel content.
    /// </summary>
    [Test]
    public async Task Sl_hud_simulator_page_defines_admin_route_and_result_panel()
    {
        var razorPath = Path.Combine(FindRepositoryRoot(), "src", "HIP.Web", "Components", "Pages", "AdminSecondLifeHudSimulator.razor");
        var razor = await File.ReadAllTextAsync(razorPath);

        Assert.Multiple(() =>
        {
            Assert.That(razor, Does.Contain("@page \"/admin/sl-hud-simulator\""));
            Assert.That(razor, Does.Contain("SL HUD Simulator"));
            Assert.That(razor, Does.Contain("Result Panel"));
        });
    }

    /// <summary>
    /// Verifies simulator result cards use dark-theme colors so risk, score, and action values stay readable.
    /// </summary>
    [Test]
    public async Task Sl_hud_simulator_result_cards_use_readable_dark_theme_colors()
    {
        var cssPath = Path.Combine(FindRepositoryRoot(), "src", "HIP.Web", "wwwroot", "app.css");
        var css = await File.ReadAllTextAsync(cssPath);

        Assert.Multiple(() =>
        {
            Assert.That(css, Does.Contain(".simulation-grid span"));
            Assert.That(css, Does.Contain("color: #e5eef8;"));
            Assert.That(css, Does.Contain("background: #0b1b2a;"));
            Assert.That(css, Does.Contain("border: 1px solid #1f3a55;"));
            Assert.That(css, Does.Contain(".simulation-grid strong"));
            Assert.That(css, Does.Contain("color: #ffffff;"));
        });
    }

    /// <summary>
    /// Locates the repository root from the compiled test folder so CSS assertions work from any test runner.
    /// </summary>
    /// <returns>The absolute path to the HIP repository root.</returns>
    /// <exception cref="DirectoryNotFoundException">Thrown when the test cannot locate the solution file.</exception>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not find the HIP repository root for simulator CSS verification.");
    }
}
