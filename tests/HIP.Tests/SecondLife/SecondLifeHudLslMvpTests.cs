namespace HIP.Tests.SecondLife;

/// <summary>
/// Verifies the checked-in Second Life LSL MVP script keeps the expected HIP API, safety-routing, and privacy contract.
/// </summary>
[TestFixture]
public sealed class SecondLifeHudLslMvpTests
{
    /// <summary>
    /// Confirms the LSL MVP calls the current versioned SL HUD API routes instead of stale or unversioned endpoints.
    /// </summary>
    [Test]
    public void Lsl_mvp_uses_current_sl_hud_api_routes()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("/api/v1/sl-hud/activate"));
            Assert.That(script, Does.Contain("/api/v1/sl-hud/scan"));
            Assert.That(script, Does.Contain("/api/v1/sl-hud/settings/"));
            Assert.That(script, Does.Contain("/api/v1/sl-hud/report"));
        });
    }

    /// <summary>
    /// Confirms local detection covers the MVP suspicious-link patterns before sending minimal findings to HIP.
    /// </summary>
    [Test]
    public void Lsl_mvp_detects_shortened_broken_up_and_obfuscated_links()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("HipLooksShortened"));
            Assert.That(script, Does.Contain("bit.ly/"));
            Assert.That(script, Does.Contain("HipLooksBrokenUp"));
            Assert.That(script, Does.Contain("hxxps://"));
            Assert.That(script, Does.Contain(" dot "));
            Assert.That(script, Does.Contain("HipLooksObfuscated"));
        });
    }

    /// <summary>
    /// Ensures risk notices stay owner-private and optional popups are controlled by the HUD settings.
    /// </summary>
    [Test]
    public void Lsl_mvp_warns_owner_only_and_supports_popup_alerts()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("llOwnerSay"));
            Assert.That(script, Does.Contain("llDialog"));
            Assert.That(script, Does.Contain("HIP_POPUP_ALERTS_ENABLED"));
            Assert.That(script, Does.Contain("HIP_PRIVATE_WARNINGS_ENABLED"));
            Assert.That(script, Does.Not.Contain("llSay("));
        });
    }

    /// <summary>
    /// Ensures risky links route through the HIP safety page flow instead of claiming platform-level blocking.
    /// </summary>
    [Test]
    public void Lsl_mvp_routes_safety_page_without_claiming_true_blocking()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("llLoadURL"));
            Assert.That(script, Does.Contain("gPendingSafetyPageUrl"));
            Assert.That(script, Does.Contain("HIP_SAFETY_ROUTING_ENABLED"));
            Assert.That(script, Does.Contain("Open Safety"));
            Assert.That(script, Does.Contain("cannot enforce browser-style blocking"));
        });
    }

    /// <summary>
    /// Confirms the script validates mode values before applying or saving remote settings.
    /// </summary>
    [Test]
    public void Lsl_mvp_rejects_invalid_mode_before_saving_settings()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("IsValidMode"));
            Assert.That(script, Does.Contain("\"Quiet\""));
            Assert.That(script, Does.Contain("\"Normal\""));
            Assert.That(script, Does.Contain("\"Strict\""));
            Assert.That(script, Does.Contain("\"Paranoid\""));
            Assert.That(script, Does.Contain("invalid mode"));
        });
    }

    /// <summary>
    /// Verifies report payload construction avoids obvious private-content fields and keeps snippets limited.
    /// </summary>
    [Test]
    public void Lsl_mvp_avoids_full_chat_log_payload_fields()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("LimitedSuspiciousSnippet"));
            Assert.That(script, Does.Not.Contain("JsonPair(\"chatLog\""));
            Assert.That(script, Does.Not.Contain("JsonPair(\"privateImLog\""));
            Assert.That(script, Does.Not.Contain("JsonPair(\"messageBody\""));
        });
    }

    /// <summary>
    /// Confirms the marketplace demo is explicitly local-only and guards every network-producing operation.
    /// </summary>
    [Test]
    public void Lsl_mvp_demo_mode_is_local_only()
    {
        var script = ReadHudScript();

        Assert.Multiple(() =>
        {
            Assert.That(script, Does.Contain("integer HIP_DEMO_MODE = FALSE"));
            Assert.That(script, Does.Contain("Demo (local-only)"));
            Assert.That(script, Does.Contain("does not contact HIP or upload chat, URLs, identifiers, or reports"));
            Assert.That(CountOccurrences(script, "if (HIP_DEMO_MODE)"), Is.GreaterThanOrEqualTo(6));
            Assert.That(script, Does.Contain("WarnOwner(\"Medium\", gPendingRiskReason, \"PrivateWarning\", \"\")"));
        });
    }

    /// <summary>
    /// Verifies buyer and merchant setup guidance covers safe setup-code handling and honest demo limitations.
    /// </summary>
    [Test]
    public void Marketplace_setup_documents_safe_activation_and_demo_packaging()
    {
        var root = FindRepositoryRoot();
        var setup = File.ReadAllText(Path.Combine(root, "clients", "second-life-hud", "docs", "setup.md"));
        var marketplace = File.ReadAllText(Path.Combine(root, "clients", "second-life-hud", "docs", "marketplace-setup.md"));

        Assert.Multiple(() =>
        {
            Assert.That(setup, Does.Contain("one-time setup code"));
            Assert.That(setup, Does.Contain("does not upload full chat or IM logs"));
            Assert.That(marketplace, Does.Contain("HIP Shield Demo - Local Only"));
            Assert.That(marketplace, Does.Contain("Do not ship development hostnames"));
            Assert.That(marketplace, Does.Contain("Marketplace billing and entitlement verification remain external"));
        });
    }

    /// <summary>
    /// Confirms the HUD documentation states the actual platform limits for local chat, group chat, and IM scanning.
    /// </summary>
    [Test]
    public void Documentation_states_lsl_chat_access_limitations()
    {
        var limitations = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "clients", "second-life-hud", "docs", "limitations.md"));

        Assert.Multiple(() =>
        {
            Assert.That(limitations, Does.Contain("nearby/local chat"));
            Assert.That(limitations, Does.Contain("cannot reliably inspect every group chat or private IM"));
            Assert.That(limitations, Does.Contain("must never upload full IM logs"));
            Assert.That(limitations, Does.Contain("cannot enforce true blocking"));
        });
    }

    /// <summary>
    /// Reads the checked-in LSL MVP script from the repository.
    /// </summary>
    /// <returns>The LSL script contents.</returns>
    private static string ReadHudScript()
    {
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), "clients", "second-life-hud", "scripts", "HIP_HUD_MVP.lsl"));
    }

    private static int CountOccurrences(string value, string search) =>
        value.Split(search, StringSplitOptions.None).Length - 1;

    /// <summary>
    /// Finds the repository root from the test output directory without relying on a fixed machine path.
    /// </summary>
    /// <returns>The absolute repository root path.</returns>
    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
