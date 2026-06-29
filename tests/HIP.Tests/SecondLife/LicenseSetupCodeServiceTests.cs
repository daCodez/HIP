using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.SecondLife;
using HIP.Application.SelfHealing;

namespace HIP.Tests.SecondLife;

/// <summary>
/// Verifies the setup code license manager used by the Second Life HUD activation flow.
/// </summary>
[TestFixture]
public sealed class LicenseSetupCodeServiceTests
{
    /// <summary>
    /// Confirms support/admin staff can create a setup code for a HUD buyer.
    /// </summary>
    [Test]
    public void Setup_code_can_be_created()
    {
        var service = new InMemorySetupCodeLicenseService();

        var response = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));

        Assert.Multiple(() =>
        {
            Assert.That(response.LicenseId, Is.Not.Empty);
            Assert.That(response.SetupCode, Does.StartWith("HIP-"));
            Assert.That(response.Status, Is.EqualTo(LicenseStatus.Pending));
        });
    }

    /// <summary>
    /// Confirms setup codes are unique so one buyer cannot guess another buyer's code.
    /// </summary>
    [Test]
    public void Setup_code_is_unique()
    {
        var service = new InMemorySetupCodeLicenseService();

        var first = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));
        var second = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));

        Assert.That(second.SetupCode, Is.Not.EqualTo(first.SetupCode));
    }

    /// <summary>
    /// Confirms generated setup codes are random-looking rather than sequential counters.
    /// </summary>
    [Test]
    public void Setup_code_is_not_sequential()
    {
        var service = new InMemorySetupCodeLicenseService();

        var codes = Enumerable.Range(0, 5)
            .Select(_ => service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal")).SetupCode)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(codes, Has.All.Not.Match(@"HIP-\d+$"));
            Assert.That(codes.Distinct(StringComparer.Ordinal).Count(), Is.EqualTo(codes.Length));
        });
    }

    /// <summary>
    /// Confirms valid setup codes activate the HUD without web login.
    /// </summary>
    [Test]
    public void Valid_setup_code_activates_hud()
    {
        var licenses = new InMemorySetupCodeLicenseService();
        var code = licenses.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));

        var response = licenses.ActivateHud(code.SetupCode, null, "avatar-hash", "0.1.0");

        Assert.Multiple(() =>
        {
            Assert.That(response.Activated, Is.True);
            Assert.That(response.LicenseStatus, Is.EqualTo(LicenseStatus.Active));
            Assert.That(response.DeviceId, Does.StartWith("sl-hud-"));
        });
    }

    /// <summary>
    /// Confirms invalid setup codes cannot activate a HUD.
    /// </summary>
    [Test]
    public void Invalid_setup_code_is_rejected()
    {
        var service = new InMemorySetupCodeLicenseService();

        var response = service.ActivateHud("not-a-real-code", null, null, "0.1.0");

        Assert.That(response.Activated, Is.False);
    }

    /// <summary>
    /// Confirms revoked codes are blocked after support/admin action.
    /// </summary>
    [Test]
    public void Revoked_setup_code_is_rejected()
    {
        var service = new InMemorySetupCodeLicenseService();
        var code = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));
        service.SetStatus(code.LicenseId, LicenseStatus.Revoked);

        var response = service.ActivateHud(code.SetupCode, null, null, "0.1.0");

        Assert.Multiple(() =>
        {
            Assert.That(response.Activated, Is.False);
            Assert.That(response.LicenseStatus, Is.EqualTo(LicenseStatus.Revoked));
        });
    }

    /// <summary>
    /// Confirms suspended codes are blocked but preserve their lifecycle status.
    /// </summary>
    [Test]
    public void Suspended_setup_code_is_rejected()
    {
        var service = new InMemorySetupCodeLicenseService();
        var code = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));
        service.SetStatus(code.LicenseId, LicenseStatus.Suspended);

        var response = service.ActivateHud(code.SetupCode, null, null, "0.1.0");

        Assert.That(response.LicenseStatus, Is.EqualTo(LicenseStatus.Suspended));
        Assert.That(response.Activated, Is.False);
    }

    /// <summary>
    /// Confirms activation returns default HUD settings so the LSL script can configure itself.
    /// </summary>
    [Test]
    public void Activation_returns_default_hud_settings()
    {
        var service = new InMemorySetupCodeLicenseService();
        var code = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", null));

        var response = service.ActivateHud(code.SetupCode, "hud-1", "avatar-hash", "0.1.0");

        Assert.Multiple(() =>
        {
            Assert.That(response.Settings.ScanMode, Is.EqualTo("Normal"));
            Assert.That(response.Settings.PrivateWarningsEnabled, Is.True);
            Assert.That(response.Settings.SafetyPageRoutingEnabled, Is.True);
        });
    }

    /// <summary>
    /// Confirms admin/support list views receive masked setup codes rather than raw secrets.
    /// </summary>
    [Test]
    public void Setup_code_is_masked_in_list_views()
    {
        var service = new InMemorySetupCodeLicenseService();
        var code = service.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Normal"));

        var listed = service.ListLicenses().Single(license => license.LicenseId == code.LicenseId);

        Assert.Multiple(() =>
        {
            Assert.That(listed.MaskedSetupCode, Is.Not.EqualTo(code.SetupCode));
            Assert.That(listed.MaskedSetupCode, Does.Contain("****"));
        });
    }

    /// <summary>
    /// Confirms the license service does not depend on a logger that could accidentally receive raw setup codes.
    /// </summary>
    [Test]
    public void Raw_setup_code_is_not_logged()
    {
        var constructorParameters = typeof(InMemorySetupCodeLicenseService)
            .GetConstructors()
            .SelectMany(constructor => constructor.GetParameters())
            .Select(parameter => parameter.ParameterType.Name)
            .ToArray();

        Assert.That(constructorParameters, Has.None.Contains("ILogger"));
    }

    /// <summary>
    /// Confirms unsupported scan modes are rejected before settings are stored.
    /// </summary>
    [Test]
    public void Invalid_scan_mode_is_rejected()
    {
        var service = new InMemorySetupCodeLicenseService();

        var response = service.SaveSettingsForDevice("hud-1", new LicenseHudSettings("Aggressive", true, true, true));

        Assert.That(response.Saved, Is.False);
    }

    /// <summary>
    /// Confirms the SL HUD service returns the setup-code-backed license settings in activation responses.
    /// </summary>
    [Test]
    public void Sl_hud_activation_uses_license_manager()
    {
        var licenses = new InMemorySetupCodeLicenseService();
        var code = licenses.CreateSetupCode(new CreateSetupCodeRequest(1, "support", "Strict"));
        var hud = HudService(licenses);

        var response = hud.Activate(new SecondLifeHudActivationRequest(code.SetupCode, null, "avatar-hash", "0.1.0"));

        Assert.Multiple(() =>
        {
            Assert.That(response.Activated, Is.True);
            Assert.That(response.LicenseStatus, Is.EqualTo("Active"));
            Assert.That(response.ClientConfig.Mode, Is.EqualTo("Strict"));
            Assert.That(response.Settings.Mode, Is.EqualTo("Strict"));
        });
    }

    /// <summary>
    /// Creates the HUD service with real MVP dependencies for license activation tests.
    /// </summary>
    /// <param name="licenses">License manager under test.</param>
    /// <returns>A HUD service using the supplied license manager.</returns>
    private static SecondLifeHudService HudService(ISetupCodeLicenseService licenses)
    {
        var ingestion = new RiskFindingIngestionService(
            new RiskFindingReportValidator(),
            new InMemoryRiskFindingReportRepository(),
            new ReviewQueueService(new ReviewItemValidator(), new InMemoryReviewQueueRepository(), new AuditLogService(new InMemoryAuditLogRepository())),
            new PatternDetectionService(),
            new Sha256PrivacyHashingService());

        return new SecondLifeHudService(ingestion, licenses);
    }
}
