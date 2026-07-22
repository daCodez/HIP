using HIP.Application.Reporting;
using HIP.Application.SecondLife;

namespace HIP.Tests.SecondLife;

/// <summary>
/// Verifies planned privacy-key rotation for stateless HUD device credentials.
/// </summary>
public sealed class HudDeviceCredentialPrivacyKeyRotationTests
{
    private const string CurrentKey = "hud-current-privacy-key-material";
    private const string LegacyKey = "hud-legacy-privacy-key-material";

    [Test]
    public void Rotated_validator_accepts_a_legacy_credential_during_the_configured_grace_window()
    {
        var oldService = Service(LegacyKey);
        var rotatedService = Service(CurrentKey, [LegacyKey]);
        var credential = oldService.Issue("license-123", "hud-device-456");

        var licenseId = rotatedService.ValidateAndGetLicenseId("hud-device-456", credential);

        Assert.That(licenseId, Is.EqualTo("license-123"));
    }

    [Test]
    public void Rotated_issuer_uses_only_the_current_key()
    {
        var oldService = Service(LegacyKey);
        var currentService = Service(CurrentKey);
        var rotatedService = Service(CurrentKey, [LegacyKey]);

        var credential = rotatedService.Issue("license-123", "hud-device-456");

        Assert.Multiple(() =>
        {
            Assert.That(
                currentService.ValidateAndGetLicenseId("hud-device-456", credential),
                Is.EqualTo("license-123"));
            Assert.That(oldService.ValidateAndGetLicenseId("hud-device-456", credential), Is.Null);
        });
    }

    [Test]
    public void Legacy_credential_fails_after_the_legacy_key_is_removed()
    {
        var oldService = Service(LegacyKey);
        var currentService = Service(CurrentKey);
        var credential = oldService.Issue("license-123", "hud-device-456");

        var licenseId = currentService.ValidateAndGetLicenseId("hud-device-456", credential);

        Assert.That(licenseId, Is.Null);
    }

    private static HudDeviceCredentialService Service(
        string currentKey,
        IReadOnlyCollection<string>? legacyKeys = null) =>
        new(new PrivacyHashingOptions(
            currentKey,
            AllowDevelopmentKey: false,
            LegacyKeys: legacyKeys));
}
