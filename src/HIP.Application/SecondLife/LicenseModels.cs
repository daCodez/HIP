using System.Security.Cryptography;

namespace HIP.Application.SecondLife;

/// <summary>
/// Represents the lifecycle state for a setup code license used by a Second Life HUD.
/// </summary>
public enum LicenseStatus
{
    /// <summary>
    /// The setup code exists but has not activated a HUD yet.
    /// </summary>
    Pending,

    /// <summary>
    /// The setup code can activate or continue using linked HUD devices.
    /// </summary>
    Active,

    /// <summary>
    /// The setup code is temporarily blocked by support or admin staff.
    /// </summary>
    Suspended,

    /// <summary>
    /// The setup code has been permanently revoked for the MVP flow.
    /// </summary>
    Revoked,

    /// <summary>
    /// The setup code is no longer valid because its validity window has ended.
    /// </summary>
    Expired
}

/// <summary>
/// Stores configurable HUD alert behavior linked to a license or device.
/// </summary>
/// <param name="ScanMode">The HUD scan mode: Quiet, Normal, Strict, or Paranoid.</param>
/// <param name="PopupAlertsEnabled">Whether high-risk detections may show popup alerts.</param>
/// <param name="PrivateWarningsEnabled">Whether owner-only chat warnings are enabled.</param>
/// <param name="SafetyPageRoutingEnabled">Whether risky links should route through the HIP safety page.</param>
public sealed record LicenseHudSettings(
    string ScanMode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyPageRoutingEnabled);

/// <summary>
/// Represents a setup code license without storing private Second Life account data.
/// </summary>
/// <param name="LicenseId">Stable internal license identifier.</param>
/// <param name="SetupCode">Raw setup code. This is returned only on creation or internal activation checks.</param>
/// <param name="Status">Current license status.</param>
/// <param name="AllowedDeviceCount">Maximum number of HUD devices that can be activated by this setup code.</param>
/// <param name="DeviceIds">Linked HUD device IDs.</param>
/// <param name="AvatarIdHash">Optional hashed avatar identity; never the raw avatar name.</param>
/// <param name="ActivatedAtUtc">First activation time, if activated.</param>
/// <param name="LastSeenAtUtc">Most recent activation/settings touch time.</param>
/// <param name="HudVersion">Most recent HUD version reported by a client.</param>
/// <param name="Settings">HUD alert and scan settings.</param>
public sealed record SetupCodeLicense(
    string LicenseId,
    string SetupCode,
    LicenseStatus Status,
    int AllowedDeviceCount,
    IReadOnlyCollection<string> DeviceIds,
    string? AvatarIdHash,
    DateTimeOffset? ActivatedAtUtc,
    DateTimeOffset? LastSeenAtUtc,
    string? HudVersion,
    LicenseHudSettings Settings);

/// <summary>
/// Request used by support/admin staff to create a hard-to-guess setup code.
/// </summary>
/// <param name="AllowedDeviceCount">Optional device count limit. Defaults to one device.</param>
/// <param name="CreatedBy">Admin/support actor creating the setup code.</param>
/// <param name="InitialScanMode">Optional initial scan mode for the HUD.</param>
public sealed record CreateSetupCodeRequest(
    int? AllowedDeviceCount,
    string? CreatedBy,
    string? InitialScanMode);

/// <summary>
/// Response returned immediately after setup code creation. It is the only list-safe response that may include the raw code.
/// </summary>
/// <param name="LicenseId">Created license identifier.</param>
/// <param name="SetupCode">Raw setup code for delivery to the buyer.</param>
/// <param name="MaskedSetupCode">Masked version safe for admin lists.</param>
/// <param name="Status">Current license status.</param>
/// <param name="AllowedDeviceCount">Maximum linked device count.</param>
public sealed record CreateSetupCodeResponse(
    string LicenseId,
    string SetupCode,
    string MaskedSetupCode,
    LicenseStatus Status,
    int AllowedDeviceCount);

/// <summary>
/// List/detail DTO that masks setup codes by default to avoid exposing secrets in admin screens.
/// </summary>
/// <param name="LicenseId">Internal license identifier.</param>
/// <param name="MaskedSetupCode">Masked setup code safe for list views.</param>
/// <param name="Status">Current license status.</param>
/// <param name="ActivationCount">Number of linked HUD devices.</param>
/// <param name="AllowedDeviceCount">Maximum linked HUD devices.</param>
/// <param name="DeviceIds">Linked device IDs for support workflows.</param>
/// <param name="ActivatedAtUtc">First activation time, if present.</param>
/// <param name="LastSeenAtUtc">Most recent activity time, if present.</param>
/// <param name="HudVersion">Most recent HUD version, if present.</param>
/// <param name="Settings">Current HUD settings.</param>
public sealed record LicenseSummary(
    string LicenseId,
    string MaskedSetupCode,
    LicenseStatus Status,
    int ActivationCount,
    int AllowedDeviceCount,
    IReadOnlyCollection<string> DeviceIds,
    DateTimeOffset? ActivatedAtUtc,
    DateTimeOffset? LastSeenAtUtc,
    string? HudVersion,
    LicenseHudSettings Settings);

/// <summary>
/// Result of activating a Second Life HUD with a setup code.
/// </summary>
/// <param name="Activated">Whether activation succeeded.</param>
/// <param name="LicenseId">License identifier when activation succeeds.</param>
/// <param name="LicenseStatus">Current license status.</param>
/// <param name="DeviceId">HUD device ID that should be stored by the script.</param>
/// <param name="Message">Plain-English status for the HUD owner.</param>
/// <param name="Settings">HUD settings returned to the script.</param>
/// <param name="ActivatedAtUtc">Activation timestamp when available.</param>
public sealed record LicenseActivationResult(
    bool Activated,
    string? LicenseId,
    LicenseStatus LicenseStatus,
    string? DeviceId,
    string Message,
    LicenseHudSettings Settings,
    DateTimeOffset? ActivatedAtUtc);

/// <summary>
/// Contract for setup code license operations used by admin/support APIs and SL HUD activation.
/// </summary>
public interface ISetupCodeLicenseService
{
    /// <summary>
    /// Creates a unique setup code and stores it for later HUD activation.
    /// </summary>
    /// <param name="request">Creation options supplied by admin/support users.</param>
    /// <returns>The created setup code response, including the raw code once.</returns>
    CreateSetupCodeResponse CreateSetupCode(CreateSetupCodeRequest request);

    /// <summary>
    /// Lists licenses with masked setup codes so admin list views do not expose secrets.
    /// </summary>
    /// <returns>All current setup code licenses as safe summaries.</returns>
    IReadOnlyCollection<LicenseSummary> ListLicenses();

    /// <summary>
    /// Lists licenses asynchronously so persistent providers never block a Blazor rendering context.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel the storage query.</param>
    /// <returns>All current setup code licenses as safe summaries.</returns>
    Task<IReadOnlyCollection<LicenseSummary>> ListLicensesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets one license by ID with masked setup code data.
    /// </summary>
    /// <param name="licenseId">License identifier.</param>
    /// <returns>The safe license summary, or null if not found.</returns>
    LicenseSummary? GetLicense(string licenseId);

    /// <summary>
    /// Activates a HUD using a setup code without requiring the owner to sign in to the web portal.
    /// </summary>
    /// <param name="setupCode">Setup code supplied in the HUD config.</param>
    /// <param name="hudDeviceId">Optional existing HUD device ID.</param>
    /// <param name="avatarIdHash">Optional hashed avatar identity.</param>
    /// <param name="hudVersion">HUD script version.</param>
    /// <returns>The activation result with settings and status.</returns>
    LicenseActivationResult ActivateHud(string setupCode, string? hudDeviceId, string? avatarIdHash, string? hudVersion);

    /// <summary>
    /// Resets linked device activation for support workflows while keeping the setup code.
    /// </summary>
    /// <param name="licenseId">License identifier.</param>
    /// <returns>The updated license summary, or null if not found.</returns>
    LicenseSummary? ResetActivation(string licenseId);

    /// <summary>
    /// Changes the license status for support/admin lifecycle actions.
    /// </summary>
    /// <param name="licenseId">License identifier.</param>
    /// <param name="status">New license status.</param>
    /// <returns>The updated license summary, or null if not found.</returns>
    LicenseSummary? SetStatus(string licenseId, LicenseStatus status);

    /// <summary>
    /// Gets HUD settings by linked device ID using safe defaults when the device is unknown.
    /// </summary>
    /// <param name="deviceId">HUD device ID.</param>
    /// <returns>Current HUD settings.</returns>
    LicenseHudSettings GetSettingsForDevice(string deviceId);

    /// <summary>
    /// Saves HUD settings for a linked or development device.
    /// </summary>
    /// <param name="deviceId">HUD device ID.</param>
    /// <param name="settings">Settings to save after validation.</param>
    /// <returns>True when settings were saved; otherwise false with the current/default settings.</returns>
    (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(string deviceId, LicenseHudSettings settings);
}

/// <summary>
/// In-memory setup code manager for MVP and development use. It avoids sequential codes and masks secrets in list views.
/// </summary>
public sealed class InMemorySetupCodeLicenseService : ISetupCodeLicenseService
{
    private static readonly object Gate = new();
    private static readonly Dictionary<string, SetupCodeLicense> LicensesById = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, string> LicenseIdsBySetupCode = new(StringComparer.Ordinal);
    private static readonly HashSet<string> ValidModes = new(StringComparer.OrdinalIgnoreCase) { "Quiet", "Normal", "Strict", "Paranoid" };
    private static readonly LicenseHudSettings DefaultSettings = new("Normal", true, true, true);

    /// <summary>
    /// Initializes the MVP service and seeds a development setup code used by existing local HUD scripts.
    /// </summary>
    public InMemorySetupCodeLicenseService()
    {
        EnsureDevelopmentCode();
    }

    /// <inheritdoc />
    public CreateSetupCodeResponse CreateSetupCode(CreateSetupCodeRequest request)
    {
        var allowedDevices = request.AllowedDeviceCount is > 0 and <= 25 ? request.AllowedDeviceCount.Value : 1;
        var mode = IsValidMode(request.InitialScanMode) ? request.InitialScanMode! : DefaultSettings.ScanMode;
        var settings = DefaultSettings with { ScanMode = mode };

        lock (Gate)
        {
            var setupCode = GenerateUniqueSetupCode();
            var license = new SetupCodeLicense(
                $"lic-{Guid.NewGuid():N}",
                setupCode,
                LicenseStatus.Pending,
                allowedDevices,
                Array.Empty<string>(),
                null,
                null,
                null,
                null,
                settings);

            LicensesById[license.LicenseId] = license;
            LicenseIdsBySetupCode[setupCode] = license.LicenseId;

            return new CreateSetupCodeResponse(license.LicenseId, setupCode, MaskSetupCode(setupCode), license.Status, allowedDevices);
        }
    }

    /// <inheritdoc />
    public IReadOnlyCollection<LicenseSummary> ListLicenses()
    {
        lock (Gate)
        {
            return LicensesById.Values.Select(ToSummary).OrderBy(summary => summary.MaskedSetupCode, StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<LicenseSummary>> ListLicensesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(ListLicenses());
    }

    /// <inheritdoc />
    public LicenseSummary? GetLicense(string licenseId)
    {
        lock (Gate)
        {
            return LicensesById.TryGetValue(licenseId, out var license) ? ToSummary(license) : null;
        }
    }

    /// <inheritdoc />
    public LicenseActivationResult ActivateHud(string setupCode, string? hudDeviceId, string? avatarIdHash, string? hudVersion)
    {
        if (string.IsNullOrWhiteSpace(setupCode))
        {
            return FailedActivation(LicenseStatus.Pending, "Setup code is required.");
        }

        lock (Gate)
        {
            if (!LicenseIdsBySetupCode.TryGetValue(setupCode.Trim(), out var licenseId) ||
                !LicensesById.TryGetValue(licenseId, out var license))
            {
                return FailedActivation(LicenseStatus.Pending, "Setup code was not accepted.");
            }

            if (license.Status is LicenseStatus.Revoked or LicenseStatus.Suspended or LicenseStatus.Expired)
            {
                return FailedActivation(license.Status, "This setup code is not active.");
            }

            var deviceIds = license.DeviceIds.ToList();
            var deviceId = string.IsNullOrWhiteSpace(hudDeviceId)
                ? $"sl-hud-{Convert.ToHexString(RandomNumberGenerator.GetBytes(9)).ToLowerInvariant()}"
                : hudDeviceId.Trim();

            if (!deviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))
            {
                if (deviceIds.Count >= license.AllowedDeviceCount)
                {
                    return FailedActivation(license.Status, "This setup code has reached its device limit.");
                }

                deviceIds.Add(deviceId);
            }

            var now = DateTimeOffset.UtcNow;
            var updated = license with
            {
                Status = LicenseStatus.Active,
                DeviceIds = deviceIds,
                AvatarIdHash = string.IsNullOrWhiteSpace(avatarIdHash) ? license.AvatarIdHash : avatarIdHash.Trim(),
                ActivatedAtUtc = license.ActivatedAtUtc ?? now,
                LastSeenAtUtc = now,
                HudVersion = string.IsNullOrWhiteSpace(hudVersion) ? license.HudVersion : hudVersion.Trim()
            };

            LicensesById[updated.LicenseId] = updated;
            return new LicenseActivationResult(true, updated.LicenseId, updated.Status, deviceId, "HIP SL HUD activated.", updated.Settings, updated.ActivatedAtUtc);
        }
    }

    /// <inheritdoc />
    public LicenseSummary? ResetActivation(string licenseId)
    {
        lock (Gate)
        {
            if (!LicensesById.TryGetValue(licenseId, out var license))
            {
                return null;
            }

            var updated = license with
            {
                Status = LicenseStatus.Pending,
                DeviceIds = Array.Empty<string>(),
                AvatarIdHash = null,
                ActivatedAtUtc = null,
                LastSeenAtUtc = null,
                HudVersion = null
            };
            LicensesById[licenseId] = updated;
            return ToSummary(updated);
        }
    }

    /// <inheritdoc />
    public LicenseSummary? SetStatus(string licenseId, LicenseStatus status)
    {
        lock (Gate)
        {
            if (!LicensesById.TryGetValue(licenseId, out var license))
            {
                return null;
            }

            var updated = license with { Status = status, LastSeenAtUtc = DateTimeOffset.UtcNow };
            LicensesById[licenseId] = updated;
            return ToSummary(updated);
        }
    }

    /// <inheritdoc />
    public LicenseHudSettings GetSettingsForDevice(string deviceId)
    {
        lock (Gate)
        {
            return LicensesById.Values.FirstOrDefault(license => license.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))?.Settings
                ?? DefaultSettings;
        }
    }

    /// <inheritdoc />
    public (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(string deviceId, LicenseHudSettings settings)
    {
        if (!IsValidMode(settings.ScanMode))
        {
            return (false, "Invalid HUD mode.", GetSettingsForDevice(deviceId));
        }

        lock (Gate)
        {
            var license = LicensesById.Values.FirstOrDefault(candidate => candidate.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase));
            if (license is null)
            {
                return (true, "HUD settings saved for development device.", settings);
            }

            var updated = license with { Settings = settings, LastSeenAtUtc = DateTimeOffset.UtcNow };
            LicensesById[updated.LicenseId] = updated;
            return (true, "HUD settings saved.", settings);
        }
    }

    /// <summary>
    /// Seeds a non-production setup code so existing local HUD docs and tests keep working.
    /// </summary>
    private static void EnsureDevelopmentCode()
    {
        lock (Gate)
        {
            if (LicenseIdsBySetupCode.ContainsKey("HIP-DEV-SETUP"))
            {
                return;
            }

            var license = new SetupCodeLicense(
                "lic-development",
                "HIP-DEV-SETUP",
                LicenseStatus.Pending,
                25,
                Array.Empty<string>(),
                null,
                null,
                null,
                null,
                DefaultSettings);
            LicensesById[license.LicenseId] = license;
            LicenseIdsBySetupCode[license.SetupCode] = license.LicenseId;
        }
    }

    /// <summary>
    /// Generates a unique, random setup code using cryptographic randomness instead of sequential IDs.
    /// </summary>
    /// <returns>A setup code grouped for human entry.</returns>
    private static string GenerateUniqueSetupCode()
    {
        string setupCode;
        do
        {
            setupCode = $"HIP-{RandomSegment()}-{RandomSegment()}-{RandomSegment()}";
        }
        while (LicenseIdsBySetupCode.ContainsKey(setupCode));

        return setupCode;
    }

    /// <summary>
    /// Generates one uppercase random code segment with ambiguous characters removed.
    /// </summary>
    /// <returns>A six-character random segment.</returns>
    private static string RandomSegment()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        Span<byte> bytes = stackalloc byte[6];
        RandomNumberGenerator.Fill(bytes);
        return new string(bytes.ToArray().Select(value => alphabet[value % alphabet.Length]).ToArray());
    }

    /// <summary>
    /// Converts a license to a list-safe DTO that never returns the raw setup code.
    /// </summary>
    /// <param name="license">The internal license record.</param>
    /// <returns>A masked license summary.</returns>
    private static LicenseSummary ToSummary(SetupCodeLicense license) =>
        new(
            license.LicenseId,
            MaskSetupCode(license.SetupCode),
            license.Status,
            license.DeviceIds.Count,
            license.AllowedDeviceCount,
            license.DeviceIds,
            license.ActivatedAtUtc,
            license.LastSeenAtUtc,
            license.HudVersion,
            license.Settings);

    /// <summary>
    /// Masks setup codes for list/detail screens while retaining enough characters for support identification.
    /// </summary>
    /// <param name="setupCode">Raw setup code.</param>
    /// <returns>A masked setup code.</returns>
    private static string MaskSetupCode(string setupCode)
    {
        if (setupCode.Length <= 8)
        {
            return "****";
        }

        return $"{setupCode[..4]}******{setupCode[^4..]}";
    }

    /// <summary>
    /// Creates a failed activation result with safe default settings.
    /// </summary>
    /// <param name="status">Status explaining why the license is not active.</param>
    /// <param name="message">Plain-English failure message.</param>
    /// <returns>A failed activation result.</returns>
    private static LicenseActivationResult FailedActivation(LicenseStatus status, string message) =>
        new(false, null, status, null, message, DefaultSettings, null);

    /// <summary>
    /// Validates scan modes before storing user-controllable settings.
    /// </summary>
    /// <param name="mode">Scan mode to validate.</param>
    /// <returns>True when the mode is supported.</returns>
    private static bool IsValidMode(string? mode) =>
        !string.IsNullOrWhiteSpace(mode) && ValidModes.Contains(mode);
}
