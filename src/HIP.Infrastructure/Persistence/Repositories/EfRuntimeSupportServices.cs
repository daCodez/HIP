using System.Security.Cryptography;
using System.Text;
using HIP.Application.SecondLife;
using HIP.Application.Security;
using HIP.Application.SiteSafety;
using HIP.Infrastructure.Persistence;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Stores Second Life setup-code licenses in encrypted PostgreSQL-backed HIP records instead of process memory.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfSetupCodeLicenseService(HipRecordStore store, TimeProvider? timeProvider = null) : ISetupCodeLicenseService
{
    private const string Partition = "setup-code-licenses";
    private const int MaxWriteAttempts = 8;
    private static readonly HashSet<string> ValidModes = new(StringComparer.OrdinalIgnoreCase) { "Quiet", "Normal", "Strict", "Paranoid" };
    private static readonly LicenseHudSettings DefaultSettings = new("Normal", true, true, true);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public CreateSetupCodeResponse CreateSetupCode(CreateSetupCodeRequest request)
    {
        var allowedDevices = request.AllowedDeviceCount is > 0 and <= 25 ? request.AllowedDeviceCount.Value : 1;
        var validForHours = request.ValidForHours is > 0 and <= 168 ? request.ValidForHours.Value : 24;
        var mode = IsValidMode(request.InitialScanMode) ? request.InitialScanMode! : DefaultSettings.ScanMode;
        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var setupCode = $"HIP-{RandomSegment()}-{RandomSegment()}-{RandomSegment()}";
            var now = clock.GetUtcNow();
            var license = new SetupCodeLicense(
                $"lic-{Guid.NewGuid():N}",
                setupCode,
                LicenseStatus.Pending,
                allowedDevices,
                [],
                null,
                null,
                null,
                null,
                DefaultSettings with { ScanMode = mode },
                string.IsNullOrWhiteSpace(request.CreatedBy) ? null : request.CreatedBy.Trim(),
                Version: 1,
                SetupCodeExpiresAtUtc: now.AddHours(validForHours));

            if (Run(() => store.TrySaveVersionedAsync(
                    Partition,
                    license.LicenseId,
                    license,
                    expectedVersion: 0,
                    newVersion: license.Version,
                    cancellationToken: CancellationToken.None)))
            {
                return new CreateSetupCodeResponse(
                    license.LicenseId,
                    setupCode,
                    MaskSetupCode(setupCode),
                    license.Status,
                    allowedDevices,
                    license.SetupCodeExpiresAtUtc);
            }
        }

        throw new InvalidOperationException("HIP could not create a setup-code license after repeated write conflicts.");
    }

    /// <inheritdoc />
    public IReadOnlyCollection<LicenseSummary> ListLicenses() =>
        List().Select(ToSummary).OrderBy(summary => summary.MaskedSetupCode, StringComparer.OrdinalIgnoreCase).ToArray();

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<LicenseSummary>> ListLicensesAsync(CancellationToken cancellationToken = default)
    {
        var licenses = await store.ListAsync<SetupCodeLicense>(Partition, cancellationToken);
        return licenses
            .Select(ToSummary)
            .OrderBy(summary => summary.MaskedSetupCode, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <inheritdoc />
    public LicenseSummary? GetLicense(string licenseId) =>
        GetVersionedById(licenseId) is { } stored ? ToSummary(stored.License) : null;

    /// <inheritdoc />
    public LicenseActivationResult ActivateHud(string setupCode, string? hudDeviceId, string? avatarIdHash, string? hudVersion)
    {
        if (string.IsNullOrWhiteSpace(setupCode))
        {
            return FailedActivation(LicenseStatus.Pending, "Setup code is required.");
        }

        var requestedDeviceId = string.IsNullOrWhiteSpace(hudDeviceId) ? null : hudDeviceId.Trim();
        if (requestedDeviceId?.Length > 128)
        {
            return FailedActivation(LicenseStatus.Pending, "HUD device ID must contain 1 to 128 characters.");
        }

        var normalizedSetupCode = setupCode.Trim();
        var licenseId = List()
            .FirstOrDefault(candidate => string.Equals(candidate.SetupCode, normalizedSetupCode, StringComparison.Ordinal))
            ?.LicenseId;
        if (licenseId is null)
        {
            return FailedActivation(LicenseStatus.Pending, "Setup code was not accepted.");
        }

        var deviceId = requestedDeviceId is null
            ? $"sl-hud-{Convert.ToHexString(RandomNumberGenerator.GetBytes(9)).ToLowerInvariant()}"
            : requestedDeviceId;
        var lastStatus = LicenseStatus.Pending;

        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var stored = GetVersionedById(licenseId);
            if (stored is null ||
                !string.Equals(stored.License.SetupCode, normalizedSetupCode, StringComparison.Ordinal))
            {
                return FailedActivation(LicenseStatus.Pending, "Setup code was not accepted.");
            }

            var license = stored.License;
            lastStatus = license.Status;
            if (license.Status is LicenseStatus.Revoked or LicenseStatus.Suspended or LicenseStatus.Expired)
            {
                return FailedActivation(license.Status, "This setup code is not active.");
            }
            if (license.SetupCodeConsumedAtUtc is not null)
            {
                return FailedActivation(license.Status, "Setup code was not accepted.");
            }

            var now = clock.GetUtcNow();
            if (license.SetupCodeExpiresAtUtc is { } expiresAtUtc && expiresAtUtc <= now)
            {
                var expired = license with
                {
                    Status = LicenseStatus.Expired,
                    LastSeenAtUtc = now
                };
                if (TryReplace(stored, expired, out _))
                {
                    return FailedActivation(LicenseStatus.Expired, "This setup code has expired.");
                }
                continue;
            }

            if (List().Any(candidate =>
                    !string.Equals(candidate.LicenseId, license.LicenseId, StringComparison.OrdinalIgnoreCase) &&
                    candidate.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase)))
            {
                return FailedActivation(license.Status, "This HUD device is already linked to another license.");
            }

            var deviceIds = license.DeviceIds.ToList();
            if (!deviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))
            {
                if (deviceIds.Count >= license.AllowedDeviceCount)
                {
                    return FailedActivation(license.Status, "This setup code has reached its device limit.");
                }

                deviceIds.Add(deviceId);
            }

            var updated = license with
            {
                Status = LicenseStatus.Active,
                DeviceIds = deviceIds,
                AvatarIdHash = string.IsNullOrWhiteSpace(avatarIdHash) ? license.AvatarIdHash : avatarIdHash.Trim(),
                ActivatedAtUtc = license.ActivatedAtUtc ?? now,
                LastSeenAtUtc = now,
                HudVersion = string.IsNullOrWhiteSpace(hudVersion) ? license.HudVersion : hudVersion.Trim(),
                SetupCodeConsumedAtUtc = deviceIds.Count >= license.AllowedDeviceCount ? now : null
            };

            if (TryReplace(stored, updated, out var persisted))
            {
                return new LicenseActivationResult(
                    true,
                    persisted.LicenseId,
                    persisted.Status,
                    deviceId,
                    "HIP SL HUD activated.",
                    persisted.Settings,
                    persisted.ActivatedAtUtc);
            }
        }

        return FailedActivation(lastStatus, "Setup code activation could not be completed safely. Try again.");
    }

    /// <inheritdoc />
    public LicenseSummary? ResetActivation(string licenseId)
    {
        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var stored = GetVersionedById(licenseId);
            if (stored is null)
            {
                return null;
            }

            var license = stored.License;
            if (license.Status is LicenseStatus.Revoked or LicenseStatus.Suspended or LicenseStatus.Expired)
            {
                return ToSummary(license);
            }

            var updated = license with
            {
                Status = LicenseStatus.Pending,
                DeviceIds = [],
                AvatarIdHash = null,
                ActivatedAtUtc = null,
                LastSeenAtUtc = null,
                HudVersion = null,
                SetupCodeExpiresAtUtc = clock.GetUtcNow().AddHours(24),
                SetupCodeConsumedAtUtc = null
            };
            if (TryReplace(stored, updated, out var persisted))
            {
                return ToSummary(persisted);
            }
        }

        throw ConcurrencyFailure();
    }

    /// <inheritdoc />
    public LicenseSummary? SetStatus(string licenseId, LicenseStatus status)
    {
        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var stored = GetVersionedById(licenseId);
            if (stored is null)
            {
                return null;
            }

            var updated = stored.License with
            {
                Status = status,
                LastSeenAtUtc = DateTimeOffset.UtcNow
            };
            if (TryReplace(stored, updated, out var persisted))
            {
                return ToSummary(persisted);
            }
        }

        throw ConcurrencyFailure();
    }

    /// <inheritdoc />
    public async Task<bool> IsActiveDeviceAsync(
        string licenseId,
        string deviceId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(licenseId) || string.IsNullOrWhiteSpace(deviceId))
        {
            return false;
        }

        var stored = await GetVersionedByIdAsync(licenseId, cancellationToken).ConfigureAwait(false);
        return stored?.License.Status == LicenseStatus.Active &&
               stored.License.DeviceIds.Contains(deviceId.Trim(), StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public LicenseHudSettings GetSettingsForDevice(string licenseId, string deviceId)
    {
        var stored = GetVersionedById(licenseId);
        return stored?.License.Status == LicenseStatus.Active &&
               stored.License.DeviceIds.Contains(deviceId.Trim(), StringComparer.OrdinalIgnoreCase)
            ? stored.License.Settings
            : DefaultSettings;
    }

    /// <inheritdoc />
    public (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(
        string licenseId,
        string deviceId,
        LicenseHudSettings settings)
    {
        if (!IsValidMode(settings.ScanMode))
        {
            return (false, "Invalid HUD mode.", GetSettingsForDevice(licenseId, deviceId));
        }

        var normalizedDeviceId = deviceId.Trim();
        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var stored = GetVersionedById(licenseId);
            if (stored is null ||
                stored.License.Status != LicenseStatus.Active ||
                !stored.License.DeviceIds.Contains(normalizedDeviceId, StringComparer.OrdinalIgnoreCase))
            {
                return (false, "The HUD license/device binding is not active.", DefaultSettings);
            }

            var updated = stored.License with
            {
                Settings = settings,
                LastSeenAtUtc = DateTimeOffset.UtcNow
            };
            if (TryReplace(stored, updated, out _))
            {
                return (true, "HUD settings saved.", settings);
            }
        }

        return (false, "HUD settings could not be saved safely. Try again.", DefaultSettings);
    }

    /// <inheritdoc />
    public LicenseHudSettings GetSettingsForDevice(string deviceId) =>
        List().FirstOrDefault(license =>
            license.Status == LicenseStatus.Active &&
            license.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))?.Settings
            ?? DefaultSettings;

    /// <inheritdoc />
    public (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(string deviceId, LicenseHudSettings settings)
    {
        if (!IsValidMode(settings.ScanMode))
        {
            return (false, "Invalid HUD mode.", GetSettingsForDevice(deviceId));
        }

        var licenseId = List()
            .FirstOrDefault(candidate => candidate.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))
            ?.LicenseId;
        if (licenseId is null)
        {
            return (true, "HUD settings accepted for an unlinked development device. Activate the HUD to persist device-specific settings.", settings);
        }

        for (var attempt = 0; attempt < MaxWriteAttempts; attempt++)
        {
            var stored = GetVersionedById(licenseId);
            if (stored is null ||
                stored.License.Status != LicenseStatus.Active ||
                !stored.License.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))
            {
                return (false, "The HUD license/device binding is not active.", DefaultSettings);
            }

            var updated = stored.License with
            {
                Settings = settings,
                LastSeenAtUtc = DateTimeOffset.UtcNow
            };
            if (TryReplace(stored, updated, out _))
            {
                return (true, "HUD settings saved.", settings);
            }
        }

        return (false, "HUD settings could not be saved safely. Try again.", DefaultSettings);
    }

    /// <summary>
    /// Loads all setup-code licenses from encrypted storage.
    /// </summary>
    /// <returns>All known licenses.</returns>
    private IReadOnlyCollection<SetupCodeLicense> List() =>
        Run(() => store.ListAsync<SetupCodeLicense>(Partition, CancellationToken.None));

    /// <summary>
    /// Loads one authenticated encrypted license together with its database compare-and-swap version.
    /// </summary>
    private VersionedLicense? GetVersionedById(string licenseId) =>
        Run(() => GetVersionedByIdAsync(licenseId, CancellationToken.None));

    /// <summary>
    /// Loads one authenticated encrypted license together with its database compare-and-swap version.
    /// </summary>
    private async Task<VersionedLicense?> GetVersionedByIdAsync(
        string licenseId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(licenseId))
        {
            return null;
        }

        var rowId = licenseId.Trim();
        var stored = await store.GetEncryptedVersionedAsync<SetupCodeLicense>(Partition, rowId, cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        ValidateStoredLicense(rowId, stored.Value.Record, stored.Value.AggregateVersion);
        return new VersionedLicense(stored.Value.Record, stored.Value.AggregateVersion);
    }

    /// <summary>
    /// Replaces an encrypted license only while its database version still matches the authenticated snapshot.
    /// </summary>
    private bool TryReplace(
        VersionedLicense stored,
        SetupCodeLicense updated,
        out SetupCodeLicense persisted)
    {
        if (!string.Equals(stored.License.LicenseId, updated.LicenseId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("A setup-code license update cannot change its stored identity.");
        }

        var newVersion = checked(stored.AggregateVersion + 1);
        var versionedUpdate = updated with { Version = newVersion };
        persisted = versionedUpdate;
        return Run(() => store.TryUpdateVersionedAsync(
            Partition,
            versionedUpdate.LicenseId,
            versionedUpdate,
            stored.AggregateVersion,
            newVersion,
            CancellationToken.None));
    }

    /// <summary>
    /// Rejects swapped, stale, or otherwise unbound encrypted license payloads.
    /// </summary>
    private static void ValidateStoredLicense(string rowId, SetupCodeLicense license, long aggregateVersion)
    {
        if (!string.Equals(rowId, license.LicenseId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Stored setup-code license identity does not match its database row.");
        }

        if (license.Version != aggregateVersion)
        {
            throw new InvalidOperationException("Stored setup-code license version does not match its database row.");
        }
    }

    /// <summary>
    /// Runs an async persistence operation from the current synchronous license interface.
    /// </summary>
    /// <typeparam name="T">Operation result type.</typeparam>
    /// <param name="operation">Persistence operation to execute.</param>
    /// <returns>Operation result.</returns>
    private static T Run<T>(Func<Task<T>> operation) => operation().GetAwaiter().GetResult();

    /// <summary>
    /// Runs an async persistence operation from the current synchronous license interface.
    /// </summary>
    /// <param name="operation">Persistence operation to execute.</param>
    private static void Run(Func<Task> operation) => operation().GetAwaiter().GetResult();

    /// <summary>
    /// Generates one uppercase random setup-code segment.
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
    /// Converts a license to a safe summary that masks the raw setup code.
    /// </summary>
    /// <param name="license">Internal license record.</param>
    /// <returns>Safe summary.</returns>
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
            license.Settings,
            license.CreatedBy,
            license.SetupCodeExpiresAtUtc,
            license.SetupCodeConsumedAtUtc);

    /// <summary>
    /// Masks setup codes for list/detail screens.
    /// </summary>
    /// <param name="setupCode">Raw setup code.</param>
    /// <returns>Masked setup code.</returns>
    private static string MaskSetupCode(string setupCode) =>
        setupCode.Length <= 8 ? "****" : $"{setupCode[..4]}******{setupCode[^4..]}";

    /// <summary>
    /// Creates a failed activation result with safe defaults.
    /// </summary>
    /// <param name="status">License status.</param>
    /// <param name="message">Plain-English message.</param>
    /// <returns>Failed activation result.</returns>
    private static LicenseActivationResult FailedActivation(LicenseStatus status, string message) =>
        new(false, null, status, null, message, DefaultSettings, null);

    /// <summary>
    /// Creates a privacy-safe failure for privileged mutations that repeatedly lose compare-and-swap races.
    /// </summary>
    private static InvalidOperationException ConcurrencyFailure() =>
        new("The setup-code license changed repeatedly and the requested update was not applied.");

    /// <summary>
    /// Validates a user-controllable HUD scan mode.
    /// </summary>
    /// <param name="mode">Mode to validate.</param>
    /// <returns>True when supported.</returns>
    private static bool IsValidMode(string? mode) =>
        !string.IsNullOrWhiteSpace(mode) && ValidModes.Contains(mode);

    /// <summary>
    /// Authenticated license snapshot paired with the unencrypted database CAS token it was read under.
    /// </summary>
    private sealed record VersionedLicense(SetupCodeLicense License, long AggregateVersion);
}

/// <summary>
/// Stores external provider settings in PostgreSQL-backed HIP records by browser or user scope.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfExternalSiteEvidenceSettingsStore(HipRecordStore store) : IExternalSiteEvidenceSettingsStore
{
    private const string Partition = "external-provider-settings";

    /// <inheritdoc />
    public Task<ExternalSiteEvidenceOptions?> GetAsync(string scopeKey, CancellationToken cancellationToken) =>
        store.GetAsync<ExternalSiteEvidenceOptions>(Partition, NormalizeScope(scopeKey), cancellationToken);

    /// <inheritdoc />
    public async Task<ExternalSiteEvidenceOptions> SaveAsync(string scopeKey, ExternalSiteEvidenceOptions options, CancellationToken cancellationToken)
    {
        var detached = options.Clone();
        await store.SaveAsync(Partition, NormalizeScope(scopeKey), detached, cancellationToken);
        return detached.Clone();
    }

    /// <summary>
    /// Normalizes a settings scope without logging or exposing any browser-instance identifier.
    /// </summary>
    /// <param name="scopeKey">Requested settings scope.</param>
    /// <returns>Stable settings key.</returns>
    private static string NormalizeScope(string scopeKey) =>
        string.IsNullOrWhiteSpace(scopeKey) ? "default" : scopeKey.Trim().ToLowerInvariant();
}

/// <summary>
/// Stores external provider evidence cache entries in PostgreSQL-backed HIP records with provider-defined expiry.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfExternalSiteEvidenceCache(HipRecordStore store) : IExternalSiteEvidenceCache
{
    private const string Partition = "external-provider-evidence-cache";

    /// <inheritdoc />
    public SiteSafetyEvidence? GetFresh(string providerName, string domain, string? urlHash)
    {
        var evidence = Run(() => store.GetAsync<SiteSafetyEvidence>(Partition, CacheKey(providerName, domain, urlHash), CancellationToken.None));
        return evidence is not null && evidence.ExpiresAtUtc > DateTimeOffset.UtcNow ? evidence : null;
    }

    /// <inheritdoc />
    public void Store(SiteSafetyEvidence evidence) =>
        Run(() => store.SaveAsync(Partition, CacheKey(evidence.ProviderName, evidence.Domain, evidence.UrlHash), evidence, CancellationToken.None));

    /// <summary>
    /// Builds a stable cache key that never includes a full URL.
    /// </summary>
    /// <param name="providerName">Provider name.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="urlHash">Optional URL hash.</param>
    /// <returns>Cache key.</returns>
    private static string CacheKey(string providerName, string domain, string? urlHash) =>
        $"{providerName.Trim().ToLowerInvariant()}|{domain.Trim().ToLowerInvariant()}|{urlHash ?? "domain"}";

    /// <summary>
    /// Runs an async persistence operation from the current synchronous cache interface.
    /// </summary>
    /// <typeparam name="T">Operation result type.</typeparam>
    /// <param name="operation">Persistence operation to execute.</param>
    /// <returns>Operation result.</returns>
    private static T Run<T>(Func<Task<T>> operation) => operation().GetAwaiter().GetResult();

    /// <summary>
    /// Runs an async persistence operation from the current synchronous cache interface.
    /// </summary>
    /// <param name="operation">Persistence operation to execute.</param>
    private static void Run(Func<Task> operation) => operation().GetAwaiter().GetResult();
}

/// <summary>
/// Persists external provider circuit state in PostgreSQL while using per-process semaphores only for immediate bulkhead coordination.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfExternalProviderResiliencePolicy(HipRecordStore store) : IExternalProviderResiliencePolicy
{
    private const string Partition = "external-provider-circuit-state";
    private const int FailureThreshold = 3;
    private static readonly TimeSpan BreakDuration = TimeSpan.FromMinutes(1);
    private static readonly Dictionary<string, SemaphoreSlim> Bulkheads = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object BulkheadGate = new();

    /// <inheritdoc />
    public async Task<T> ExecuteAsync<T>(string providerName, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        var normalizedProvider = NormalizeProvider(providerName);
        var state = await LoadStateAsync(normalizedProvider, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (state.CircuitOpenUntilUtc is not null && state.CircuitOpenUntilUtc > now)
        {
            throw new ExternalProviderCircuitOpenException(providerName);
        }

        var bulkhead = GetBulkhead(normalizedProvider);
        await bulkhead.WaitAsync(cancellationToken);
        try
        {
            var result = await operation(cancellationToken);
            await SaveStateAsync(normalizedProvider, new ProviderCircuitRecord(0, null), cancellationToken);
            return result;
        }
        catch
        {
            var failureCount = state.CircuitOpenUntilUtc <= now ? 1 : state.FailureCount + 1;
            DateTimeOffset? openUntil = failureCount >= FailureThreshold ? now.Add(BreakDuration) : null;
            await SaveStateAsync(normalizedProvider, new ProviderCircuitRecord(failureCount, openUntil), cancellationToken);
            throw;
        }
        finally
        {
            bulkhead.Release();
        }
    }

    /// <summary>
    /// Loads persisted provider circuit state.
    /// </summary>
    /// <param name="providerName">Normalized provider name.</param>
    /// <param name="cancellationToken">Token used to cancel the read.</param>
    /// <returns>Persisted state or a closed circuit.</returns>
    private async Task<ProviderCircuitRecord> LoadStateAsync(string providerName, CancellationToken cancellationToken) =>
        await store.GetAsync<ProviderCircuitRecord>(Partition, providerName, cancellationToken) ?? new ProviderCircuitRecord(0, null);

    /// <summary>
    /// Saves provider circuit state without storing request URLs, API keys, or response bodies.
    /// </summary>
    /// <param name="providerName">Normalized provider name.</param>
    /// <param name="state">Circuit state to persist.</param>
    /// <param name="cancellationToken">Token used to cancel the write.</param>
    private Task SaveStateAsync(string providerName, ProviderCircuitRecord state, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, providerName, state, cancellationToken);

    /// <summary>
    /// Gets the local semaphore used to prevent one provider from consuming all request workers.
    /// </summary>
    /// <param name="providerName">Normalized provider name.</param>
    /// <returns>Provider-specific semaphore.</returns>
    private static SemaphoreSlim GetBulkhead(string providerName)
    {
        lock (BulkheadGate)
        {
            if (!Bulkheads.TryGetValue(providerName, out var semaphore))
            {
                semaphore = new SemaphoreSlim(4, 4);
                Bulkheads[providerName] = semaphore;
            }

            return semaphore;
        }
    }

    /// <summary>
    /// Normalizes provider names for persistence keys.
    /// </summary>
    /// <param name="providerName">Provider name.</param>
    /// <returns>Safe persistence key.</returns>
    private static string NormalizeProvider(string providerName) =>
        string.IsNullOrWhiteSpace(providerName) ? "unknown-provider" : providerName.Trim().ToLowerInvariant();

    /// <summary>
    /// Durable circuit breaker state for one provider.
    /// </summary>
    /// <param name="FailureCount">Consecutive failure count.</param>
    /// <param name="CircuitOpenUntilUtc">UTC time until calls are rejected.</param>
    private sealed record ProviderCircuitRecord(int FailureCount, DateTimeOffset? CircuitOpenUntilUtc);
}
