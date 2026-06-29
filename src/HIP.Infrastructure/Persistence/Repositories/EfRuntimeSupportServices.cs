using System.Security.Cryptography;
using System.Text;
using HIP.Application.SecondLife;
using HIP.Application.Security;
using HIP.Application.SiteSafety;
using HIP.Infrastructure.Persistence;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Stores duplicate-submission fingerprints in PostgreSQL-backed HIP records so dedupe state survives process restarts.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfDuplicateSubmissionGuard(HipRecordStore store) : IDuplicateSubmissionGuard
{
    private const string Partition = "duplicate-submission-guards";

    /// <inheritdoc />
    public bool TryAccept(string scope, IEnumerable<string?> parts, TimeSpan window)
    {
        var now = DateTimeOffset.UtcNow;
        var id = Fingerprint(scope, parts);
        var existing = Run(() => store.GetAsync<DuplicateSubmissionRecord>(Partition, id, CancellationToken.None));
        if (existing is not null && existing.AcceptedUntilUtc > now)
        {
            return false;
        }

        Run(() => store.SaveAsync(Partition, id, new DuplicateSubmissionRecord(id, now.Add(window)), CancellationToken.None));
        return true;
    }

    /// <summary>
    /// Runs an async persistence operation from the current synchronous interface without hiding exceptions.
    /// </summary>
    /// <typeparam name="T">Operation result type.</typeparam>
    /// <param name="operation">Persistence operation to execute.</param>
    /// <returns>Operation result.</returns>
    private static T Run<T>(Func<Task<T>> operation) => operation().GetAwaiter().GetResult();

    /// <summary>
    /// Runs an async persistence operation from the current synchronous interface without hiding exceptions.
    /// </summary>
    /// <param name="operation">Persistence operation to execute.</param>
    private static void Run(Func<Task> operation) => operation().GetAwaiter().GetResult();

    /// <summary>
    /// Builds a stable duplicate fingerprint without storing raw submitted values.
    /// </summary>
    /// <param name="scope">Submission scope, such as browser-scan or feedback.</param>
    /// <param name="parts">Privacy-safe values used for dedupe.</param>
    /// <returns>Hex SHA-256 fingerprint.</returns>
    private static string Fingerprint(string scope, IEnumerable<string?> parts)
    {
        var joined = string.Join("|", parts.Select(part => (part ?? string.Empty).Trim().ToLowerInvariant()));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{scope}|{joined}"))).ToLowerInvariant();
    }

    /// <summary>
    /// Durable duplicate-submission state.
    /// </summary>
    /// <param name="Fingerprint">Privacy-safe fingerprint.</param>
    /// <param name="AcceptedUntilUtc">UTC time until the same fingerprint should be rejected.</param>
    private sealed record DuplicateSubmissionRecord(string Fingerprint, DateTimeOffset AcceptedUntilUtc);
}

/// <summary>
/// Stores Second Life setup-code licenses in encrypted PostgreSQL-backed HIP records instead of process memory.
/// </summary>
/// <param name="store">Encrypted generic HIP record store.</param>
public sealed class EfSetupCodeLicenseService(HipRecordStore store) : ISetupCodeLicenseService
{
    private const string Partition = "setup-code-licenses";
    private static readonly HashSet<string> ValidModes = new(StringComparer.OrdinalIgnoreCase) { "Quiet", "Normal", "Strict", "Paranoid" };
    private static readonly LicenseHudSettings DefaultSettings = new("Normal", true, true, true);

    /// <inheritdoc />
    public CreateSetupCodeResponse CreateSetupCode(CreateSetupCodeRequest request)
    {
        var allowedDevices = request.AllowedDeviceCount is > 0 and <= 25 ? request.AllowedDeviceCount.Value : 1;
        var mode = IsValidMode(request.InitialScanMode) ? request.InitialScanMode! : DefaultSettings.ScanMode;
        var setupCode = $"HIP-{RandomSegment()}-{RandomSegment()}-{RandomSegment()}";
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
            DefaultSettings with { ScanMode = mode });

        Save(license);
        return new CreateSetupCodeResponse(license.LicenseId, setupCode, MaskSetupCode(setupCode), license.Status, allowedDevices);
    }

    /// <inheritdoc />
    public IReadOnlyCollection<LicenseSummary> ListLicenses() =>
        List().Select(ToSummary).OrderBy(summary => summary.MaskedSetupCode, StringComparer.OrdinalIgnoreCase).ToArray();

    /// <inheritdoc />
    public LicenseSummary? GetLicense(string licenseId) =>
        GetById(licenseId) is { } license ? ToSummary(license) : null;

    /// <inheritdoc />
    public LicenseActivationResult ActivateHud(string setupCode, string? hudDeviceId, string? avatarIdHash, string? hudVersion)
    {
        if (string.IsNullOrWhiteSpace(setupCode))
        {
            return FailedActivation(LicenseStatus.Pending, "Setup code is required.");
        }

        var license = List().FirstOrDefault(candidate => string.Equals(candidate.SetupCode, setupCode.Trim(), StringComparison.Ordinal));
        if (license is null)
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

        Save(updated);
        return new LicenseActivationResult(true, updated.LicenseId, updated.Status, deviceId, "HIP SL HUD activated.", updated.Settings, updated.ActivatedAtUtc);
    }

    /// <inheritdoc />
    public LicenseSummary? ResetActivation(string licenseId)
    {
        var license = GetById(licenseId);
        if (license is null)
        {
            return null;
        }

        var updated = license with
        {
            Status = LicenseStatus.Pending,
            DeviceIds = [],
            AvatarIdHash = null,
            ActivatedAtUtc = null,
            LastSeenAtUtc = null,
            HudVersion = null
        };
        Save(updated);
        return ToSummary(updated);
    }

    /// <inheritdoc />
    public LicenseSummary? SetStatus(string licenseId, LicenseStatus status)
    {
        var license = GetById(licenseId);
        if (license is null)
        {
            return null;
        }

        var updated = license with { Status = status, LastSeenAtUtc = DateTimeOffset.UtcNow };
        Save(updated);
        return ToSummary(updated);
    }

    /// <inheritdoc />
    public LicenseHudSettings GetSettingsForDevice(string deviceId) =>
        List().FirstOrDefault(license => license.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase))?.Settings
            ?? DefaultSettings;

    /// <inheritdoc />
    public (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(string deviceId, LicenseHudSettings settings)
    {
        if (!IsValidMode(settings.ScanMode))
        {
            return (false, "Invalid HUD mode.", GetSettingsForDevice(deviceId));
        }

        var license = List().FirstOrDefault(candidate => candidate.DeviceIds.Contains(deviceId, StringComparer.OrdinalIgnoreCase));
        if (license is null)
        {
            return (true, "HUD settings accepted for an unlinked development device. Activate the HUD to persist device-specific settings.", settings);
        }

        var updated = license with { Settings = settings, LastSeenAtUtc = DateTimeOffset.UtcNow };
        Save(updated);
        return (true, "HUD settings saved.", settings);
    }

    /// <summary>
    /// Loads all setup-code licenses from encrypted storage.
    /// </summary>
    /// <returns>All known licenses.</returns>
    private IReadOnlyCollection<SetupCodeLicense> List() =>
        Run(() => store.ListAsync<SetupCodeLicense>(Partition, CancellationToken.None));

    /// <summary>
    /// Gets a license by its stable identifier.
    /// </summary>
    /// <param name="licenseId">License identifier.</param>
    /// <returns>License or null.</returns>
    private SetupCodeLicense? GetById(string licenseId) =>
        string.IsNullOrWhiteSpace(licenseId)
            ? null
            : Run(() => store.GetAsync<SetupCodeLicense>(Partition, licenseId.Trim(), CancellationToken.None));

    /// <summary>
    /// Saves one encrypted setup-code license.
    /// </summary>
    /// <param name="license">License to save.</param>
    private void Save(SetupCodeLicense license) =>
        Run(() => store.SaveAsync(Partition, license.LicenseId, license, CancellationToken.None));

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
        new(license.LicenseId, MaskSetupCode(license.SetupCode), license.Status, license.DeviceIds.Count, license.AllowedDeviceCount, license.DeviceIds, license.ActivatedAtUtc, license.LastSeenAtUtc, license.HudVersion, license.Settings);

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
    /// Validates a user-controllable HUD scan mode.
    /// </summary>
    /// <param name="mode">Mode to validate.</param>
    /// <returns>True when supported.</returns>
    private static bool IsValidMode(string? mode) =>
        !string.IsNullOrWhiteSpace(mode) && ValidModes.Contains(mode);
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
            var openUntil = failureCount >= FailureThreshold ? now.Add(BreakDuration) : null;
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
