using HIP.Application.Browser;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed browser scan result repository using typed hot-path tables.
/// </summary>
/// <param name="dbContext">HIP EF Core database context.</param>
/// <param name="legacyStore">Generic encrypted record store used only as a migration fallback for older local data.</param>
public sealed class EfBrowserScanResultRepository(HipDbContext dbContext, HipRecordStore legacyStore) : IBrowserScanResultRepository
{
    private const string Partition = "browser-scan-result";

    /// <summary>
    /// Saves the latest privacy-safe scan result for a domain.
    /// </summary>
    /// <param name="result">Privacy-safe browser scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes when the record has been stored.</returns>
    public async Task SaveAsync(BrowserScanResultRecord result, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var entity = await dbContext.BrowserScanResults.FindAsync([result.ScanResultId], cancellationToken);
        if (entity is null)
        {
            dbContext.BrowserScanResults.Add(ToEntity(result, now));
        }
        else
        {
            Apply(entity, result, now);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Retrieves the latest browser plugin scan result for a normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored scan result, or null when none exists.</returns>
    public async Task<BrowserScanResultRecord?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalizedDomain = domain.Trim().ToLowerInvariant();
        var entity = IsSqlite()
            ? (await dbContext.BrowserScanResults.AsNoTracking()
                .Where(result => result.Domain == normalizedDomain)
                .ToArrayAsync(cancellationToken))
                .OrderByDescending(result => result.LastCheckedUtc)
                .FirstOrDefault()
            : await dbContext.BrowserScanResults.AsNoTracking()
                .Where(result => result.Domain == normalizedDomain)
                .OrderByDescending(result => result.LastCheckedUtc)
                .FirstOrDefaultAsync(cancellationToken);

        if (entity is not null)
        {
            return FromEntity(entity);
        }

        return (await ListLegacyAsync(cancellationToken))
            .Where(result => result.Domain.Equals(normalizedDomain, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(result => result.LastCheckedUtc)
            .FirstOrDefault();
    }

    /// <summary>
    /// Lists stored browser plugin scan results for privacy-safe dashboard aggregation.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Stored scan results, newest first.</returns>
    public async Task<IReadOnlyCollection<BrowserScanResultRecord>> ListAsync(CancellationToken cancellationToken)
    {
        var typedResults = IsSqlite()
            ? (await dbContext.BrowserScanResults.AsNoTracking()
                .ToArrayAsync(cancellationToken))
                .OrderByDescending(result => result.LastCheckedUtc)
                .ToArray()
            : await dbContext.BrowserScanResults.AsNoTracking()
                .OrderByDescending(result => result.LastCheckedUtc)
                .ToArrayAsync(cancellationToken);
        if (typedResults.Length > 0)
        {
            return typedResults.Select(FromEntity).ToArray();
        }

        return (await ListLegacyAsync(cancellationToken))
            .OrderByDescending(result => result.LastCheckedUtc)
            .ToArray();
    }

    /// <summary>
    /// Lists recent browser scan results for dashboard read models without requiring dashboard code to process every scan.
    /// </summary>
    /// <param name="maxCount">Maximum number of recent scans to return.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Recent privacy-safe scan results, newest first.</returns>
    public async Task<IReadOnlyCollection<BrowserScanResultRecord>> ListRecentAsync(int maxCount, CancellationToken cancellationToken)
    {
        var boundedMax = Math.Max(0, maxCount);
        if (boundedMax == 0)
        {
            return Array.Empty<BrowserScanResultRecord>();
        }

        var typedResults = IsSqlite()
            ? (await dbContext.BrowserScanResults.AsNoTracking()
                .ToArrayAsync(cancellationToken))
                .OrderByDescending(result => result.LastCheckedUtc)
                .Take(boundedMax)
                .ToArray()
            : await dbContext.BrowserScanResults.AsNoTracking()
                .OrderByDescending(result => result.LastCheckedUtc)
                .Take(boundedMax)
                .ToArrayAsync(cancellationToken);
        if (typedResults.Length > 0)
        {
            return typedResults.Select(FromEntity).ToArray();
        }

        return (await legacyStore.ListRecentAsync<BrowserScanResultRecord>(Partition, boundedMax, cancellationToken))
            .OrderByDescending(result => result.LastCheckedUtc)
            .ToArray();
    }

    /// <summary>
    /// Lists older scan records from the generic encrypted table as a non-hot-path migration fallback.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel fallback reads.</param>
    /// <returns>Legacy scan records.</returns>
    private Task<IReadOnlyCollection<BrowserScanResultRecord>> ListLegacyAsync(CancellationToken cancellationToken) =>
        legacyStore.ListAsync<BrowserScanResultRecord>(Partition, cancellationToken);

    /// <summary>
    /// Creates a typed scan entity from a privacy-safe application record.
    /// </summary>
    /// <param name="result">Application scan result.</param>
    /// <param name="now">Persistence timestamp.</param>
    /// <returns>Typed EF entity.</returns>
    private static HipBrowserScanResultEntity ToEntity(BrowserScanResultRecord result, DateTimeOffset now)
    {
        var entity = new HipBrowserScanResultEntity
        {
            ScanResultId = result.ScanResultId,
            CreatedAtUtc = now
        };

        Apply(entity, result, now);
        return entity;
    }

    /// <summary>
    /// Copies privacy-safe scan fields into an existing typed entity.
    /// </summary>
    /// <param name="entity">Entity being inserted or updated.</param>
    /// <param name="result">Application scan result.</param>
    /// <param name="now">Persistence timestamp.</param>
    private static void Apply(HipBrowserScanResultEntity entity, BrowserScanResultRecord result, DateTimeOffset now)
    {
        entity.Domain = result.Domain.Trim().ToLowerInvariant();
        entity.PageUrlHash = result.PageUrlHash;
        entity.StoredPageUrl = result.StoredPageUrl;
        entity.ScanSource = result.ScanSource;
        entity.Score = result.Score;
        entity.RiskLevel = result.RiskLevel;
        entity.Status = result.Status;
        entity.ReasonsJson = HipJsonSerializer.Serialize(result.Reasons);
        entity.LinksScanned = result.LinksScanned;
        entity.RiskyLinksFound = result.RiskyLinksFound;
        entity.SuspiciousLinksFound = result.SuspiciousLinksFound;
        entity.DangerousLinksFound = result.DangerousLinksFound;
        entity.LastCheckedUtc = result.LastCheckedUtc;
        entity.RecommendedAction = result.RecommendedAction;
        entity.PrivacySafeMetadataJson = HipJsonSerializer.Serialize(result.PrivacySafeMetadata);
        entity.PluginVersion = ResolvePluginVersion(result.PrivacySafeMetadata);
        entity.UpdatedAtUtc = now;
    }

    /// <summary>
    /// Rehydrates a privacy-safe application record from the typed scan table.
    /// </summary>
    /// <param name="entity">Typed EF entity.</param>
    /// <returns>Application scan record.</returns>
    private static BrowserScanResultRecord FromEntity(HipBrowserScanResultEntity entity) =>
        new(
            entity.ScanResultId,
            entity.Domain,
            entity.PageUrlHash,
            entity.StoredPageUrl,
            entity.ScanSource,
            entity.Score,
            entity.RiskLevel,
            entity.Status,
            HipJsonSerializer.Deserialize<IReadOnlyCollection<string>>(entity.ReasonsJson),
            entity.LinksScanned,
            entity.RiskyLinksFound,
            entity.SuspiciousLinksFound,
            entity.DangerousLinksFound,
            entity.LastCheckedUtc,
            entity.RecommendedAction,
            HipJsonSerializer.Deserialize<IReadOnlyDictionary<string, string>>(entity.PrivacySafeMetadataJson));

    /// <summary>
    /// Extracts plugin version from safe metadata so dashboard queries can display it without parsing JSON.
    /// </summary>
    /// <param name="metadata">Privacy-safe metadata submitted with the scan.</param>
    /// <returns>Plugin version or null when the client did not submit one.</returns>
    private static string? ResolvePluginVersion(IReadOnlyDictionary<string, string> metadata) =>
        metadata.TryGetValue("pluginVersion", out var pluginVersion) && !string.IsNullOrWhiteSpace(pluginVersion)
            ? pluginVersion
            : null;

    /// <summary>
    /// Detects SQLite so tests can avoid provider translation gaps for <see cref="DateTimeOffset" /> ordering.
    /// </summary>
    /// <returns>True when the active EF provider is SQLite.</returns>
    private bool IsSqlite() =>
        dbContext.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true;
}
