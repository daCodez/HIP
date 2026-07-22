using System.Data;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Privacy-safe totals from an idempotent consumer-history owner-index backfill.
/// No record identifiers, owner hashes, or decrypted payloads are exposed.
/// </summary>
public sealed record ConsumerHistoryOwnerIndexBackfillSummary(
    int ProcessedGlobalRecords,
    int CreatedOwnerRecords,
    int AlreadyIndexedRecords,
    int SkippedWithoutOwner,
    int Batches);

/// <summary>
/// Creates the owner-scoped encrypted copies required by bounded consumer history queries.
/// The operation reads authenticated global records in bounded pages and never runs on a request path.
/// </summary>
public sealed class ConsumerHistoryOwnerIndexBackfillService(
    HipRecordStore store,
    HipDbContext dbContext,
    IHipRecordEncryptor recordEncryptor)
{
    private const int MaximumBatchSize = 100;

    /// <summary>
    /// Backfills all legacy risk-finding and appeal rows. Re-running the operation is safe and creates no duplicates.
    /// </summary>
    public async Task<ConsumerHistoryOwnerIndexBackfillSummary> BackfillAllAsync(
        int batchSize,
        CancellationToken cancellationToken)
    {
        if (batchSize is < 1 or > MaximumBatchSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(batchSize),
                $"Consumer-history owner-index batch size must be between 1 and {MaximumBatchSize}.");
        }

        var riskFindings = await BackfillPartitionAsync<RiskFindingReport>(
            EfRiskFindingReportRepository.Partition,
            EfRiskFindingReportRepository.OwnerPartitionPrefix,
            batchSize,
            report => report.ReportId,
            report => report.ConsumerScopeHash,
            report => report.DetectedAtUtc,
            cancellationToken);
        var appeals = await BackfillPartitionAsync<AppealRequest>(
            EfAppealRepository.Partition,
            EfAppealRepository.OwnerPartitionPrefix,
            batchSize,
            appeal => appeal.AppealId,
            appeal => appeal.SubmittedByHash,
            appeal => appeal.UpdatedAtUtc,
            cancellationToken);

        return new ConsumerHistoryOwnerIndexBackfillSummary(
            riskFindings.ProcessedGlobalRecords + appeals.ProcessedGlobalRecords,
            riskFindings.CreatedOwnerRecords + appeals.CreatedOwnerRecords,
            riskFindings.AlreadyIndexedRecords + appeals.AlreadyIndexedRecords,
            riskFindings.SkippedWithoutOwner + appeals.SkippedWithoutOwner,
            riskFindings.Batches + appeals.Batches);
    }

    private async Task<ConsumerHistoryOwnerIndexBackfillSummary> BackfillPartitionAsync<T>(
        string globalPartition,
        string ownerPartitionPrefix,
        int batchSize,
        Func<T, string> idSelector,
        Func<T, string?> ownerHashSelector,
        Func<T, DateTimeOffset> orderSelector,
        CancellationToken cancellationToken)
    {
        string? cursor = null;
        var processed = 0;
        var created = 0;
        var alreadyIndexed = 0;
        var skippedWithoutOwner = 0;
        var batches = 0;

        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var transaction = await ConsumerHistoryOwnerIndexMaintenanceLock
                .BeginExclusiveBatchAsync(dbContext, cancellationToken)
                .ConfigureAwait(false);
            var page = await store.ListEncryptedPageAsync<T>(
                globalPartition,
                cursor,
                batchSize,
                cancellationToken).ConfigureAwait(false);
            if (page.Items.Count == 0)
            {
                if (transaction is not null)
                {
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                }

                break;
            }

            batches++;
            var ids = page.Items.Select(item => item.Id).ToArray();
            var globalRows = await dbContext.Records
                .Where(row => row.Partition == globalPartition && ids.Contains(row.Id))
                .ToDictionaryAsync(row => row.Id, StringComparer.Ordinal, cancellationToken)
                .ConfigureAwait(false);
            var ownerRows = await dbContext.Records
                .Where(row => ids.Contains(row.Id) && row.Partition.StartsWith(ownerPartitionPrefix))
                .ToArrayAsync(cancellationToken)
                .ConfigureAwait(false);

            foreach (var item in page.Items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                processed++;
                if (!string.Equals(idSelector(item.Record), item.Id, StringComparison.Ordinal) ||
                    !globalRows.TryGetValue(item.Id, out var globalRow) ||
                    !recordEncryptor.IsProtectedPayload(globalRow.Json))
                {
                    throw new InvalidOperationException(
                        "Consumer-history owner-index backfill rejected an inconsistent global record.");
                }

                var serializedGlobalValue = HipJsonSerializer.Serialize(item.Record);
                var currentGlobalValue = recordEncryptor.Unprotect(globalRow.Json);
                if (!string.Equals(currentGlobalValue, serializedGlobalValue, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Consumer-history owner-index backfill detected a concurrently changed global record.");
                }

                var ownerHash = ownerHashSelector(item.Record);
                if (string.IsNullOrWhiteSpace(ownerHash))
                {
                    skippedWithoutOwner++;
                    continue;
                }

                if (!OwnerScopedEncryptedRecordQuery.IsPrivacyHash(ownerHash))
                {
                    throw new InvalidOperationException(
                        "Consumer-history owner-index backfill rejected an invalid privacy hash.");
                }

                var expectedPartition = OwnerScopedEncryptedRecordQuery.OwnerPartition(
                    ownerPartitionPrefix,
                    ownerHash);
                var existingForId = ownerRows
                    .Where(row => string.Equals(row.Id, item.Id, StringComparison.Ordinal))
                    .ToArray();
                if (existingForId.Any(row =>
                        !string.Equals(row.Partition, expectedPartition, StringComparison.Ordinal)))
                {
                    throw new InvalidOperationException(
                        "Consumer-history owner-index backfill rejected an ambiguous owner binding.");
                }

                var existing = existingForId.SingleOrDefault();
                if (existing is not null)
                {
                    ValidateExistingOwnerRecord(
                        existing,
                        item.Id,
                        ownerHash,
                        idSelector,
                        ownerHashSelector,
                        serializedGlobalValue);
                    alreadyIndexed++;
                    continue;
                }

                dbContext.Records.Add(new HipDbRecord
                {
                    Partition = expectedPartition,
                    Id = item.Id,
                    Json = globalRow.Json,
                    AggregateVersion = globalRow.AggregateVersion,
                    CreatedAtUtc = globalRow.CreatedAtUtc,
                    UpdatedAtUtc = orderSelector(item.Record)
                });
                created++;
            }

            await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            if (transaction is not null)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            cursor = page.NextCursor;
            dbContext.ChangeTracker.Clear();
        }
        while (cursor is not null);

        return new ConsumerHistoryOwnerIndexBackfillSummary(
            processed,
            created,
            alreadyIndexed,
            skippedWithoutOwner,
            batches);
    }

    private void ValidateExistingOwnerRecord<T>(
        HipDbRecord existing,
        string expectedId,
        string expectedOwnerHash,
        Func<T, string> idSelector,
        Func<T, string?> ownerHashSelector,
        string serializedGlobalValue)
    {
        if (!recordEncryptor.IsProtectedPayload(existing.Json))
        {
            throw new InvalidOperationException(
                "Consumer-history owner-index backfill requires authenticated owner records.");
        }

        var existingValue = HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(existing.Json));
        if (!string.Equals(idSelector(existingValue), expectedId, StringComparison.Ordinal) ||
            !string.Equals(ownerHashSelector(existingValue), expectedOwnerHash, StringComparison.Ordinal) ||
            !string.Equals(
                HipJsonSerializer.Serialize(existingValue),
                serializedGlobalValue,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Consumer-history owner-index backfill rejected an owner copy that differs from the global record.");
        }
    }
}

/// <summary>
/// Coordinates normal dual writes with bounded owner-index maintenance on PostgreSQL. Shared writer locks
/// can run concurrently; a maintenance batch takes the exclusive counterpart before copying global rows.
/// </summary>
internal static class ConsumerHistoryOwnerIndexMaintenanceLock
{
    private const long AdvisoryLockId = 0x4849504F574E4552;

    internal static async Task<IDbContextTransaction?> BeginSharedWriteAsync(
        HipDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!UsesPostgreSql(dbContext))
        {
            return null;
        }

        var transaction = dbContext.Database.CurrentTransaction is null
            ? await dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
                .ConfigureAwait(false)
            : null;
        await dbContext.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock_shared({AdvisoryLockId})",
            cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    internal static async Task<IDbContextTransaction?> BeginExclusiveBatchAsync(
        HipDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!UsesPostgreSql(dbContext))
        {
            return null;
        }

        if (dbContext.Database.CurrentTransaction is not null)
        {
            throw new InvalidOperationException(
                "Consumer-history owner-index maintenance requires its own database transaction.");
        }

        var transaction = await dbContext.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken).ConfigureAwait(false);
        await dbContext.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock({AdvisoryLockId})",
            cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    private static bool UsesPostgreSql(HipDbContext dbContext) =>
        string.Equals(
            dbContext.Database.ProviderName,
            "Npgsql.EntityFrameworkCore.PostgreSQL",
            StringComparison.Ordinal);
}
