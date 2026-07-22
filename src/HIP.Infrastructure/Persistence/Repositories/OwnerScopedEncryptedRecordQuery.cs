using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists an encrypted global record plus a queryable privacy-hash partition and reads only
/// bounded owner partitions. The partition key contains a keyed hash, never the raw owner ID.
/// </summary>
internal sealed class OwnerScopedEncryptedRecordQuery(
    HipDbContext dbContext,
    IHipRecordEncryptor recordEncryptor)
{
    private const string PrivacyHashPrefix = "sha256:";
    private const int PrivacyHashLength = 71;
    private const int MaximumOwnerHashCandidates = 9;
    private const int MaximumResults = 100;

    public async Task SaveAsync<T>(
        string globalPartition,
        string ownerPartitionPrefix,
        string id,
        string? ownerHash,
        DateTimeOffset ownerOrderingTimestamp,
        T value,
        Func<T, string> idSelector,
        Func<T, string?> ownerHashSelector,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(globalPartition);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerPartitionPrefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(idSelector);
        ArgumentNullException.ThrowIfNull(ownerHashSelector);

        await using var transaction = await ConsumerHistoryOwnerIndexMaintenanceLock
            .BeginSharedWriteAsync(dbContext, cancellationToken)
            .ConfigureAwait(false);

        var safeOwnerHash = IsPrivacyHash(ownerHash) ? ownerHash : null;
        var ownerPartition = safeOwnerHash is null
            ? null
            : OwnerPartition(ownerPartitionPrefix, safeOwnerHash);
        var rows = await dbContext.Records
            .Where(record =>
                record.Id == id &&
                (record.Partition == globalPartition ||
                 (ownerPartition != null && record.Partition == ownerPartition)))
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (var row in rows)
        {
            var stored = HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(row.Json));
            if (!string.Equals(idSelector(stored), id, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("An owner-scoped encrypted record has an inconsistent identifier.");
            }

            var storedOwnerHash = ownerHashSelector(stored);
            if (IsPrivacyHash(storedOwnerHash) &&
                !string.Equals(storedOwnerHash, safeOwnerHash, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("An owner-scoped encrypted record cannot be reassigned to another owner.");
            }
        }

        var now = DateTimeOffset.UtcNow;
        var serialized = HipJsonSerializer.Serialize(value);
        Upsert(rows, globalPartition, id, recordEncryptor.Protect(serialized), now, now);
        if (ownerPartition is not null)
        {
            Upsert(
                rows,
                ownerPartition,
                id,
                recordEncryptor.Protect(serialized),
                now,
                ownerOrderingTimestamp);
        }

        await dbContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (transaction is not null)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyCollection<T>> ListAsync<T>(
        string ownerPartitionPrefix,
        IReadOnlyCollection<string> ownerHashCandidates,
        int maximumResults,
        Func<T, string> idSelector,
        Func<T, string?> ownerHashSelector,
        Func<T, DateTimeOffset> orderSelector,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerPartitionPrefix);
        ArgumentNullException.ThrowIfNull(ownerHashCandidates);
        ArgumentNullException.ThrowIfNull(idSelector);
        ArgumentNullException.ThrowIfNull(ownerHashSelector);
        ArgumentNullException.ThrowIfNull(orderSelector);
        if (ownerHashCandidates.Count is < 1 or > MaximumOwnerHashCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(ownerHashCandidates));
        }
        if (maximumResults is < 1 or > MaximumResults)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResults));
        }

        var hashes = ownerHashCandidates
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (hashes.Length < 1 || hashes.Any(hash => !IsPrivacyHash(hash)))
        {
            throw new ArgumentException("Owner history queries require bounded privacy hashes.", nameof(ownerHashCandidates));
        }

        var ownersByPartition = hashes.ToDictionary(
            hash => OwnerPartition(ownerPartitionPrefix, hash),
            hash => hash,
            StringComparer.Ordinal);
        var partitions = ownersByPartition.Keys.ToArray();
        var candidateRows = dbContext.Records.AsNoTracking()
            .Where(record => partitions.Contains(record.Partition));

        var hasDuplicateId = await candidateRows
            .GroupBy(record => record.Id)
            .AnyAsync(group => group.Count() > 1, cancellationToken)
            .ConfigureAwait(false);
        if (hasDuplicateId)
        {
            throw new InvalidOperationException("Ambiguous owner-scoped encrypted history was rejected.");
        }

        IOrderedQueryable<HipDbRecord> orderedRows;
        if (string.Equals(
                dbContext.Database.ProviderName,
                "Npgsql.EntityFrameworkCore.PostgreSQL",
                StringComparison.Ordinal))
        {
            orderedRows = candidateRows
                .OrderByDescending(record => record.UpdatedAtUtc)
                .ThenBy(record => EF.Functions.Collate(record.Partition, "C"))
                .ThenBy(record => EF.Functions.Collate(record.Id, "C"));
        }
        else
        {
            orderedRows = candidateRows
                .OrderByDescending(record => record.UpdatedAtUtc)
                .ThenBy(record => record.Partition)
                .ThenBy(record => record.Id);
        }

        var rows = await orderedRows
            .Take(maximumResults)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);
        var values = new T[rows.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var row = rows[index];
            if (!recordEncryptor.IsProtectedPayload(row.Json))
            {
                throw new InvalidOperationException("Owner-scoped history requires authenticated encrypted records.");
            }

            var value = HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(row.Json));
            if (!ownersByPartition.TryGetValue(row.Partition, out var expectedOwnerHash) ||
                !string.Equals(idSelector(value), row.Id, StringComparison.Ordinal) ||
                !string.Equals(ownerHashSelector(value), expectedOwnerHash, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Corrupt owner-scoped encrypted history was rejected.");
            }

            values[index] = value;
        }

        return values
            .OrderByDescending(orderSelector)
            .ThenBy(idSelector, StringComparer.Ordinal)
            .ToArray();
    }

    private void Upsert(
        IReadOnlyCollection<HipDbRecord> existingRows,
        string partition,
        string id,
        string protectedPayload,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        var record = existingRows.SingleOrDefault(row =>
            string.Equals(row.Partition, partition, StringComparison.Ordinal) &&
            string.Equals(row.Id, id, StringComparison.Ordinal));
        if (record is null)
        {
            dbContext.Records.Add(new HipDbRecord
            {
                Partition = partition,
                Id = id,
                Json = protectedPayload,
                CreatedAtUtc = createdAtUtc,
                UpdatedAtUtc = updatedAtUtc
            });
            return;
        }

        record.Json = protectedPayload;
        record.UpdatedAtUtc = updatedAtUtc;
    }

    internal static string OwnerPartition(string prefix, string ownerHash) => prefix + ownerHash;

    internal static bool IsPrivacyHash(string? value)
    {
        if (value is not { Length: PrivacyHashLength } ||
            !value.StartsWith(PrivacyHashPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var character in value.AsSpan(PrivacyHashPrefix.Length))
        {
            var isDecimal = character is >= '0' and <= '9';
            var isLowerHex = character is >= 'a' and <= 'f';
            if (!isDecimal && !isLowerHex)
            {
                return false;
            }
        }

        return true;
    }
}
