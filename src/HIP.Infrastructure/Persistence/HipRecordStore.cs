using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Stores typed HIP records in the generic database table using encrypted JSON payloads.
/// </summary>
/// <param name="dbContext">HIP EF Core database context.</param>
/// <param name="encryptor">Record encryptor. Tests may omit it to use the local development encryptor.</param>
public sealed class HipRecordStore(HipDbContext dbContext, IHipRecordEncryptor? encryptor = null)
{
    private readonly IHipRecordEncryptor recordEncryptor = encryptor ?? new DevelopmentHipRecordEncryptor();

    /// <summary>
    /// Saves or updates a typed record after encrypting the serialized JSON payload.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="value">Record value.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    public async Task SaveAsync<T>(string partition, string id, T value, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var protectedPayload = recordEncryptor.Protect(HipJsonSerializer.Serialize(value));
        var record = await dbContext.Records.FindAsync([partition, id], cancellationToken);
        if (record is null)
        {
            dbContext.Records.Add(new HipDbRecord
            {
                Partition = partition,
                Id = id,
                Json = protectedPayload,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });
        }
        else
        {
            record.Json = protectedPayload;
            record.UpdatedAtUtc = now;
        }

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsDuplicateKeyViolation(exception))
        {
            await UpdateAfterDuplicateInsertAsync(partition, id, protectedPayload, now, cancellationToken);
        }
    }

    /// <summary>
    /// Encrypts and saves a versioned aggregate only when the database row still has the expected version.
    /// </summary>
    /// <typeparam name="T">Aggregate snapshot type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Aggregate identifier.</param>
    /// <param name="value">New immutable aggregate snapshot.</param>
    /// <param name="expectedVersion">Version that must currently be stored, or zero for the first insert.</param>
    /// <param name="newVersion">Version stored with the new snapshot; it must be exactly one greater than expected.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>True when the insert or atomic update won; false when the expected version was stale.</returns>
    public Task<bool> TrySaveVersionedAsync<T>(
        string partition,
        string id,
        T value,
        long expectedVersion,
        long newVersion,
        CancellationToken cancellationToken) =>
        TrySaveVersionedWithRelatedRecordsAsync<T, object>(
            partition,
            id,
            value,
            expectedVersion,
            newVersion,
            [],
            cancellationToken);

    /// <summary>
    /// Commits an encrypted aggregate compare-and-swap and its encrypted related records in one database transaction.
    /// </summary>
    /// <typeparam name="TAggregate">Aggregate snapshot type.</typeparam>
    /// <typeparam name="TRelated">Related record payload type.</typeparam>
    /// <param name="partition">Logical aggregate partition.</param>
    /// <param name="id">Aggregate identifier.</param>
    /// <param name="value">New immutable aggregate snapshot.</param>
    /// <param name="expectedVersion">Version that must currently be stored, or zero for the first insert.</param>
    /// <param name="newVersion">Version stored with the new snapshot; it must be exactly one greater than expected.</param>
    /// <param name="relatedRecords">Bounded records that must be persisted only when the aggregate write wins.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>True when the complete transaction committed; false when CAS or an identifier collision rejected it.</returns>
    public async Task<bool> TrySaveVersionedWithRelatedRecordsAsync<TAggregate, TRelated>(
        string partition,
        string id,
        TAggregate value,
        long expectedVersion,
        long newVersion,
        IReadOnlyCollection<HipRelatedRecordWrite<TRelated>> relatedRecords,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(relatedRecords);

        if (expectedVersion < 0 || expectedVersion == long.MaxValue || newVersion != expectedVersion + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(newVersion),
                "A versioned HIP record must advance the expected aggregate version by exactly one.");
        }
        if (relatedRecords.Count > 32)
        {
            throw new ArgumentOutOfRangeException(
                nameof(relatedRecords),
                "An atomic HIP record commit cannot contain more than 32 related records.");
        }

        var now = DateTimeOffset.UtcNow;
        var protectedPayload = recordEncryptor.Protect(HipJsonSerializer.Serialize(value));
        var relatedKeys = new HashSet<(string Partition, string Id)>();
        var encryptedRelatedRecords = relatedRecords.Select(write =>
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(write.Partition);
            ArgumentException.ThrowIfNullOrWhiteSpace(write.Id);
            ArgumentNullException.ThrowIfNull(write.Value);
            if (write.Partition.Length > 160 || write.Id.Length > 220)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(relatedRecords),
                    "Related HIP record identifiers exceed the encrypted record schema limits.");
            }
            if (!relatedKeys.Add((write.Partition, write.Id)) ||
                (write.Partition == partition && write.Id == id))
            {
                throw new InvalidOperationException(
                    "An atomic HIP record commit cannot contain duplicate record identifiers.");
            }

            return new HipDbRecord
            {
                Partition = write.Partition,
                Id = write.Id,
                Json = recordEncryptor.Protect(HipJsonSerializer.Serialize(write.Value)),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
        }).ToArray();

        if (string.Equals(
                dbContext.Database.ProviderName,
                "Microsoft.EntityFrameworkCore.InMemory",
                StringComparison.Ordinal))
        {
            // EF's test provider has no transaction or ExecuteUpdate support. One SaveChanges call keeps
            // the aggregate and audit rows together for API tests; production PostgreSQL uses the CAS transaction below.
            return await TrySaveVersionedInMemoryAsync(
                partition,
                id,
                protectedPayload,
                expectedVersion,
                newVersion,
                encryptedRelatedRecords,
                now,
                cancellationToken);
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            if (expectedVersion == 0)
            {
                dbContext.Records.Add(new HipDbRecord
                {
                    Partition = partition,
                    Id = id,
                    Json = protectedPayload,
                    AggregateVersion = newVersion,
                    CreatedAtUtc = now,
                    UpdatedAtUtc = now
                });
            }
            else
            {
                var affectedRows = await dbContext.Records
                    .Where(record =>
                        record.Partition == partition &&
                        record.Id == id &&
                        record.AggregateVersion == expectedVersion)
                    .ExecuteUpdateAsync(
                        setters => setters
                            .SetProperty(record => record.Json, protectedPayload)
                            .SetProperty(record => record.AggregateVersion, newVersion)
                            .SetProperty(record => record.UpdatedAtUtc, now),
                        cancellationToken);
                if (affectedRows != 1)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return false;
                }
            }

            dbContext.Records.AddRange(encryptedRelatedRecords);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException exception) when (IsDuplicateKeyViolation(exception))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return false;
        }
    }

    private async Task<bool> TrySaveVersionedInMemoryAsync(
        string partition,
        string id,
        string protectedPayload,
        long expectedVersion,
        long newVersion,
        IReadOnlyCollection<HipDbRecord> encryptedRelatedRecords,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        foreach (var relatedRecord in encryptedRelatedRecords)
        {
            if (await dbContext.Records.AnyAsync(
                    record => record.Partition == relatedRecord.Partition && record.Id == relatedRecord.Id,
                    cancellationToken))
            {
                return false;
            }
        }

        if (expectedVersion == 0)
        {
            if (await dbContext.Records.AnyAsync(
                    record => record.Partition == partition && record.Id == id,
                    cancellationToken))
            {
                return false;
            }

            dbContext.Records.Add(new HipDbRecord
            {
                Partition = partition,
                Id = id,
                Json = protectedPayload,
                AggregateVersion = newVersion,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });
        }
        else
        {
            var existing = await dbContext.Records.SingleOrDefaultAsync(
                record => record.Partition == partition && record.Id == id,
                cancellationToken);
            if (existing is null || existing.AggregateVersion != expectedVersion)
            {
                return false;
            }

            existing.Json = protectedPayload;
            existing.AggregateVersion = newVersion;
            existing.UpdatedAtUtc = now;
        }

        dbContext.Records.AddRange(encryptedRelatedRecords);
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException exception) when (IsDuplicateKeyViolation(exception))
        {
            dbContext.ChangeTracker.Clear();
            return false;
        }
    }

    /// <summary>
    /// Reads and decrypts a typed record, while still supporting old plaintext development records.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Deserialized record or null when missing.</returns>
    public async Task<T?> GetAsync<T>(string partition, string id, CancellationToken cancellationToken)
    {
        var record = await dbContext.Records.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Partition == partition && item.Id == id, cancellationToken);

        return record is null ? default : HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json));
    }

    /// <summary>
    /// Reads a security-sensitive record only when it uses HIP's authenticated encryption envelope.
    /// Legacy plaintext compatibility is intentionally disabled for this path.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Deserialized record or null when missing.</returns>
    public async Task<T?> GetEncryptedAsync<T>(string partition, string id, CancellationToken cancellationToken)
    {
        var record = await dbContext.Records.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Partition == partition && item.Id == id, cancellationToken);
        if (record is null)
        {
            return default;
        }

        if (!recordEncryptor.IsProtectedPayload(record.Json))
        {
            throw new InvalidOperationException("This HIP record partition requires authenticated encrypted payloads.");
        }

        return HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json));
    }

    /// <summary>
    /// Lists and decrypts all typed records for a partition without exposing decrypted payloads to logs.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Records ordered by update time descending.</returns>
    public async Task<IReadOnlyCollection<T>> ListAsync<T>(string partition, CancellationToken cancellationToken)
    {
        var records = await dbContext.Records.AsNoTracking()
            .Where(item => item.Partition == partition)
            .ToArrayAsync(cancellationToken);

        return records
            .OrderByDescending(record => record.UpdatedAtUtc)
            .Select(record => HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json)))
            .ToArray();
    }

    /// <summary>
    /// Lists a bounded set of recent typed records for dashboard hot paths.
    /// This limits encrypted payload decryption to the requested window and avoids scanning full history on page load.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="maxCount">Maximum number of recent records to decrypt.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Records ordered by update time descending.</returns>
    public async Task<IReadOnlyCollection<T>> ListRecentAsync<T>(string partition, int maxCount, CancellationToken cancellationToken)
    {
        var boundedMax = Math.Max(0, maxCount);
        if (boundedMax == 0)
        {
            return Array.Empty<T>();
        }

        var records = await dbContext.Records.AsNoTracking()
            .Where(item => item.Partition == partition)
            .OrderByDescending(record => record.UpdatedAtUtc)
            .Take(boundedMax)
            .ToArrayAsync(cancellationToken);

        return records
            .Select(record => HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json)))
            .ToArray();
    }

    /// <summary>
    /// Removes a typed record by partition and identifier.
    /// </summary>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    public async Task RemoveAsync(string partition, string id, CancellationToken cancellationToken)
    {
        var record = await dbContext.Records.FindAsync([partition, id], cancellationToken);
        if (record is null)
        {
            return;
        }

        dbContext.Records.Remove(record);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Replaces the just-created insert with an update when another request inserted the same logical record first.
    /// This keeps generic encrypted records safe under concurrent browser scan submissions without logging payload data.
    /// </summary>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="protectedPayload">Encrypted JSON payload that must be written after the duplicate insert race.</param>
    /// <param name="updatedAtUtc">Timestamp to apply to the winning update.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    private async Task UpdateAfterDuplicateInsertAsync(
        string partition,
        string id,
        string protectedPayload,
        DateTimeOffset updatedAtUtc,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        var existing = await dbContext.Records.FindAsync([partition, id], cancellationToken);
        if (existing is null)
        {
            throw new DbUpdateConcurrencyException("HIP record insert collided, but the existing record could not be reloaded.");
        }

        existing.Json = protectedPayload;
        existing.UpdatedAtUtc = updatedAtUtc;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Detects duplicate-key errors through the shared classifier so HIP can retry insert races without carrying
    /// test-only database provider assemblies in runtime projects.
    /// </summary>
    /// <param name="exception">EF Core update exception raised while saving a generic HIP record.</param>
    /// <returns>True when the exception represents a duplicate primary key insert race.</returns>
    private static bool IsDuplicateKeyViolation(DbUpdateException exception) =>
        RelationalExceptionClassifier.IsDuplicateKeyViolation(exception);
}
