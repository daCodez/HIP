using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Stores typed HIP records in the generic database table using encrypted JSON payloads.
/// </summary>
/// <param name="dbContext">HIP EF Core database context.</param>
/// <param name="encryptor">Record encryptor. Tests may omit it to use the local development encryptor.</param>
public sealed class HipRecordStore(HipDbContext dbContext, IHipRecordEncryptor? encryptor = null)
{
    private const int MaximumPartitionLength = 160;
    private const int MaximumRecordIdLength = 220;
    private const int MaximumEncryptedPageSize = 100;
    private static readonly SemaphoreSlim InMemoryVersionedWriteGate = new(1, 1);
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
        TrySaveVersionedWithRelatedRecordsAsync(
            partition,
            id,
            value,
            expectedVersion,
            newVersion,
            [],
            cancellationToken);

    /// <summary>
    /// Atomically updates an existing encrypted aggregate at the expected database version.
    /// Unlike first-insert CAS, version zero is valid here so legacy rows can enter versioned updates safely.
    /// </summary>
    public async Task<bool> TryUpdateVersionedAsync<T>(
        string partition,
        string id,
        T value,
        long expectedVersion,
        long newVersion,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(value);
        if (expectedVersion < 0 || expectedVersion == long.MaxValue || newVersion != expectedVersion + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(newVersion),
                "A versioned HIP record update must advance the expected version by exactly one.");
        }

        var now = DateTimeOffset.UtcNow;
        var protectedPayload = recordEncryptor.Protect(HipJsonSerializer.Serialize(value));
        if (string.Equals(
                dbContext.Database.ProviderName,
                "Microsoft.EntityFrameworkCore.InMemory",
                StringComparison.Ordinal))
        {
            await InMemoryVersionedWriteGate.WaitAsync(cancellationToken);
            try
            {
                dbContext.ChangeTracker.Clear();
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
                try
                {
                    await dbContext.SaveChangesAsync(cancellationToken);
                    return true;
                }
                catch (DbUpdateConcurrencyException)
                {
                    dbContext.ChangeTracker.Clear();
                    return false;
                }
            }
            finally
            {
                InMemoryVersionedWriteGate.Release();
            }
        }

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
        return affectedRows == 1;
    }

    /// <summary>
    /// Commits an encrypted aggregate compare-and-swap and its encrypted related records in one database transaction.
    /// </summary>
    /// <typeparam name="TAggregate">Aggregate snapshot type.</typeparam>
    /// <param name="partition">Logical aggregate partition.</param>
    /// <param name="id">Aggregate identifier.</param>
    /// <param name="value">New immutable aggregate snapshot.</param>
    /// <param name="expectedVersion">Version that must currently be stored, or zero for the first insert.</param>
    /// <param name="newVersion">Version stored with the new snapshot; it must be exactly one greater than expected.</param>
    /// <param name="relatedRecords">Bounded records that must be persisted only when the aggregate write wins.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <param name="versionGuards">Bounded exact record versions that must remain unchanged until commit.</param>
    /// <returns>True when the complete transaction committed; false when CAS or an identifier collision rejected it.</returns>
    public async Task<bool> TrySaveVersionedWithRelatedRecordsAsync<TAggregate>(
        string partition,
        string id,
        TAggregate value,
        long expectedVersion,
        long newVersion,
        IReadOnlyCollection<HipRelatedRecordWrite> relatedRecords,
        CancellationToken cancellationToken,
        IReadOnlyCollection<HipVersionedRecordGuard>? versionGuards = null)
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

        var resolvedVersionGuards = versionGuards ??
            [new HipVersionedRecordGuard(partition, id, expectedVersion)];
        if (resolvedVersionGuards.Count is < 1 or > 16)
        {
            throw new ArgumentOutOfRangeException(
                nameof(versionGuards),
                "An atomic HIP record commit requires between one and sixteen version guards.");
        }

        var guardKeys = new HashSet<(string Partition, string Id)>();
        foreach (var guard in resolvedVersionGuards)
        {
            ArgumentNullException.ThrowIfNull(guard);
            ArgumentException.ThrowIfNullOrWhiteSpace(guard.Partition);
            ArgumentException.ThrowIfNullOrWhiteSpace(guard.Id);
            if (guard.Partition.Length > MaximumPartitionLength ||
                guard.Id.Length > MaximumRecordIdLength ||
                guard.ExpectedVersion < 0 ||
                guard.ExpectedVersion == long.MaxValue)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(versionGuards),
                    "An atomic HIP record version guard is outside the encrypted record bounds.");
            }

            if (!guardKeys.Add((guard.Partition, guard.Id)))
            {
                throw new ArgumentException(
                    "An atomic HIP record commit cannot contain duplicate version guards.",
                    nameof(versionGuards));
            }
        }

        if (!resolvedVersionGuards.Any(guard =>
                guard.Partition == partition &&
                guard.Id == id &&
                guard.ExpectedVersion == expectedVersion))
        {
            throw new ArgumentException(
                "An atomic HIP record commit must guard its primary aggregate at the expected version.",
                nameof(versionGuards));
        }

        var now = DateTimeOffset.UtcNow;
        var protectedPayload = recordEncryptor.Protect(HipJsonSerializer.Serialize(value));
        var relatedKeys = new HashSet<(string Partition, string Id)>();
        var encryptedRelatedRecords = relatedRecords.Select(write =>
        {
            ArgumentNullException.ThrowIfNull(write);
            ArgumentException.ThrowIfNullOrWhiteSpace(write.Partition);
            ArgumentException.ThrowIfNullOrWhiteSpace(write.Id);
            if (!write.HasValue)
            {
                throw new ArgumentNullException(nameof(relatedRecords), "Related HIP record values cannot be null.");
            }
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
                Json = recordEncryptor.Protect(write.SerializeValue()),
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
                resolvedVersionGuards,
                now,
                cancellationToken);
        }

        var isolationLevel = resolvedVersionGuards.Count > 1
            ? IsolationLevel.Serializable
            : IsolationLevel.ReadCommitted;
        var executionStrategy = dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(ExecuteTransactionAsync).ConfigureAwait(false);

        async Task<bool> ExecuteTransactionAsync()
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                isolationLevel,
                cancellationToken);
            try
            {
                if (!await VersionGuardsMatchAsync(resolvedVersionGuards, cancellationToken).ConfigureAwait(false))
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return false;
                }

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
            catch (DbUpdateException exception) when (
                exception.InnerException is PostgresException postgresException &&
                postgresException.SqlState == PostgresErrorCodes.SerializationFailure)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                dbContext.ChangeTracker.Clear();
                return false;
            }
            catch (PostgresException exception) when (
                exception.SqlState == PostgresErrorCodes.SerializationFailure)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                dbContext.ChangeTracker.Clear();
                return false;
            }
        }
    }

    private async Task<bool> TrySaveVersionedInMemoryAsync(
        string partition,
        string id,
        string protectedPayload,
        long expectedVersion,
        long newVersion,
        IReadOnlyCollection<HipDbRecord> encryptedRelatedRecords,
        IReadOnlyCollection<HipVersionedRecordGuard> versionGuards,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await InMemoryVersionedWriteGate.WaitAsync(cancellationToken);
        try
        {
            dbContext.ChangeTracker.Clear();
            if (!await VersionGuardsMatchAsync(versionGuards, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

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
            catch (DbUpdateConcurrencyException)
            {
                dbContext.ChangeTracker.Clear();
                return false;
            }
            catch (DbUpdateException exception) when (IsDuplicateKeyViolation(exception))
            {
                dbContext.ChangeTracker.Clear();
                return false;
            }
        }
        finally
        {
            InMemoryVersionedWriteGate.Release();
        }
    }

    private async Task<bool> VersionGuardsMatchAsync(
        IReadOnlyCollection<HipVersionedRecordGuard> versionGuards,
        CancellationToken cancellationToken)
    {
        foreach (var guard in versionGuards)
        {
            var storedVersion = await dbContext.Records
                .AsNoTracking()
                .Where(record => record.Partition == guard.Partition && record.Id == guard.Id)
                .Select(record => (long?)record.AggregateVersion)
                .SingleOrDefaultAsync(cancellationToken)
                .ConfigureAwait(false);
            if (guard.ExpectedVersion == 0
                    ? storedVersion is not null
                    : storedVersion != guard.ExpectedVersion)
            {
                return false;
            }
        }

        return true;
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
    /// Reads a typed record together with its database compare-and-swap version.
    /// </summary>
    public async Task<(T Record, long AggregateVersion)?> GetVersionedAsync<T>(
        string partition,
        string id,
        CancellationToken cancellationToken)
    {
        var record = await dbContext.Records.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Partition == partition && item.Id == id, cancellationToken);
        if (record is null)
        {
            return null;
        }

        return (HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json)), record.AggregateVersion);
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
        var storedRecord = await GetEncryptedVersionedAsync<T>(partition, id, cancellationToken)
            .ConfigureAwait(false);
        return storedRecord is null ? default : storedRecord.Value.Record;
    }

    /// <summary>
    /// Gets and decrypts a typed record together with its database compare-and-swap version.
    /// Security-sensitive aggregate repositories must compare this version with authenticated version data in the payload.
    /// </summary>
    /// <typeparam name="T">Record type.</typeparam>
    /// <param name="partition">Logical partition name.</param>
    /// <param name="id">Record identifier.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The decrypted record and database aggregate version, or null when the record does not exist.</returns>
    public async Task<(T Record, long AggregateVersion)?> GetEncryptedVersionedAsync<T>(
        string partition,
        string id,
        CancellationToken cancellationToken)
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

        return (
            HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(record.Json)),
            record.AggregateVersion);
    }

    /// <summary>
    /// Reads one bounded, identifier-ordered page from an exact partition while rejecting legacy
    /// plaintext rows. The query materializes only <paramref name="pageSize"/> plus one sentinel
    /// row, and decrypts only the rows returned to the caller.
    /// </summary>
    /// <typeparam name="T">Record payload type.</typeparam>
    /// <param name="partition">Exact logical partition name.</param>
    /// <param name="afterId">Exact last-returned record identifier, or null for the first page.</param>
    /// <param name="pageSize">Requested page size from 1 through 100.</param>
    /// <param name="cancellationToken">Token used to cancel query and decryption work.</param>
    /// <returns>A bounded authenticated page and the next raw record identifier when more rows exist.</returns>
    public async Task<HipEncryptedRecordPage<T>> ListEncryptedPageAsync<T>(
        string partition,
        string? afterId,
        int pageSize,
        CancellationToken cancellationToken)
    {
        ValidateRecordIdentifier(partition, MaximumPartitionLength, nameof(partition));
        if (afterId is not null)
        {
            ValidateRecordIdentifier(afterId, MaximumRecordIdLength, nameof(afterId));
        }

        if (pageSize is < 1 or > MaximumEncryptedPageSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize),
                $"Encrypted record page size must be between 1 and {MaximumEncryptedPageSize}.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var query = dbContext.Records.AsNoTracking()
            .Where(record => record.Partition == partition);
        HipDbRecord[] storedRows;
        if (string.Equals(
                dbContext.Database.ProviderName,
                "Microsoft.EntityFrameworkCore.InMemory",
                StringComparison.Ordinal))
        {
            storedRows = await ListInMemoryOrdinalPageAsync(
                    query,
                    afterId,
                    pageSize,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            IOrderedQueryable<HipDbRecord> orderedQuery;
            if (string.Equals(
                    dbContext.Database.ProviderName,
                    "Npgsql.EntityFrameworkCore.PostgreSQL",
                    StringComparison.Ordinal))
            {
                if (afterId is not null)
                {
                    query = query.Where(record =>
                        EF.Functions.Collate(record.Id, "C").CompareTo(afterId) > 0);
                }

                // PostgreSQL database defaults are deployment-specific. Pin service cursor order to its
                // bytewise C collation so it matches the shared ordinal application cursor contract.
                orderedQuery = query.OrderBy(record => EF.Functions.Collate(record.Id, "C"));
            }
            else
            {
                if (afterId is not null)
                {
                    query = query.Where(record => record.Id.CompareTo(afterId) > 0);
                }

                orderedQuery = query.OrderBy(record => record.Id);
            }

            storedRows = await orderedQuery
                .Take(pageSize + 1)
                .ToArrayAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        if (storedRows.Any(row => !recordEncryptor.IsProtectedPayload(row.Json)))
        {
            throw new InvalidOperationException("This HIP record partition requires authenticated encrypted payloads.");
        }

        var returnedCount = Math.Min(pageSize, storedRows.Length);
        var items = new HipEncryptedRecordPageItem<T>[returnedCount];
        for (var index = 0; index < returnedCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var row = storedRows[index];
            items[index] = new HipEncryptedRecordPageItem<T>(
                row.Id,
                HipJsonSerializer.Deserialize<T>(recordEncryptor.Unprotect(row.Json)),
                row.AggregateVersion);
        }

        var nextCursor = storedRows.Length > pageSize
            ? items[^1].Id
            : null;
        return new HipEncryptedRecordPage<T>(Array.AsReadOnly(items), nextCursor);
    }

    /// <summary>
    /// Applies the production ordinal cursor contract for EF's process-local test provider, which
    /// cannot translate an explicit string comparer. Runtime persistence remains PostgreSQL and
    /// always applies its bound before materialization.
    /// </summary>
    private static async Task<HipDbRecord[]> ListInMemoryOrdinalPageAsync(
        IQueryable<HipDbRecord> partitionQuery,
        string? afterId,
        int pageSize,
        CancellationToken cancellationToken)
    {
        var partitionRows = await partitionQuery.ToArrayAsync(cancellationToken).ConfigureAwait(false);
        return partitionRows
            .Where(record => afterId is null || string.CompareOrdinal(record.Id, afterId) > 0)
            .OrderBy(record => record.Id, StringComparer.Ordinal)
            .Take(pageSize + 1)
            .ToArray();
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

    /// <summary>
    /// Rejects blank, oversized, padded, or control-bearing record keys before they reach a query.
    /// </summary>
    private static void ValidateRecordIdentifier(string value, int maximumLength, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maximumLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("The HIP record identifier is invalid.", parameterName);
        }
    }
}
