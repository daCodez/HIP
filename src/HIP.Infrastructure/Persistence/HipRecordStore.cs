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

        var query = dbContext.Records.AsNoTracking()
            .Where(item => item.Partition == partition);

        var records = dbContext.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true
            ? (await query.ToArrayAsync(cancellationToken))
                .OrderByDescending(record => record.UpdatedAtUtc)
                .Take(boundedMax)
                .ToArray()
            : await query
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
