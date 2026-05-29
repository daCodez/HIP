using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

public sealed class HipRecordStore(HipDbContext dbContext)
{
    public async Task SaveAsync<T>(string partition, string id, T value, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var record = await dbContext.Records.FindAsync([partition, id], cancellationToken);
        if (record is null)
        {
            dbContext.Records.Add(new HipDbRecord
            {
                Partition = partition,
                Id = id,
                Json = HipJsonSerializer.Serialize(value),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });
        }
        else
        {
            record.Json = HipJsonSerializer.Serialize(value);
            record.UpdatedAtUtc = now;
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<T?> GetAsync<T>(string partition, string id, CancellationToken cancellationToken)
    {
        var record = await dbContext.Records.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Partition == partition && item.Id == id, cancellationToken);

        return record is null ? default : HipJsonSerializer.Deserialize<T>(record.Json);
    }

    public async Task<IReadOnlyCollection<T>> ListAsync<T>(string partition, CancellationToken cancellationToken)
    {
        var records = await dbContext.Records.AsNoTracking()
            .Where(item => item.Partition == partition)
            .ToArrayAsync(cancellationToken);

        return records
            .OrderByDescending(record => record.UpdatedAtUtc)
            .Select(record => HipJsonSerializer.Deserialize<T>(record.Json))
            .ToArray();
    }
}
