using HIP.Application.Platforms;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed platform connection repository that stores low-volume admin configuration in HIP's encrypted record store.
/// </summary>
public sealed class EfPlatformConnectionRepository(HipRecordStore store) : IPlatformConnectionRepository
{
    private const string Partition = "platform-connections";

    /// <inheritdoc />
    public Task SaveAsync(PlatformConnectionRecord connection, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, connection.PlatformConnectionId, connection, cancellationToken);

    /// <inheritdoc />
    public Task<PlatformConnectionRecord?> GetAsync(string platformConnectionId, CancellationToken cancellationToken) =>
        store.GetAsync<PlatformConnectionRecord>(Partition, platformConnectionId, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<PlatformConnectionRecord>> ListAsync(CancellationToken cancellationToken)
    {
        var records = await store.ListAsync<PlatformConnectionRecord>(Partition, cancellationToken);
        return records
            .OrderByDescending(item => item.UpdatedAtUtc)
            .ToArray();
    }
}
