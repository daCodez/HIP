using HIP.Application.Dns;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Stores bounded authoritative zone management state in HIP's encrypted record store.</summary>
public sealed class EfAuthoritativeDnsZoneRepository(HipRecordStore store) : IAuthoritativeDnsZoneRepository
{
    private const string Partition = "authoritative-dns-zones";

    /// <inheritdoc />
    public Task<AuthoritativeDnsZone?> GetAsync(string domain, CancellationToken cancellationToken) =>
        store.GetEncryptedAsync<AuthoritativeDnsZone>(Partition, domain, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AuthoritativeDnsZone>> ListAsync(CancellationToken cancellationToken)
    {
        var page = await store.ListEncryptedPageAsync<AuthoritativeDnsZone>(Partition, null, 100, cancellationToken)
            .ConfigureAwait(false);
        return page.Items.Select(item => item.Record).ToArray();
    }

    /// <inheritdoc />
    public Task<bool> TrySaveAsync(
        AuthoritativeDnsZone zone,
        long expectedVersion,
        CancellationToken cancellationToken) =>
        store.TrySaveVersionedAsync(
            Partition,
            zone.Domain,
            zone,
            expectedVersion,
            zone.Version,
            cancellationToken);
}
