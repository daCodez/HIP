using HIP.Application.Scalability;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed inbox repository that stores idempotency records in HIP's encrypted generic record store.
/// </summary>
/// <param name="store">Encrypted HIP record store.</param>
public sealed class EfInboxEventRepository(HipRecordStore store) : IInboxEventRepository
{
    private const string Partition = "inbox-event";

    /// <inheritdoc />
    public async Task<bool> TryStartProcessingAsync(string eventId, string consumerName, CancellationToken cancellationToken)
    {
        var key = InboxKey(eventId, consumerName);
        var existing = await store.GetAsync<HipInboxEvent>(Partition, key, cancellationToken);
        if (existing is not null)
        {
            return false;
        }

        await store.SaveAsync(
            Partition,
            key,
            new HipInboxEvent(eventId, consumerName, DateTimeOffset.UtcNow, null, HipDurableEventStatus.Pending),
            cancellationToken);

        return true;
    }

    /// <inheritdoc />
    public async Task MarkProcessedAsync(string eventId, string consumerName, CancellationToken cancellationToken)
    {
        var key = InboxKey(eventId, consumerName);
        var record = await store.GetAsync<HipInboxEvent>(Partition, key, cancellationToken);
        if (record is null)
        {
            return;
        }

        await store.SaveAsync(
            Partition,
            key,
            record with
            {
                Status = HipDurableEventStatus.Processed,
                ProcessedAtUtc = DateTimeOffset.UtcNow
            },
            cancellationToken);
    }

    /// <summary>
    /// Builds the idempotency key for one event and consumer.
    /// </summary>
    /// <param name="eventId">Event id.</param>
    /// <param name="consumerName">Consumer identity.</param>
    /// <returns>Stable inbox key.</returns>
    private static string InboxKey(string eventId, string consumerName) => $"{consumerName}:{eventId}";
}
