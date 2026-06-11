using HIP.Application.Scalability;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed outbox repository using HIP's encrypted generic record store.
/// </summary>
/// <param name="store">Encrypted HIP record store.</param>
public sealed class EfOutboxEventRepository(HipRecordStore store) : IOutboxEventRepository
{
    private const string Partition = "outbox-event";

    /// <inheritdoc />
    public Task SaveAsync(HipDurableEvent durableEvent, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, durableEvent.EventId, durableEvent, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<HipDurableEvent>> ListPendingAsync(int maxCount, CancellationToken cancellationToken)
    {
        var events = await store.ListAsync<HipDurableEvent>(Partition, cancellationToken);
        return events
            .Where(item => item.Status is HipDurableEventStatus.Pending or HipDurableEventStatus.Failed)
            .OrderBy(item => item.OccurredAtUtc)
            .Take(Math.Max(0, maxCount))
            .ToArray();
    }

    /// <inheritdoc />
    public async Task MarkProcessedAsync(string eventId, CancellationToken cancellationToken)
    {
        var durableEvent = await store.GetAsync<HipDurableEvent>(Partition, eventId, cancellationToken);
        if (durableEvent is null)
        {
            return;
        }

        await store.SaveAsync(
            Partition,
            eventId,
            durableEvent with
            {
                Status = HipDurableEventStatus.Processed,
                ProcessedAtUtc = DateTimeOffset.UtcNow,
                AttemptCount = durableEvent.AttemptCount + 1
            },
            cancellationToken);
    }
}
