using System.Collections.Concurrent;
using System.Text.Json;

namespace HIP.Application.Scalability;

/// <summary>
/// Processing state for HIP durable events.
/// </summary>
public enum HipDurableEventStatus
{
    /// <summary>
    /// Event has been stored but not dispatched.
    /// </summary>
    Pending,

    /// <summary>
    /// Event has been successfully dispatched or consumed.
    /// </summary>
    Processed,

    /// <summary>
    /// Event processing failed and may be retried.
    /// </summary>
    Failed
}

/// <summary>
/// Privacy classification for durable event payloads.
/// </summary>
public enum HipDurableEventPrivacyLevel
{
    /// <summary>
    /// Payload contains only public-safe summary fields such as domain, score, and status.
    /// </summary>
    PublicSafe,

    /// <summary>
    /// Payload contains hashed identifiers and must not be exposed directly to public users.
    /// </summary>
    HashedSensitive,

    /// <summary>
    /// Payload contains private material and should not be used by HIP scan/review events.
    /// </summary>
    Private
}

/// <summary>
/// Durable event stored in the outbox for retry-safe scan, provider, and review workflows.
/// </summary>
/// <param name="EventId">Unique event id.</param>
/// <param name="EventType">Event type such as BrowserScanResultStored.</param>
/// <param name="AggregateType">Aggregate type that produced the event.</param>
/// <param name="AggregateId">Aggregate id that produced the event.</param>
/// <param name="OccurredAtUtc">UTC event creation time.</param>
/// <param name="PayloadJson">Privacy-safe serialized payload.</param>
/// <param name="PrivacyLevel">Payload privacy classification.</param>
/// <param name="Status">Dispatch status.</param>
/// <param name="AttemptCount">Dispatch attempt count.</param>
/// <param name="LastError">Safe last error message, if any.</param>
/// <param name="ProcessedAtUtc">UTC time when processing completed.</param>
public sealed record HipDurableEvent(
    string EventId,
    string EventType,
    string AggregateType,
    string AggregateId,
    DateTimeOffset OccurredAtUtc,
    string PayloadJson,
    HipDurableEventPrivacyLevel PrivacyLevel,
    HipDurableEventStatus Status = HipDurableEventStatus.Pending,
    int AttemptCount = 0,
    string? LastError = null,
    DateTimeOffset? ProcessedAtUtc = null);

/// <summary>
/// Inbox record used to make event consumption idempotent.
/// </summary>
/// <param name="EventId">Source event id.</param>
/// <param name="ConsumerName">Consumer identity.</param>
/// <param name="StartedAtUtc">UTC time processing was first accepted.</param>
/// <param name="ProcessedAtUtc">UTC time processing completed.</param>
/// <param name="Status">Processing status.</param>
public sealed record HipInboxEvent(
    string EventId,
    string ConsumerName,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? ProcessedAtUtc,
    HipDurableEventStatus Status);

/// <summary>
/// Repository boundary for retry-safe outbox events.
/// </summary>
public interface IOutboxEventRepository
{
    /// <summary>
    /// Saves a durable event.
    /// </summary>
    /// <param name="durableEvent">Event to save.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes after storage.</returns>
    Task SaveAsync(HipDurableEvent durableEvent, CancellationToken cancellationToken);

    /// <summary>
    /// Lists pending or retryable events.
    /// </summary>
    /// <param name="maxCount">Maximum number of events to return.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Pending events ordered by occurrence time.</returns>
    Task<IReadOnlyCollection<HipDurableEvent>> ListPendingAsync(int maxCount, CancellationToken cancellationToken);

    /// <summary>
    /// Marks an event as processed after successful dispatch.
    /// </summary>
    /// <param name="eventId">Event id.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes after the status is saved.</returns>
    Task MarkProcessedAsync(string eventId, CancellationToken cancellationToken);
}

/// <summary>
/// Repository boundary for inbox idempotency records.
/// </summary>
public interface IInboxEventRepository
{
    /// <summary>
    /// Attempts to reserve an event for one consumer.
    /// </summary>
    /// <param name="eventId">Event id.</param>
    /// <param name="consumerName">Consumer identity.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>True when processing should continue; false when the event was already accepted.</returns>
    Task<bool> TryStartProcessingAsync(string eventId, string consumerName, CancellationToken cancellationToken);

    /// <summary>
    /// Marks a previously accepted event as processed.
    /// </summary>
    /// <param name="eventId">Event id.</param>
    /// <param name="consumerName">Consumer identity.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes after the status is saved.</returns>
    Task MarkProcessedAsync(string eventId, string consumerName, CancellationToken cancellationToken);
}

/// <summary>
/// Writes durable outbox events from application services.
/// </summary>
public interface IOutboxEventWriter
{
    /// <summary>
    /// Enqueues a privacy-safe outbox event.
    /// </summary>
    /// <param name="durableEvent">Event to persist.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes after the event is stored.</returns>
    Task EnqueueAsync(HipDurableEvent durableEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Default outbox writer that keeps application services independent of storage implementation details.
/// </summary>
/// <param name="repository">Outbox repository.</param>
public sealed class OutboxEventWriter(IOutboxEventRepository repository) : IOutboxEventWriter
{
    /// <inheritdoc />
    public Task EnqueueAsync(HipDurableEvent durableEvent, CancellationToken cancellationToken) =>
        repository.SaveAsync(durableEvent, cancellationToken);
}

/// <summary>
/// In-memory outbox repository for local development and focused tests.
/// </summary>
public sealed class InMemoryOutboxEventRepository : IOutboxEventRepository
{
    private readonly ConcurrentDictionary<string, HipDurableEvent> events = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task SaveAsync(HipDurableEvent durableEvent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        events[durableEvent.EventId] = durableEvent;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<HipDurableEvent>> ListPendingAsync(int maxCount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var pending = events.Values
            .Where(item => item.Status is HipDurableEventStatus.Pending or HipDurableEventStatus.Failed)
            .OrderBy(item => item.OccurredAtUtc)
            .Take(Math.Max(0, maxCount))
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<HipDurableEvent>>(pending);
    }

    /// <inheritdoc />
    public Task MarkProcessedAsync(string eventId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (events.TryGetValue(eventId, out var durableEvent))
        {
            events[eventId] = durableEvent with
            {
                Status = HipDurableEventStatus.Processed,
                ProcessedAtUtc = DateTimeOffset.UtcNow,
                AttemptCount = durableEvent.AttemptCount + 1
            };
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// In-memory inbox repository for local idempotency tests.
/// </summary>
public sealed class InMemoryInboxEventRepository : IInboxEventRepository
{
    private readonly ConcurrentDictionary<string, HipInboxEvent> records = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task<bool> TryStartProcessingAsync(string eventId, string consumerName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = InboxKey(eventId, consumerName);
        var record = new HipInboxEvent(eventId, consumerName, DateTimeOffset.UtcNow, null, HipDurableEventStatus.Pending);
        return Task.FromResult(records.TryAdd(key, record));
    }

    /// <inheritdoc />
    public Task MarkProcessedAsync(string eventId, string consumerName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = InboxKey(eventId, consumerName);
        if (records.TryGetValue(key, out var record))
        {
            records[key] = record with
            {
                Status = HipDurableEventStatus.Processed,
                ProcessedAtUtc = DateTimeOffset.UtcNow
            };
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Builds the idempotency key for one event and consumer.
    /// </summary>
    /// <param name="eventId">Event id.</param>
    /// <param name="consumerName">Consumer name.</param>
    /// <returns>Stable inbox key.</returns>
    private static string InboxKey(string eventId, string consumerName) => $"{consumerName}:{eventId}";
}

/// <summary>
/// Factory helpers for common HIP durable events.
/// </summary>
public static class HipDurableEventFactory
{
    /// <summary>
    /// Creates a durable event with a JSON payload that must already be privacy-safe.
    /// </summary>
    /// <param name="eventType">Event type.</param>
    /// <param name="aggregateType">Aggregate type.</param>
    /// <param name="aggregateId">Aggregate id.</param>
    /// <param name="payload">Anonymous or typed payload to serialize.</param>
    /// <param name="privacyLevel">Payload privacy level.</param>
    /// <returns>Durable outbox event.</returns>
    public static HipDurableEvent Create(
        string eventType,
        string aggregateType,
        string aggregateId,
        object payload,
        HipDurableEventPrivacyLevel privacyLevel) =>
        new(
            $"evt:{Guid.NewGuid():N}",
            eventType,
            aggregateType,
            aggregateId,
            DateTimeOffset.UtcNow,
            JsonSerializer.Serialize(payload),
            privacyLevel);
}
