using HIP.Application.Consumer;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Encrypted owner-hash scoped consumer alert settings.</summary>
public sealed class EfConsumerSettingsRepository(HipRecordStore store) : IConsumerSettingsRepository
{
    private const string Partition = "consumer-settings";

    public async Task<ConsumerSettingsRecord?> GetAsync(
        string consumerScopeHash,
        CancellationToken cancellationToken)
    {
        ValidateHash(consumerScopeHash);
        var stored = await store.GetVersionedAsync<ConsumerSettingsRecord>(
            Partition,
            consumerScopeHash,
            cancellationToken);
        if (stored is null)
        {
            return null;
        }

        Validate(stored.Value.Record);
        return stored.Value.AggregateVersion == stored.Value.Record.Version
            ? stored.Value.Record
            : throw new InvalidOperationException("Consumer settings version is inconsistent.");
    }

    public Task<bool> TrySaveAsync(
        ConsumerSettingsRecord record,
        long expectedVersion,
        CancellationToken cancellationToken)
    {
        Validate(record);
        return expectedVersion == 0
            ? store.TrySaveVersionedAsync(
                Partition,
                record.ConsumerScopeHash,
                record,
                expectedVersion,
                record.Version,
                cancellationToken)
            : store.TryUpdateVersionedAsync(
                Partition,
                record.ConsumerScopeHash,
                record,
                expectedVersion,
                record.Version,
                cancellationToken);
    }

    private static void Validate(ConsumerSettingsRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateHash(record.ConsumerScopeHash);
        ArgumentNullException.ThrowIfNull(record.Settings);
        if (record.Version < 1 || record.UpdatedAtUtc == default)
        {
            throw new ArgumentException("Consumer settings metadata is invalid.", nameof(record));
        }
    }

    private static void ValidateHash(string consumerScopeHash)
    {
        if (string.IsNullOrWhiteSpace(consumerScopeHash) ||
            !consumerScopeHash.StartsWith("sha256:", StringComparison.Ordinal) ||
            consumerScopeHash.Length != 71)
        {
            throw new ArgumentException("Consumer settings require a keyed consumer scope hash.", nameof(consumerScopeHash));
        }
    }
}
