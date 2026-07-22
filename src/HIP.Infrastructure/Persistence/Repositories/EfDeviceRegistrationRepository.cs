using HIP.Application.Devices;
using HIP.Domain.Audit;
using HIP.Domain.Devices;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists owner-scoped device-registration aggregates with encrypted compare-and-swap writes.
/// Global device and public-key bindings are insert-only related records committed with the aggregate and audit facts.
/// </summary>
public sealed class EfDeviceRegistrationRepository(HipRecordStore store) : IDeviceRegistrationRepository
{
    internal const string AggregatePartition = "device-registration-owner";
    internal const string DeviceBindingPartition = "device-registration-device-binding";
    internal const string KeyBindingPartition = "device-registration-key-binding";
    internal const string AuditPartition = "audit-log";

    private const string DeviceBindingType = "device-id";
    private const string KeyBindingType = "device-public-key";

    /// <inheritdoc />
    public async Task<DeviceRegistrationAggregate?> GetAsync(
        string ownerScopeId,
        CancellationToken cancellationToken)
    {
        DeviceRegistrationTransitionValidator.ValidateOwnerScopeId(ownerScopeId, nameof(ownerScopeId));
        var stored = await store.GetEncryptedVersionedAsync<DeviceRegistrationAggregate>(
                AggregatePartition,
                ownerScopeId,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        DeviceRegistrationTransitionValidator.ValidateStoredAggregate(
            stored.Value.Record,
            ownerScopeId,
            stored.Value.AggregateVersion);
        return stored.Value.Record;
    }

    /// <inheritdoc />
    public async Task<RegisteredDevice?> GetDeviceAsync(
        string deviceId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        var binding = await store.GetEncryptedAsync<DeviceRegistrationBinding>(
                DeviceBindingPartition,
                deviceId,
                cancellationToken)
            .ConfigureAwait(false);
        if (binding is null)
        {
            return null;
        }
        ValidateStoredBinding(binding, DeviceBindingType, deviceId);
        var aggregate = await GetAsync(binding.OwnerScopeId, cancellationToken).ConfigureAwait(false);
        var device = aggregate?.Devices.SingleOrDefault(candidate =>
            string.Equals(candidate.DeviceId, deviceId, StringComparison.Ordinal));
        if (device is null)
        {
            throw new InvalidOperationException("Persisted device binding has no matching owner device.");
        }
        return device;
    }

    /// <inheritdoc />
    public async Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
        DeviceRegistrationTransitionBatch transition,
        CancellationToken cancellationToken)
    {
        DeviceRegistrationTransitionValidator.ValidateTransition(transition);
        var aggregate = transition.Aggregate;
        var stored = await store.GetEncryptedVersionedAsync<DeviceRegistrationAggregate>(
                AggregatePartition,
                aggregate.OwnerScopeId,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is not null)
        {
            DeviceRegistrationTransitionValidator.ValidateStoredAggregate(
                stored.Value.Record,
                aggregate.OwnerScopeId,
                stored.Value.AggregateVersion);
        }

        if ((stored is null && transition.ExpectedVersion != 0) ||
            (stored is not null && stored.Value.AggregateVersion != transition.ExpectedVersion))
        {
            return DeviceRegistrationSaveOutcome.VersionConflict;
        }

        DeviceRegistrationTransitionValidator.ValidateDelta(stored?.Record, transition);
        var relatedWrites = new List<HipRelatedRecordWrite>(
            transition.NewBindings.Count + transition.AuditEntries.Count);
        relatedWrites.AddRange(transition.NewBindings.Select(binding =>
            (HipRelatedRecordWrite)new HipRelatedRecordWrite<DeviceRegistrationBinding>(
                BindingPartition(binding.BindingType),
                binding.BindingId,
                binding)));
        relatedWrites.AddRange(transition.AuditEntries.Select(entry =>
            (HipRelatedRecordWrite)new HipRelatedRecordWrite<AuditLogEntry>(
                AuditPartition,
                entry.AuditLogId,
                entry)));
        var versionGuards = DeviceRegistrationTransitionValidator
            .ResolveOwnerVersionGuards(transition)
            .Select(guard => new HipVersionedRecordGuard(
                AggregatePartition,
                guard.OwnerScopeId,
                guard.ExpectedVersion))
            .ToArray();

        var saved = await store.TrySaveVersionedWithRelatedRecordsAsync(
                AggregatePartition,
                aggregate.OwnerScopeId,
                aggregate,
                transition.ExpectedVersion,
                aggregate.Version,
                relatedWrites,
                cancellationToken,
                versionGuards)
            .ConfigureAwait(false);
        if (saved)
        {
            return DeviceRegistrationSaveOutcome.Succeeded;
        }

        // The record-store transaction intentionally returns one collision result for both stale CAS and
        // insert-only related-record conflicts. Read the security-sensitive binding keys after rollback so
        // callers can retry only a stale owner aggregate without weakening global key/device uniqueness.
        foreach (var requestedBinding in transition.NewBindings)
        {
            var storedBinding = await store.GetEncryptedAsync<DeviceRegistrationBinding>(
                    BindingPartition(requestedBinding.BindingType),
                    requestedBinding.BindingId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (storedBinding is null)
            {
                continue;
            }

            ValidateStoredBinding(
                storedBinding,
                requestedBinding.BindingType,
                requestedBinding.BindingId);
            return DeviceRegistrationSaveOutcome.BindingConflict;
        }

        return DeviceRegistrationSaveOutcome.VersionConflict;
    }

    private static void ValidateStoredBinding(
        DeviceRegistrationBinding binding,
        string expectedType,
        string expectedId)
    {
        if (binding is null ||
            !string.Equals(binding.BindingType, expectedType, StringComparison.Ordinal) ||
            !string.Equals(binding.BindingId, expectedId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(binding.DeviceId))
        {
            throw new InvalidOperationException("Persisted device-registration binding data is invalid.");
        }

        DeviceRegistrationTransitionValidator.ValidateOwnerScopeId(
            binding.OwnerScopeId,
            nameof(binding.OwnerScopeId));
    }

    private static string BindingPartition(string bindingType) => bindingType switch
    {
        DeviceBindingType => DeviceBindingPartition,
        KeyBindingType => KeyBindingPartition,
        _ => throw new ArgumentOutOfRangeException(nameof(bindingType), "Unknown device-registration binding type.")
    };
}
