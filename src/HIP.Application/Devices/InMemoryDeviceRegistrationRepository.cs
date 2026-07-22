using HIP.Domain.Audit;
using HIP.Domain.Devices;

namespace HIP.Application.Devices;

/// <summary>Process-local atomic repository used by focused tests and explicit development-only hosts.</summary>
public sealed class InMemoryDeviceRegistrationRepository : IDeviceRegistrationRepository
{
    private readonly Dictionary<string, DeviceRegistrationAggregate> aggregates = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DeviceRegistrationBinding> bindings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AuditLogEntry> auditEntries = new(StringComparer.Ordinal);
    private readonly object gate = new();

    public Task<DeviceRegistrationAggregate?> GetAsync(
        string ownerScopeId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerScopeId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            aggregates.TryGetValue(ownerScopeId, out var aggregate);
            return Task.FromResult(aggregate);
        }
    }

    public Task<RegisteredDevice?> GetDeviceAsync(string deviceId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var bindingKey = $"device-id\0{deviceId}";
            if (!bindings.TryGetValue(bindingKey, out var binding) ||
                !aggregates.TryGetValue(binding.OwnerScopeId, out var aggregate))
            {
                return Task.FromResult<RegisteredDevice?>(null);
            }
            return Task.FromResult(aggregate.Devices.SingleOrDefault(device =>
                string.Equals(device.DeviceId, deviceId, StringComparison.Ordinal)));
        }
    }

    public Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
        DeviceRegistrationTransitionBatch transition,
        CancellationToken cancellationToken)
    {
        DeviceRegistrationTransitionValidator.ValidateTransition(transition);
        cancellationToken.ThrowIfCancellationRequested();

        lock (gate)
        {
            var aggregate = transition.Aggregate;
            foreach (var guard in DeviceRegistrationTransitionValidator.ResolveOwnerVersionGuards(transition))
            {
                aggregates.TryGetValue(guard.OwnerScopeId, out var guardedAggregate);
                if ((guardedAggregate?.Version ?? 0) != guard.ExpectedVersion)
                {
                    return Task.FromResult(DeviceRegistrationSaveOutcome.VersionConflict);
                }
            }

            DeviceRegistrationAggregate? current = null;

            if (transition.ExpectedVersion == 0)
            {
                if (aggregates.ContainsKey(aggregate.OwnerScopeId))
                {
                    return Task.FromResult(DeviceRegistrationSaveOutcome.VersionConflict);
                }
            }
            else if (!aggregates.TryGetValue(aggregate.OwnerScopeId, out current) ||
                     current.Version != transition.ExpectedVersion)
            {
                return Task.FromResult(DeviceRegistrationSaveOutcome.VersionConflict);
            }

            DeviceRegistrationTransitionValidator.ValidateDelta(current, transition);
            if (transition.NewBindings.Any(binding =>
                    bindings.ContainsKey(BindingKey(binding))))
            {
                return Task.FromResult(DeviceRegistrationSaveOutcome.BindingConflict);
            }

            if (transition.AuditEntries.Any(entry => auditEntries.ContainsKey(entry.AuditLogId)))
            {
                return Task.FromResult(DeviceRegistrationSaveOutcome.VersionConflict);
            }

            aggregates[aggregate.OwnerScopeId] = aggregate;
            foreach (var binding in transition.NewBindings)
            {
                bindings.TryAdd(BindingKey(binding), binding);
            }

            foreach (var entry in transition.AuditEntries)
            {
                auditEntries.Add(entry.AuditLogId, entry);
            }

            return Task.FromResult(DeviceRegistrationSaveOutcome.Succeeded);
        }
    }

    private static string BindingKey(DeviceRegistrationBinding binding) =>
        $"{binding.BindingType}\0{binding.BindingId}";
}
