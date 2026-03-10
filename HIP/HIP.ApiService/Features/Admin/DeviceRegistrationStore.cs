namespace HIP.ApiService.Features.Admin;

internal sealed class DeviceRegistrationStore
{
    private readonly object _gate = new();
    private readonly List<DeviceRegistrationEntry> _devices =
    [
        new("Nora Kim", "nora@hip.local", "MacBook Pro", "Trusted", DateTime.UtcNow.AddMinutes(-5)),
        new("Derek Holt", "derek@hip.local", "Pixel 9", "Pending", DateTime.UtcNow.AddMinutes(-18)),
        new("Mina Rao", "mina@hip.local", "Windows 11", "Blocked", DateTime.UtcNow.AddHours(-3))
    ];

    private readonly List<DeviceActionHistoryEntry> _history =
    [
        new("nora@hip.local", "MacBook Pro", "register", "Pending", "Initial enrollment", "system", DateTime.UtcNow.AddHours(-8)),
        new("nora@hip.local", "MacBook Pro", "approve", "Trusted", "Known employee laptop", "admin", DateTime.UtcNow.AddHours(-7)),
        new("derek@hip.local", "Pixel 9", "register", "Pending", "Awaiting analyst review", "analyst", DateTime.UtcNow.AddMinutes(-18)),
        new("mina@hip.local", "Windows 11", "block", "Blocked", "Fingerprint mismatch and geo anomaly", "admin", DateTime.UtcNow.AddHours(-3))
    ];

    public IReadOnlyList<DeviceRegistrationEntry> GetAll()
    {
        lock (_gate)
        {
            return _devices
                .OrderByDescending(x => x.LastSeenUtc)
                .Select(x => x with { })
                .ToList();
        }
    }

    public DeviceRegistrationEntry Register(DeviceRegistrationEntry entry, string actor)
    {
        lock (_gate)
        {
            _devices.Add(entry);
            _history.Add(new DeviceActionHistoryEntry(entry.Email, entry.Device, "register", entry.DeviceStatus, "Registration submitted", actor, DateTime.UtcNow));
            return entry;
        }
    }

    public DeviceRegistrationEntry? UpdateStatus(string email, string device, string status, string action, string note, string actor)
    {
        lock (_gate)
        {
            var ix = _devices.FindIndex(x =>
                x.Email.Equals(email, StringComparison.OrdinalIgnoreCase)
                && x.Device.Equals(device, StringComparison.OrdinalIgnoreCase));

            if (ix < 0)
            {
                return null;
            }

            var current = _devices[ix];
            var updated = current with { DeviceStatus = status, LastSeenUtc = DateTime.UtcNow };
            _devices[ix] = updated;
            _history.Add(new DeviceActionHistoryEntry(email, device, action, status, note, actor, DateTime.UtcNow));
            return updated;
        }
    }

    public IReadOnlyList<DeviceActionHistoryEntry> GetHistory(string email, string device)
    {
        lock (_gate)
        {
            return _history
                .Where(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase) && x.Device.Equals(device, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.TimestampUtc)
                .ToList();
        }
    }
}

internal sealed record DeviceActionHistoryEntry(
    string Email,
    string Device,
    string Action,
    string Status,
    string Note,
    string Actor,
    DateTime TimestampUtc);

internal sealed record DeviceRegistrationEntry(
    string User,
    string Email,
    string Device,
    string DeviceStatus,
    DateTime LastSeenUtc);
