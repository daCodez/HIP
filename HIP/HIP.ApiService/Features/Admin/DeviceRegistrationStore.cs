using System.Text.Json;

namespace HIP.ApiService.Features.Admin;

internal sealed class DeviceRegistrationStore
{
    private readonly object _gate = new();
    private readonly List<DeviceRegistrationEntry> _devices = [];
    private readonly List<DeviceActionHistoryEntry> _history = [];
    private readonly string _storePath;
    private readonly ILogger<DeviceRegistrationStore> _logger;

    public DeviceRegistrationStore(IConfiguration configuration, IWebHostEnvironment env, ILogger<DeviceRegistrationStore> logger)
    {
        _logger = logger;
        _storePath = configuration["HIP:DeviceRegistration:StorePath"]
            ?? Path.Combine(env.ContentRootPath, "SecurityEvents", "device-registrations.store.json");

        if (TryLoadPersistedState())
        {
            return;
        }

        _devices.AddRange(
        [
            new("Nora Kim", "nora@hip.local", "MacBook Pro", "Trusted", DateTime.UtcNow.AddMinutes(-5)),
            new("Derek Holt", "derek@hip.local", "Pixel 9", "Pending", DateTime.UtcNow.AddMinutes(-18)),
            new("Mina Rao", "mina@hip.local", "Windows 11", "Blocked", DateTime.UtcNow.AddHours(-3))
        ]);

        _history.AddRange(
        [
            new("nora@hip.local", "MacBook Pro", "register", "Pending", "Initial enrollment", "system", DateTime.UtcNow.AddHours(-8)),
            new("nora@hip.local", "MacBook Pro", "approve", "Trusted", "Known employee laptop", "admin", DateTime.UtcNow.AddHours(-7)),
            new("derek@hip.local", "Pixel 9", "register", "Pending", "Awaiting analyst review", "analyst", DateTime.UtcNow.AddMinutes(-18)),
            new("mina@hip.local", "Windows 11", "block", "Blocked", "Fingerprint mismatch and geo anomaly", "admin", DateTime.UtcNow.AddHours(-3))
        ]);

        SavePersistedStateUnsafe();
    }

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
            SavePersistedStateUnsafe();
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
            SavePersistedStateUnsafe();
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

    private bool TryLoadPersistedState()
    {
        try
        {
            if (!File.Exists(_storePath))
            {
                return false;
            }

            var json = File.ReadAllText(_storePath);
            var state = JsonSerializer.Deserialize<DeviceRegistrationStoreState>(json);
            if (state is null)
            {
                return false;
            }

            _devices.Clear();
            _devices.AddRange(state.Devices ?? []);
            _history.Clear();
            _history.AddRange(state.History ?? []);

            _logger.LogInformation("Loaded persisted device registrations from {Path}: devices={DeviceCount}, history={HistoryCount}", _storePath, _devices.Count, _history.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load persisted device registrations from {Path}. Falling back to seed data.", _storePath);
            return false;
        }
    }

    private void SavePersistedStateUnsafe()
    {
        try
        {
            var dir = Path.GetDirectoryName(_storePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var state = new DeviceRegistrationStoreState
            {
                Devices = _devices.Select(x => x with { }).ToList(),
                History = _history.Select(x => x with { }).ToList()
            };

            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_storePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist device registrations to {Path}", _storePath);
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

internal sealed class DeviceRegistrationStoreState
{
    public List<DeviceRegistrationEntry> Devices { get; set; } = [];
    public List<DeviceActionHistoryEntry> History { get; set; } = [];
}
