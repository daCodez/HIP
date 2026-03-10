using System.Text.Json;

namespace HIP.ApiService.Features.Admin;

internal sealed class AgentEnrollmentStore
{
    private readonly object _gate = new();
    private readonly List<AgentEnrollmentRecord> _records = [];
    private readonly List<EnrollmentTokenRecord> _tokens = [];
    private readonly string _storePath;
    private readonly ILogger<AgentEnrollmentStore> _logger;

    public AgentEnrollmentStore(IConfiguration configuration, IWebHostEnvironment env, ILogger<AgentEnrollmentStore> logger)
    {
        _logger = logger;
        _storePath = configuration["HIP:AgentEnrollment:StorePath"]
            ?? Path.Combine(env.ContentRootPath, "SecurityEvents", "agent-enrollments.store.json");

        TryLoadPersistedState();
    }

    public EnrollmentTokenRecord IssueEnrollmentToken(string issuedBy, TimeSpan ttl)
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            var token = $"enr_{Convert.ToHexString(Guid.NewGuid().ToByteArray())}";
            var record = new EnrollmentTokenRecord(
                Token: token,
                IssuedBy: string.IsNullOrWhiteSpace(issuedBy) ? "admin" : issuedBy,
                IssuedAtUtc: now,
                ExpiresAtUtc: now.Add(ttl),
                UsedAtUtc: null,
                UsedByDeviceId: null);

            _tokens.Add(record);
            SavePersistedStateUnsafe();
            return record;
        }
    }

    public bool TryConsumeEnrollmentToken(string token, string deviceId, out EnrollmentTokenConsumeResult result)
    {
        lock (_gate)
        {
            var idx = _tokens.FindIndex(x => x.Token.Equals(token, StringComparison.Ordinal));
            if (idx < 0)
            {
                result = EnrollmentTokenConsumeResult.Invalid;
                return false;
            }

            var rec = _tokens[idx];
            if (rec.UsedAtUtc is not null)
            {
                result = EnrollmentTokenConsumeResult.AlreadyUsed;
                return false;
            }

            if (DateTime.UtcNow > rec.ExpiresAtUtc)
            {
                result = EnrollmentTokenConsumeResult.Expired;
                return false;
            }

            _tokens[idx] = rec with { UsedAtUtc = DateTime.UtcNow, UsedByDeviceId = deviceId };
            SavePersistedStateUnsafe();
            result = EnrollmentTokenConsumeResult.Consumed;
            return true;
        }
    }

    public AgentEnrollmentRecord Register(string deviceId, string deviceName, string enrollmentToken)
    {
        lock (_gate)
        {
            var assignedIdentity = $"agent:{deviceId.ToLowerInvariant()}";
            var bootstrapToken = $"boot_{Convert.ToHexString(Guid.NewGuid().ToByteArray())}";
            var issuedAtUtc = DateTime.UtcNow;

            var existingIndex = _records.FindIndex(x => x.DeviceId.Equals(deviceId, StringComparison.OrdinalIgnoreCase));
            var record = new AgentEnrollmentRecord(deviceId, deviceName, assignedIdentity, bootstrapToken, enrollmentToken, issuedAtUtc, issuedAtUtc);

            if (existingIndex >= 0)
            {
                _records[existingIndex] = record;
            }
            else
            {
                _records.Add(record);
            }

            SavePersistedStateUnsafe();
            return record;
        }
    }

    public bool TryFindByBootstrapToken(string token, out AgentEnrollmentRecord? record)
    {
        lock (_gate)
        {
            record = _records.FirstOrDefault(x => x.BootstrapToken.Equals(token, StringComparison.Ordinal));
            return record is not null;
        }
    }

    public AgentEnrollmentRecord? Heartbeat(string deviceId)
    {
        lock (_gate)
        {
            var idx = _records.FindIndex(x => x.DeviceId.Equals(deviceId, StringComparison.OrdinalIgnoreCase));
            if (idx < 0)
            {
                return null;
            }

            var updated = _records[idx] with { LastSeenUtc = DateTime.UtcNow };
            _records[idx] = updated;
            SavePersistedStateUnsafe();
            return updated;
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
            var state = JsonSerializer.Deserialize<AgentEnrollmentStoreState>(json);
            if (state is null)
            {
                return false;
            }

            _records.Clear();
            _records.AddRange(state.Enrollments ?? []);
            _tokens.Clear();
            _tokens.AddRange(state.EnrollmentTokens ?? []);
            _logger.LogInformation("Loaded persisted agent enrollments from {Path}: records={Count}, tokens={TokenCount}", _storePath, _records.Count, _tokens.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load persisted agent enrollments from {Path}.", _storePath);
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

            var state = new AgentEnrollmentStoreState
            {
                Enrollments = _records.Select(x => x with { }).ToList(),
                EnrollmentTokens = _tokens.Select(x => x with { }).ToList()
            };

            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_storePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist agent enrollments to {Path}", _storePath);
        }
    }
}

internal enum EnrollmentTokenConsumeResult
{
    Consumed,
    Invalid,
    Expired,
    AlreadyUsed
}

internal sealed record EnrollmentTokenRecord(
    string Token,
    string IssuedBy,
    DateTime IssuedAtUtc,
    DateTime ExpiresAtUtc,
    DateTime? UsedAtUtc,
    string? UsedByDeviceId);

internal sealed record AgentEnrollmentRecord(
    string DeviceId,
    string DeviceName,
    string AssignedIdentity,
    string BootstrapToken,
    string EnrollmentToken,
    DateTime IssuedAtUtc,
    DateTime LastSeenUtc);

internal sealed class AgentEnrollmentStoreState
{
    public List<AgentEnrollmentRecord> Enrollments { get; set; } = [];
    public List<EnrollmentTokenRecord> EnrollmentTokens { get; set; } = [];
}
