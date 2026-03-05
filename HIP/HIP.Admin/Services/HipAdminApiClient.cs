using System.Text.Json;
using HIP.Admin.Models;

namespace HIP.Admin.Services;

public sealed class HipAdminApiClient(HttpClient httpClient, AdminContextService context)
{
    public async Task<ApiResult<List<DashboardMetric>>> GetDashboardMetricsAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            var data = await httpClient.GetFromJsonAsync<List<DashboardMetric>>("api/admin/dashboard/metrics", ct);
            return data ?? [];
        }, MockMetrics(), "api/admin/dashboard/metrics");

    public async Task<ApiResult<List<ActivityItem>>> GetActivityAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            var data = await httpClient.GetFromJsonAsync<List<ActivityItem>>("api/admin/audit/latest", ct);
            return data ?? [];
        }, MockActivity(), "api/admin/audit/latest");

    public Task<ApiResult<List<SecurityCheck>>> GetSecurityChecksAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<SecurityCheck>>("api/admin/security", ct)!, MockSecurity(), "api/admin/security");

    public Task<ApiResult<List<UserDeviceRecord>>> GetUsersDevicesAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<UserDeviceRecord>>("api/admin/users-devices", ct)!, MockUsers(), "api/admin/users-devices");

    public Task<ApiResult<List<PolicyRule>>> GetPolicyRulesAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<PolicyRule>>("api/admin/policy", ct)!, MockRules(), "api/admin/policy");

    public async Task<ApiResult<List<AuditLogEntry>>> GetAuditLogsAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<AuditLogEntry>>.Ok(MockLogs());
        }

        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/admin/audit?take=250", ct);
            var root = doc?.RootElement;
            if (root is null || root.Value.ValueKind != JsonValueKind.Array)
            {
                return ApiResult<List<AuditLogEntry>>.Ok(MockLogs());
            }

            var mapped = new List<AuditLogEntry>();
            foreach (var e in root.Value.EnumerateArray())
            {
                var created = e.TryGetProperty("createdAtUtc", out var createdEl) && createdEl.ValueKind == JsonValueKind.String
                    && DateTime.TryParse(createdEl.GetString(), out var dt)
                    ? dt
                    : DateTime.UtcNow;

                var subject = e.TryGetProperty("subject", out var subjectEl) ? subjectEl.GetString() ?? "unknown" : "unknown";
                var eventType = e.TryGetProperty("eventType", out var eventEl) ? eventEl.GetString() ?? "unknown" : "unknown";
                var category = e.TryGetProperty("category", out var catEl) ? catEl.GetString() ?? "general" : "general";
                var outcome = e.TryGetProperty("outcome", out var outEl) ? outEl.GetString() ?? "unknown" : "unknown";
                var reason = e.TryGetProperty("reasonCode", out var reasonEl) ? reasonEl.GetString() ?? string.Empty : string.Empty;
                var detail = e.TryGetProperty("detail", out var detailEl) ? detailEl.GetString() ?? string.Empty : string.Empty;

                var severity = outcome.Equals("success", StringComparison.OrdinalIgnoreCase)
                    ? "Info"
                    : outcome.Equals("review", StringComparison.OrdinalIgnoreCase)
                        ? "Warning"
                        : "Critical";

                mapped.Add(new AuditLogEntry
                {
                    Timestamp = created,
                    Actor = subject,
                    EventType = eventType,
                    Category = category,
                    Severity = severity,
                    Result = outcome,
                    Detail = string.IsNullOrWhiteSpace(reason) ? detail : $"{detail} ({reason})"
                });
            }

            return ApiResult<List<AuditLogEntry>>.Ok(mapped);
        }
        catch (Exception ex)
        {
            return ApiResult<List<AuditLogEntry>>.Fail($"Failed to load audit logs. {ex.Message}");
        }
    }

    public async Task<ApiResult<PolicyPackSummary>> GetPolicyPackSummaryAsync(CancellationToken ct = default)
    {
        // First real endpoint wiring: plugin metadata route from API service.
        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/plugins/policy/current", ct);
            var root = doc?.RootElement;
            if (root is not null && root.Value.TryGetProperty("policyVersion", out var policyVersion))
            {
                var source = root.Value.TryGetProperty("source", out var sourceEl) ? sourceEl.GetString() ?? "default" : "default";
                var summary = new PolicyPackSummary
                {
                    Name = source.Equals("strict", StringComparison.OrdinalIgnoreCase)
                        ? "HIP Strict Policy Pack"
                        : "HIP Default Policy Pack",
                    Version = policyVersion.GetString() ?? "unknown",
                    EnabledRules = root.Value.TryGetProperty("requiredScores", out var scores) ? scores.EnumerateObject().Count() : 0,
                    LastUpdatedUtc = DateTime.UtcNow
                };

                return ApiResult<PolicyPackSummary>.Ok(summary);
            }
        }
        catch
        {
            // fall through to mock fallback
        }

        return ApiResult<PolicyPackSummary>.Ok(MockPolicyPack());
    }

    public async Task<ApiResult<SystemUsageSummary>> GetSystemUsageSummaryAsync(CancellationToken ct = default)
    {
        // First real endpoint wiring: system metrics plugin route.
        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/plugins/system-metrics?take=1", ct);
            var root = doc?.RootElement;
            if (root is not null && root.Value.TryGetProperty("samples", out var samples) && samples.ValueKind == JsonValueKind.Array)
            {
                var first = samples.EnumerateArray().FirstOrDefault();
                if (first.ValueKind == JsonValueKind.Object)
                {
                    var cpu = first.TryGetProperty("cpu", out var cpuEl) ? cpuEl.GetDouble() : 0d;
                    var memPercent = first.TryGetProperty("memory", out var memEl) ? memEl.GetDouble() : 0d;
                    const double assumedTotalGb = 8.0;
                    var used = Math.Round((memPercent / 100d) * assumedTotalGb, 2);

                    var usage = new SystemUsageSummary
                    {
                        CpuPercent = cpu,
                        MemoryUsedGb = used,
                        MemoryTotalGb = assumedTotalGb,
                        DiskPercent = null,
                        SampledUtc = DateTime.UtcNow
                    };

                    return ApiResult<SystemUsageSummary>.Ok(usage);
                }
            }
        }
        catch
        {
            // fall through to mock fallback
        }

        return ApiResult<SystemUsageSummary>.Ok(MockSystemUsage());
    }

    private async Task<ApiResult<List<T>>> ExecuteWithMockFallback<T>(Func<Task<List<T>>> apiCall, List<T> mock, string endpoint)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<T>>.Ok(mock);
        }

        try
        {
            var data = await apiCall();
            return ApiResult<List<T>>.Ok(data ?? mock);
        }
        catch (Exception ex)
        {
            return context.MockModeEnabled
                ? ApiResult<List<T>>.Ok(mock)
                : ApiResult<List<T>>.Fail($"Failed to load data from '{endpoint}'. {ex.Message}");
        }
    }

    private static List<DashboardMetric> MockMetrics() =>
    [
        new() { Title = "Total Users", Value = "12,482", Delta = "+4.8%", Trend = "up" },
        new() { Title = "Risk Alerts", Value = "38", Delta = "-2.1%", Trend = "down" },
        new() { Title = "Policy Match", Value = "97.4%", Delta = "+0.3%", Trend = "up" },
        new() { Title = "Active Sessions", Value = "1,284", Delta = "+8.2%", Trend = "up" }
    ];

    private static List<ActivityItem> MockActivity() =>
    [
        new() { Timestamp = DateTime.UtcNow.AddMinutes(-12), Actor = "security.bot", Action = "Policy test completed" },
        new() { Timestamp = DateTime.UtcNow.AddMinutes(-25), Actor = "analyst@hip.local", Action = "Reviewed suspicious cluster" },
        new() { Timestamp = DateTime.UtcNow.AddHours(-1), Actor = "admin@hip.local", Action = "Updated MFA baseline" }
    ];

    private static List<SecurityCheck> MockSecurity() =>
    [
        new() { Name = "MFA Enforced", Status = "Healthy", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Token Hygiene", Status = "Warning", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Geo Velocity", Status = "Healthy", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Root Access Monitoring", Status = "Critical", LastChecked = DateTime.UtcNow.AddMinutes(-1) }
    ];

    private static List<UserDeviceRecord> MockUsers() =>
    [
        new() { User = "Nora Kim", Email = "nora@hip.local", Device = "MacBook Pro", DeviceStatus = "Compliant", LastSeen = DateTime.UtcNow.AddMinutes(-5) },
        new() { User = "Derek Holt", Email = "derek@hip.local", Device = "Pixel 9", DeviceStatus = "Pending", LastSeen = DateTime.UtcNow.AddMinutes(-18) },
        new() { User = "Mina Rao", Email = "mina@hip.local", Device = "Windows 11", DeviceStatus = "Blocked", LastSeen = DateTime.UtcNow.AddHours(-3) }
    ];

    private static List<PolicyRule> MockRules() =>
    [
        new() { RuleId = "POL-001", Name = "MFA Required for Admin Actions", Severity = "Critical", Enabled = true },
        new() { RuleId = "POL-017", Name = "Block impossible travel login", Severity = "High", Enabled = true },
        new() { RuleId = "POL-033", Name = "Session renewal every 12h", Severity = "Medium", Enabled = false }
    ];

    private static PolicyPackSummary MockPolicyPack() => new()
    {
        Name = "HIP Core Policy Pack",
        Version = "2026.03.1",
        EnabledRules = 42,
        LastUpdatedUtc = DateTime.UtcNow.AddHours(-6)
    };

    private static SystemUsageSummary MockSystemUsage() => new()
    {
        CpuPercent = 27.4,
        MemoryUsedGb = 2.9,
        MemoryTotalGb = 7.8,
        DiskPercent = 61.0,
        SampledUtc = DateTime.UtcNow.AddSeconds(-20)
    };

    private static List<AuditLogEntry> MockLogs() => Enumerable.Range(1, 48)
        .Select(i => new AuditLogEntry
        {
            Timestamp = DateTime.UtcNow.AddMinutes(i * -9),
            Actor = i % 2 == 0 ? "admin@hip.local" : "support@hip.local",
            Category = i % 3 == 0 ? "Policy" : "Session",
            EventType = i % 4 == 0 ? "PolicyTest" : i % 3 == 0 ? "TokenAction" : "LoginCheck",
            Severity = i % 9 == 0 ? "Critical" : i % 4 == 0 ? "Warning" : "Info",
            Result = i % 5 == 0 ? "Denied" : "Success",
            Detail = $"Action #{i} processed"
        })
        .ToList();
}
