using HIP.Admin.Models;

namespace HIP.Admin.Services;

public sealed class HipAdminApiClient(HttpClient httpClient, AdminContextService context)
{
    public async Task<ApiResult<List<DashboardMetric>>> GetDashboardMetricsAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            var data = await httpClient.GetFromJsonAsync<List<DashboardMetric>>("api/admin/dashboard/metrics", ct);
            return data ?? [];
        }, MockMetrics());

    public async Task<ApiResult<List<ActivityItem>>> GetActivityAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            var data = await httpClient.GetFromJsonAsync<List<ActivityItem>>("api/admin/audit/latest", ct);
            return data ?? [];
        }, MockActivity());

    public Task<ApiResult<List<SecurityCheck>>> GetSecurityChecksAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<SecurityCheck>>("api/admin/security", ct)!, MockSecurity());

    public Task<ApiResult<List<UserDeviceRecord>>> GetUsersDevicesAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<UserDeviceRecord>>("api/admin/users-devices", ct)!, MockUsers());

    public Task<ApiResult<List<PolicyRule>>> GetPolicyRulesAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<PolicyRule>>("api/admin/policy", ct)!, MockRules());

    public Task<ApiResult<List<AuditLogEntry>>> GetAuditLogsAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<AuditLogEntry>>("api/admin/audit", ct)!, MockLogs());

    public async Task<ApiResult<PolicyPackSummary>> GetPolicyPackSummaryAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<PolicyPackSummary>.Ok(MockPolicyPack());
        }

        try
        {
            var data = await httpClient.GetFromJsonAsync<PolicyPackSummary>("api/admin/policy/pack", ct);
            return ApiResult<PolicyPackSummary>.Ok(data ?? MockPolicyPack());
        }
        catch (Exception ex)
        {
            return ApiResult<PolicyPackSummary>.Fail($"Failed to load policy pack. {ex.Message}");
        }
    }

    public async Task<ApiResult<SystemUsageSummary>> GetSystemUsageSummaryAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<SystemUsageSummary>.Ok(MockSystemUsage());
        }

        try
        {
            var data = await httpClient.GetFromJsonAsync<SystemUsageSummary>("api/admin/system/usage", ct);
            return ApiResult<SystemUsageSummary>.Ok(data ?? MockSystemUsage());
        }
        catch (Exception ex)
        {
            return ApiResult<SystemUsageSummary>.Fail($"Failed to load system usage. {ex.Message}");
        }
    }

    private async Task<ApiResult<List<T>>> ExecuteWithMockFallback<T>(Func<Task<List<T>>> apiCall, List<T> mock)
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
                : ApiResult<List<T>>.Fail($"Failed to load data. {ex.Message}");
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
