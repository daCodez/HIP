namespace HIP.Admin.Models;

public sealed class DashboardMetric
{
    public required string Title { get; init; }
    public required string Value { get; init; }
    public required string Delta { get; init; }
    public string Trend { get; init; } = "up";
}

public sealed class ActivityItem
{
    public required DateTime Timestamp { get; init; }
    public required string Actor { get; init; }
    public required string Action { get; init; }
}

public sealed class SecurityCheck
{
    public required string Name { get; init; }
    public required string Status { get; init; }
    public required DateTime LastChecked { get; init; }
}

public sealed class UserDeviceRecord
{
    public required string User { get; init; }
    public required string Email { get; init; }
    public required string Device { get; init; }
    public required string DeviceStatus { get; init; }
    public required DateTime LastSeen { get; init; }
}

public sealed class PolicyRule
{
    public required string RuleId { get; init; }
    public required string Name { get; init; }
    public required string Severity { get; init; }
    public bool Enabled { get; set; }
}

public sealed class AuditLogEntry
{
    public required DateTime Timestamp { get; init; }
    public required string Actor { get; init; }
    public required string Category { get; init; }
    public required string EventType { get; init; }
    public required string Severity { get; init; }
    public required string Result { get; init; }
    public required string Detail { get; init; }
}

public sealed class PolicyPackSummary
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required int EnabledRules { get; init; }
    public required DateTime LastUpdatedUtc { get; init; }
}

public sealed class SystemUsageSummary
{
    public required double CpuPercent { get; init; }
    public required double MemoryUsedGb { get; init; }
    public required double MemoryTotalGb { get; init; }
    public double? DiskPercent { get; init; }
    public required DateTime SampledUtc { get; init; }
}

public sealed class ReputationWatchItem
{
    public required string IdentityId { get; init; }
    public required int Score { get; init; }
    public required int Blocked { get; init; }
    public required int Review { get; init; }
}

public sealed class ReputationInsight
{
    public required string IdentityId { get; init; }
    public required int ReputationScore { get; init; }
    public required int PolicyBlockCount { get; init; }
    public required int PolicyReviewCount { get; init; }
    public required List<(string ReasonCode, int Count)> ReasonBreakdown { get; init; }
}

public sealed class ApiResult<T>
{
    public bool Success { get; init; }
    public T? Data { get; init; }
    public string? Error { get; init; }

    public static ApiResult<T> Ok(T data) => new() { Success = true, Data = data };
    public static ApiResult<T> Fail(string error) => new() { Success = false, Error = error };
}
