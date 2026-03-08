namespace HIP.Admin.Models;

public enum SeverityLevel
{
    Critical,
    High,
    Medium,
    Low
}

public enum WorkflowStatus
{
    New,
    Acknowledged,
    Escalated,
    InProgress,
    Resolved,
    Closed,
    Failed,
    Queued
}

public enum StateViewMode
{
    Loading,
    EmptyTrue,
    EmptyFiltered,
    Error,
    Success
}

public enum AlertBannerKind
{
    Info,
    Success,
    Warning,
    Error,
    Critical
}

public sealed class AdminShellConfig
{
    public IReadOnlyCollection<AdminRole> UserRoles { get; init; } = [];
    public IReadOnlyCollection<string> EnabledModules { get; init; } = [];
    public DateTimeOffset? ServerTimestampUtc { get; init; }
    public string? CorrelationId { get; init; }
}
