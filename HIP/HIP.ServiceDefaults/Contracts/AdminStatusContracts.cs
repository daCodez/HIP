namespace HIP.Shared.Contracts;

/// <summary>
/// Canonical severity levels for HIP admin UI and backend workflows.
/// Severity communicates impact/urgency and is intentionally separate from workflow status.
/// </summary>
public enum SeverityLevel
{
    Info = 0,
    Warning = 1,
    High = 2,
    Critical = 3
}

/// <summary>
/// Canonical workflow status values for HIP admin entities.
/// Workflow status communicates lifecycle state and is intentionally separate from severity.
/// </summary>
public enum WorkflowStatus
{
    Pending = 0,
    InProgress = 1,
    Resolved = 2,
    Cancelled = 3,
    Failed = 4
}
