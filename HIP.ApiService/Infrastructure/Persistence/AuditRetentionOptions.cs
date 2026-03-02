namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Retention and export controls for audit events.
/// </summary>
public sealed class AuditRetentionOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "HIP:Audit";

    /// <summary>Days to retain audit events.</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>Maximum number of rows allowed for export.</summary>
    public int ExportMaxRows { get; set; } = 2000;
}
