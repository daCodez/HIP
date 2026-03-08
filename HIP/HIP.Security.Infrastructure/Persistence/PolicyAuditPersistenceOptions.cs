namespace HIP.Security.Infrastructure.Persistence;

public sealed class PolicyAuditPersistenceOptions
{
    public const string SectionName = "HipSecurity:AuditPersistence";

    /// <summary>
    /// Persistence provider for policy audit events. Supported values: InMemory, Sqlite.
    /// </summary>
    public string Provider { get; set; } = "InMemory";

    /// <summary>
    /// Sqlite connection string used when Provider=Sqlite.
    /// </summary>
    public string ConnectionString { get; set; } = "Data Source=hip-security-audit.db";
}
