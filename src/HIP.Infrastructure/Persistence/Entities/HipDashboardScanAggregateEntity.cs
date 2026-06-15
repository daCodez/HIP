namespace HIP.Infrastructure.Persistence.Entities;

/// <summary>
/// Typed dashboard projection row for scan counters.
/// </summary>
/// <remarks>
/// HIP keeps this as a pre-aggregated read model so admin dashboard refreshes do not repeatedly scan the full
/// browser scan history. The current MVP uses one row named <c>current</c>; future deployments can shard this by
/// tenant, region, or time bucket without changing dashboard callers.
/// </remarks>
public sealed class HipDashboardScanAggregateEntity
{
    /// <summary>
    /// Gets or sets the aggregate row identifier.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the total number of projected scans.
    /// </summary>
    public int TotalScans { get; set; }

    /// <summary>
    /// Gets or sets the number of scans received today in UTC.
    /// </summary>
    public int ScansToday { get; set; }

    /// <summary>
    /// Gets or sets the trusted scan count.
    /// </summary>
    public int Trusted { get; set; }

    /// <summary>
    /// Gets or sets the mostly trusted scan count.
    /// </summary>
    public int MostlyTrusted { get; set; }

    /// <summary>
    /// Gets or sets the limited trust data scan count.
    /// </summary>
    public int LimitedTrustData { get; set; }

    /// <summary>
    /// Gets or sets the unknown scan count.
    /// </summary>
    public int Unknown { get; set; }

    /// <summary>
    /// Gets or sets the suspicious scan count.
    /// </summary>
    public int Suspicious { get; set; }

    /// <summary>
    /// Gets or sets the high-risk scan count.
    /// </summary>
    public int HighRisk { get; set; }

    /// <summary>
    /// Gets or sets the dangerous scan count.
    /// </summary>
    public int Dangerous { get; set; }

    /// <summary>
    /// Gets or sets the UTC timestamp when the projection was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
