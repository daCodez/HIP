namespace HIP.Infrastructure.Persistence;

public sealed class HipDbRecord
{
    public string Partition { get; set; } = string.Empty;

    public string Id { get; set; } = string.Empty;

    public string Json { get; set; } = "{}";

    /// <summary>
    /// Gets or sets the queryable aggregate version used by repositories that require compare-and-swap writes.
    /// Unversioned record partitions keep the default value of zero.
    /// </summary>
    public long AggregateVersion { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
