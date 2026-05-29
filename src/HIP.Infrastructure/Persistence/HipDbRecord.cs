namespace HIP.Infrastructure.Persistence;

public sealed class HipDbRecord
{
    public string Partition { get; set; } = string.Empty;

    public string Id { get; set; } = string.Empty;

    public string Json { get; set; } = "{}";

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
