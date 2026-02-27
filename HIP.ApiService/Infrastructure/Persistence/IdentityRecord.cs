namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class IdentityRecord
{
    public string Id { get; set; } = string.Empty;
    public string PublicKeyRef { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; }
}
