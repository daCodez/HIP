namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class ReplayNonceRecord
{
    public string MessageId { get; set; } = string.Empty;
    public string IdentityId { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
}