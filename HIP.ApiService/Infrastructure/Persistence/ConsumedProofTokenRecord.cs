namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class ConsumedProofTokenRecord
{
    public string Jti { get; set; } = string.Empty;
    public string IdentityId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset ConsumedAtUtc { get; set; }
}