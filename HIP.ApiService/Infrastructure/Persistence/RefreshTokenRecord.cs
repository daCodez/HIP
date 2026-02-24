namespace HIP.ApiService.Infrastructure.Persistence;

public sealed class RefreshTokenRecord
{
    public string TokenHash { get; set; } = string.Empty;
    public string IdentityId { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string? DeviceId { get; set; }
    public string KeyId { get; set; } = string.Empty;
    public int Version { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
}