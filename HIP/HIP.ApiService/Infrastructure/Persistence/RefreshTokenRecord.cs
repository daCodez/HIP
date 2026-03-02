namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class RefreshTokenRecord
{
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string IdentityId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string Audience { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string? DeviceId { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int Version { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset ExpiresAtUtc { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset CreatedAtUtc { get; set; }
}