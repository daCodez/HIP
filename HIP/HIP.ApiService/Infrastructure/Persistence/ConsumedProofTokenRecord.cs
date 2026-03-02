namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class ConsumedProofTokenRecord
{
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string Jti { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string IdentityId { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string Action { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset ExpiresAtUtc { get; set; }
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset ConsumedAtUtc { get; set; }
}