namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class IdentityRecord
{
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public string PublicKeyRef { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public DateTimeOffset CreatedAtUtc { get; set; }
}
