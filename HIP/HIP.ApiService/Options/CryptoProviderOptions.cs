namespace HIP.ApiService;

/// <summary>
/// Configuration options controlling HIP crypto provider behavior.
/// </summary>
public sealed class CryptoProviderOptions
{
    /// <summary>
    /// Configuration section key used for binding crypto options.
    /// </summary>
    public const string SectionName = "HIP:Crypto";

    /// <summary>
    /// Active crypto provider identifier (for example: Placeholder, ECDsa).
    /// </summary>
    public string Provider { get; init; } = "Placeholder";

    /// <summary>
    /// Optional filesystem path containing public-key material.
    /// </summary>
    public string? PublicKeyStorePath { get; init; }

    /// <summary>
    /// Optional filesystem path containing private-key material.
    /// </summary>
    public string? PrivateKeyStorePath { get; init; }
}
