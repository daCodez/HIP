using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Reporting;

/// <summary>
/// Configuration for HIP privacy hashes.
/// </summary>
/// <param name="SecretKey">Secret HMAC key. Production must supply a strong non-demo value from configuration.</param>
/// <param name="AllowDevelopmentKey">Whether the built-in development key may be used.</param>
public sealed record PrivacyHashingOptions(
    string SecretKey = Sha256PrivacyHashingService.DevelopmentOnlyKey,
    bool AllowDevelopmentKey = true);

/// <summary>
/// Provides stable keyed HMAC-SHA256 hashes for privacy-sensitive HIP identifiers.
/// </summary>
/// <remarks>
/// The class name is retained for compatibility with older tests and callers, but the implementation no longer uses
/// plain SHA-256. The output keeps the legacy `sha256:` prefix so existing browser-plugin and database records remain
/// compatible while the underlying digest becomes keyed.
/// </remarks>
public sealed class Sha256PrivacyHashingService : IPrivacyHashingService
{
    /// <summary>
    /// Development-only fallback key used by tests and local MVP runs.
    /// </summary>
    public const string DevelopmentOnlyKey = "HIP-DEV-ONLY-HMAC-KEY-CHANGE-BEFORE-PRODUCTION";

    private readonly byte[] keyBytes;

    /// <summary>
    /// Creates the keyed privacy hashing service and refuses demo keys when the host disables them.
    /// </summary>
    /// <param name="options">Hashing options supplied by the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when a demo key is used outside local Development.</exception>
    public Sha256PrivacyHashingService(PrivacyHashingOptions? options = null)
    {
        var resolved = options ?? new PrivacyHashingOptions();
        if (!resolved.AllowDevelopmentKey && IsDevelopmentKey(resolved.SecretKey))
        {
            throw new InvalidOperationException("HIP Privacy hashing key requires a non-default HMAC key outside local Development.");
        }

        keyBytes = Encoding.UTF8.GetBytes(resolved.SecretKey);
    }

    /// <inheritdoc />
    public string Hash(string value)
    {
        using var hmac = new HMACSHA256(keyBytes);
        var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(Normalize(value)));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    /// <summary>
    /// Normalizes raw values before hashing so insignificant casing and whitespace changes do not split evidence.
    /// </summary>
    /// <param name="value">Raw privacy-sensitive value.</param>
    /// <returns>Normalized value used as HMAC input.</returns>
    private static string Normalize(string value) => (value ?? string.Empty).Trim().ToLowerInvariant();

    /// <summary>
    /// Checks whether a configured key is the built-in demo key.
    /// </summary>
    /// <param name="key">Configured HMAC key.</param>
    /// <returns>True when the key is missing or the built-in development key.</returns>
    private static bool IsDevelopmentKey(string? key) =>
        string.IsNullOrWhiteSpace(key) ||
        key.Equals(DevelopmentOnlyKey, StringComparison.Ordinal);
}
