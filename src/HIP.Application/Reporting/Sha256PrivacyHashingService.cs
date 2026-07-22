using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Reporting;

/// <summary>
/// Configuration for HIP privacy hashes.
/// </summary>
/// <param name="SecretKey">Secret HMAC key. Production must supply a strong non-demo value from configuration.</param>
/// <param name="AllowDevelopmentKey">Whether the built-in development key may be used.</param>
/// <param name="LegacyKeys">Previous privacy HMAC keys retained only for explicitly supported rotation lookups.</param>
public sealed record PrivacyHashingOptions(
    string SecretKey = Sha256PrivacyHashingService.DevelopmentOnlyKey,
    bool AllowDevelopmentKey = true,
    IReadOnlyCollection<string>? LegacyKeys = null)
{
    /// <summary>Maximum explicitly configured former privacy HMAC keys.</summary>
    public const int MaximumLegacyKeyCount = 8;

    /// <summary>Maximum current-plus-legacy privacy HMAC keys.</summary>
    public const int MaximumKeyCount = MaximumLegacyKeyCount + 1;

    /// <summary>
    /// Preserves the original version-one constructor contract for already compiled callers while
    /// selecting an empty legacy key ring.
    /// </summary>
    public PrivacyHashingOptions(string SecretKey, bool AllowDevelopmentKey)
        : this(SecretKey, AllowDevelopmentKey, LegacyKeys: null)
    {
    }
}

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

    private readonly IReadOnlyList<byte[]> keyBytes;

    /// <summary>
    /// Creates the keyed privacy hashing service and refuses demo keys when the host disables them.
    /// </summary>
    /// <param name="options">Hashing options supplied by the host.</param>
    /// <exception cref="InvalidOperationException">Thrown when a demo key is used outside local Development.</exception>
    public Sha256PrivacyHashingService(PrivacyHashingOptions? options = null)
    {
        var resolved = options ?? new PrivacyHashingOptions();
        var legacyKeys = resolved.LegacyKeys?.ToArray() ?? [];
        if (legacyKeys.Length > PrivacyHashingOptions.MaximumLegacyKeyCount)
        {
            throw new InvalidOperationException(
                $"HIP privacy hashing supports at most {PrivacyHashingOptions.MaximumLegacyKeyCount} legacy keys.");
        }

        var uniqueKeys = new HashSet<string>(StringComparer.Ordinal);
        var resolvedKeys = new List<byte[]>(PrivacyHashingOptions.MaximumKeyCount);
        AddKey(resolved.SecretKey, resolved.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        foreach (var legacyKey in legacyKeys)
        {
            AddKey(legacyKey, resolved.AllowDevelopmentKey, uniqueKeys, resolvedKeys);
        }

        keyBytes = Array.AsReadOnly(resolvedKeys.ToArray());
    }

    /// <inheritdoc />
    public string Hash(string value) => Hash(value, keyBytes[0]);

    /// <inheritdoc />
    public IReadOnlyList<string> HashCandidates(string value) =>
        Array.AsReadOnly(keyBytes.Select(candidate => Hash(value, candidate)).ToArray());

    private static string Hash(string value, byte[] candidateKey)
    {
        var bytes = HMACSHA256.HashData(
            candidateKey,
            Encoding.UTF8.GetBytes(Normalize(value)));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    private static void AddKey(
        string? candidate,
        bool allowDevelopmentKey,
        ISet<string> uniqueKeys,
        ICollection<byte[]> resolvedKeys)
    {
        if (string.IsNullOrWhiteSpace(candidate) ||
            (!allowDevelopmentKey && IsDevelopmentKey(candidate)))
        {
            throw new InvalidOperationException(
                "HIP Privacy hashing key requires configured non-development key material.");
        }

        if (uniqueKeys.Add(candidate))
        {
            resolvedKeys.Add(Encoding.UTF8.GetBytes(candidate));
        }
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
        string.Equals(key, DevelopmentOnlyKey, StringComparison.Ordinal);
}
