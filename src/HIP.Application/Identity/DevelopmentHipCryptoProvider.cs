using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Identity;

/// <summary>
/// Options that allow host projects to prevent accidental production activation of the development crypto provider.
/// </summary>
/// <param name="AllowDevelopmentProvider">True only when the host intentionally permits the development placeholder provider.</param>
public sealed record DevelopmentHipCryptoProviderOptions(bool AllowDevelopmentProvider = true);

/// <summary>
/// Development-only placeholder implementation of HIP signing operations.
/// </summary>
public sealed class DevelopmentHipCryptoProvider : IHipCryptoProvider
{
    public const string Algorithm = "PQ-Placeholder-Development-Only";
    public const bool IsProductionSafe = false;

    /// <summary>
    /// Creates the development-only placeholder crypto provider and refuses host activation when disabled.
    /// </summary>
    /// <param name="options">Host-supplied safety option controlling whether placeholder crypto may activate.</param>
    /// <exception cref="InvalidOperationException">Thrown when a host disables this non-production provider.</exception>
    public DevelopmentHipCryptoProvider(DevelopmentHipCryptoProviderOptions? options = null)
    {
        if (options?.AllowDevelopmentProvider is false)
        {
            throw new InvalidOperationException("DevelopmentHipCryptoProvider is a non-production placeholder and cannot be used outside Development.");
        }
    }

    /// <inheritdoc />
    public HipKeyPair GenerateKeyPair()
    {
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return new HipKeyPair($"dev-public:{secret}", $"dev-private:{secret}", Algorithm, IsProductionSafe);
    }

    /// <inheritdoc />
    public string SignHash(string contentHash, string privateKey)
    {
        var secret = SecretFromKey(privateKey);
        return $"devsig:{Hmac(contentHash, secret)}";
    }

    /// <inheritdoc />
    public bool VerifySignature(string contentHash, string signatureValue, string publicKey)
    {
        var secret = SecretFromKey(publicKey);
        var expected = $"devsig:{Hmac(contentHash, secret)}";
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signatureValue));
    }

    /// <inheritdoc />
    public string HashContent(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    /// <summary>
    /// Computes a deterministic development HMAC for tests without pretending to be production-safe signing.
    /// </summary>
    /// <param name="value">Content hash to sign.</param>
    /// <param name="secret">Development secret extracted from the placeholder key.</param>
    /// <returns>Hex HMAC value.</returns>
    private static string Hmac(string value, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    /// <summary>
    /// Extracts the shared placeholder secret from a dev-public or dev-private key.
    /// </summary>
    /// <param name="key">Placeholder key string.</param>
    /// <returns>Development-only secret component.</returns>
    private static string SecretFromKey(string key)
    {
        var index = key.IndexOf(':', StringComparison.Ordinal);
        return index >= 0 ? key[(index + 1)..] : key;
    }
}
