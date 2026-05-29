using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Identity;

public sealed class DevelopmentHipCryptoProvider : IHipCryptoProvider
{
    public const string Algorithm = "PQ-Placeholder-Development-Only";
    public const bool IsProductionSafe = false;

    public HipKeyPair GenerateKeyPair()
    {
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return new HipKeyPair($"dev-public:{secret}", $"dev-private:{secret}", Algorithm, IsProductionSafe);
    }

    public string SignHash(string contentHash, string privateKey)
    {
        var secret = SecretFromKey(privateKey);
        return $"devsig:{Hmac(contentHash, secret)}";
    }

    public bool VerifySignature(string contentHash, string signatureValue, string publicKey)
    {
        var secret = SecretFromKey(publicKey);
        var expected = $"devsig:{Hmac(contentHash, secret)}";
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signatureValue));
    }

    public string HashContent(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    private static string Hmac(string value, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static string SecretFromKey(string key)
    {
        var index = key.IndexOf(':', StringComparison.Ordinal);
        return index >= 0 ? key[(index + 1)..] : key;
    }
}
