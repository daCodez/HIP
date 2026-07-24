using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Identity;

/// <summary>Creates and compares high-entropy, URL-safe domain verification challenges.</summary>
internal static class DomainVerificationChallengeToken
{
    private const int EntropyBytes = 32;

    /// <summary>Generates a 256-bit random challenge encoded without padding.</summary>
    /// <returns>A URL-safe challenge suitable for DNS and HTTPS proof methods.</returns>
    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(EntropyBytes);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>Compares challenges without data-dependent content comparison.</summary>
    /// <param name="expected">Active challenge held by HIP.</param>
    /// <param name="supplied">Untrusted challenge supplied for verification.</param>
    /// <returns>True only when the complete challenge values match.</returns>
    public static bool Matches(string expected, string supplied)
    {
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(supplied) ||
            expected.Length > 256 || supplied.Length > 256)
        {
            return false;
        }

        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(supplied));
        return CryptographicOperations.FixedTimeEquals(expectedHash, suppliedHash);
    }
}
