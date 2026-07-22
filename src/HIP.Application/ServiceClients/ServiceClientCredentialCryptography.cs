using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.ServiceClients;

/// <summary>Generates opaque service-client identifiers and one-time high-entropy secrets.</summary>
public sealed class CryptographicServiceClientCredentialGenerator : IServiceClientCredentialGenerator
{
    /// <inheritdoc />
    public string GenerateClientId() =>
        GenerateOpaqueValue(
            ServiceClientCredentialFormat.ClientIdPrefix,
            ServiceClientCredentialFormat.ClientIdEntropyBytes);

    /// <inheritdoc />
    public ServiceClientSecret GenerateSecret() =>
        new(GenerateOpaqueValue(
            ServiceClientCredentialFormat.SecretPrefix,
            ServiceClientCredentialFormat.SecretEntropyBytes));

    private static string GenerateOpaqueValue(string prefix, int entropyBytes)
    {
        var entropy = RandomNumberGenerator.GetBytes(entropyBytes);
        try
        {
            return prefix + ServiceClientCredentialFormat.EncodeBase64Url(entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }
}

/// <summary>
/// Protects service-client secrets with a client-bound, deliberately slow PBKDF2-HMAC-SHA256 verifier.
/// </summary>
public sealed class Pbkdf2ServiceClientSecretProtector : IServiceClientSecretProtector
{
    private const string AlgorithmMarker = "pbkdf2-sha256-v1";
    private const string IterationMarker = "600000";
    private const string DomainSeparator = "HIP-Service-Credential-v1";
    private const int IterationCount = 600_000;
    private const int SaltBytes = 16;
    private const int DerivedBytes = 32;
    private const int EncodedSaltCharacters = 22;
    private const int EncodedDerivedCharacters = 43;
    private static readonly int ExpectedVerifierCharacters =
        AlgorithmMarker.Length + IterationMarker.Length + EncodedSaltCharacters +
        EncodedDerivedCharacters + 3;

    /// <inheritdoc />
    public string Protect(string clientId, ServiceClientSecret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (!ServiceClientCredentialFormat.IsCanonicalClientId(clientId))
        {
            throw new ArgumentException(
                "The service-client identifier is not in canonical form.",
                nameof(clientId));
        }

        if (!ServiceClientCredentialFormat.IsCanonicalSecret(secret.Reveal()))
        {
            throw new ArgumentException(
                "The service-client secret is not in canonical form.",
                nameof(secret));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var passwordBytes = BuildPasswordBytes(clientId, secret);
        byte[]? derived = null;

        try
        {
            derived = Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                IterationCount,
                HashAlgorithmName.SHA256,
                DerivedBytes);
            return string.Concat(
                AlgorithmMarker,
                "$",
                IterationMarker,
                "$",
                ServiceClientCredentialFormat.EncodeBase64Url(salt),
                "$",
                ServiceClientCredentialFormat.EncodeBase64Url(derived));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
            if (derived is not null)
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        }
    }

    /// <inheritdoc />
    public bool Verify(
        string clientId,
        ServiceClientSecret presentedSecret,
        string credentialVerifier)
    {
        if (presentedSecret is null ||
            !ServiceClientCredentialFormat.IsCanonicalClientId(clientId) ||
            !ServiceClientCredentialFormat.IsCanonicalSecret(presentedSecret.Reveal()) ||
            !TryParseVerifier(credentialVerifier, out var salt, out var expected))
        {
            return false;
        }

        var passwordBytes = BuildPasswordBytes(clientId, presentedSecret);
        byte[]? actual = null;

        try
        {
            actual = Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                IterationCount,
                HashAlgorithmName.SHA256,
                DerivedBytes);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expected);
            if (actual is not null)
            {
                CryptographicOperations.ZeroMemory(actual);
            }
        }
    }

    private static byte[] BuildPasswordBytes(string clientId, ServiceClientSecret secret)
    {
        var secretValue = secret.Reveal();
        var byteCount = Encoding.UTF8.GetByteCount(DomainSeparator) +
                        1 +
                        Encoding.UTF8.GetByteCount(clientId) +
                        1 +
                        Encoding.UTF8.GetByteCount(secretValue);
        var passwordBytes = new byte[byteCount];
        var offset = Encoding.UTF8.GetBytes(DomainSeparator, passwordBytes);
        passwordBytes[offset++] = 0;
        offset += Encoding.UTF8.GetBytes(clientId, passwordBytes.AsSpan(offset));
        passwordBytes[offset++] = 0;
        Encoding.UTF8.GetBytes(secretValue, passwordBytes.AsSpan(offset));
        return passwordBytes;
    }

    private static bool TryParseVerifier(
        string credentialVerifier,
        out byte[] salt,
        out byte[] expected)
    {
        salt = [];
        expected = [];
        if (credentialVerifier is null ||
            credentialVerifier.Length != ExpectedVerifierCharacters)
        {
            return false;
        }

        var parts = credentialVerifier.Split('$', StringSplitOptions.None);
        if (parts.Length != 4 ||
            !string.Equals(parts[0], AlgorithmMarker, StringComparison.Ordinal) ||
            !string.Equals(parts[1], IterationMarker, StringComparison.Ordinal) ||
            !ServiceClientCredentialFormat.TryDecodeExactBase64Url(
                parts[2],
                SaltBytes,
                EncodedSaltCharacters,
                out salt) ||
            !ServiceClientCredentialFormat.TryDecodeExactBase64Url(
                parts[3],
                DerivedBytes,
                EncodedDerivedCharacters,
                out expected))
        {
            CryptographicOperations.ZeroMemory(salt);
            salt = [];
            CryptographicOperations.ZeroMemory(expected);
            expected = [];
            return false;
        }

        return true;
    }
}

/// <summary>
/// Defines the narrow, versioned wire-format validation boundary shared by service-client hosts.
/// Entropy generation and verifier encoding remain internal implementation details.
/// </summary>
public static class ServiceClientCredentialFormat
{
    /// <summary>Gets the exact prefix for version-one service-client identifiers.</summary>
    public const string ClientIdPrefix = "hipc_v1_";

    /// <summary>Gets the exact prefix for version-one service-client secrets.</summary>
    public const string SecretPrefix = "hips_v1_";
    internal const int ClientIdEntropyBytes = 16;
    internal const int SecretEntropyBytes = 32;
    private const int EncodedClientIdCharacters = 22;
    private const int EncodedSecretCharacters = 43;

    internal static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Returns whether a value is an exact canonical version-one service-client identifier.</summary>
    public static bool IsCanonicalClientId(string? clientId) =>
        IsCanonicalPrefixedValue(
            clientId,
            ClientIdPrefix,
            ClientIdEntropyBytes,
            EncodedClientIdCharacters);

    /// <summary>Returns whether a value is an exact canonical version-one service-client secret.</summary>
    public static bool IsCanonicalSecret(string? secret) =>
        IsCanonicalPrefixedValue(
            secret,
            SecretPrefix,
            SecretEntropyBytes,
            EncodedSecretCharacters);

    internal static bool TryDecodeExactBase64Url(
        string value,
        int expectedBytes,
        int expectedCharacters,
        out byte[] decoded)
    {
        decoded = [];
        if (value.Length != expectedCharacters ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            return false;
        }

        try
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            var remainder = base64.Length % 4;
            if (remainder > 0)
            {
                base64 = base64.PadRight(base64.Length + 4 - remainder, '=');
            }

            decoded = Convert.FromBase64String(base64);
            if (decoded.Length == expectedBytes &&
                string.Equals(EncodeBase64Url(decoded), value, StringComparison.Ordinal))
            {
                return true;
            }

            CryptographicOperations.ZeroMemory(decoded);
            decoded = [];
            return false;
        }
        catch (FormatException)
        {
            decoded = [];
            return false;
        }
    }

    private static bool IsCanonicalPrefixedValue(
        string? value,
        string prefix,
        int expectedBytes,
        int expectedCharacters)
    {
        if (value is null ||
            value.Length != prefix.Length + expectedCharacters ||
            !value.StartsWith(prefix, StringComparison.Ordinal) ||
            !TryDecodeExactBase64Url(
                value[prefix.Length..],
                expectedBytes,
                expectedCharacters,
                out var decoded))
        {
            return false;
        }

        CryptographicOperations.ZeroMemory(decoded);
        return true;
    }
}
