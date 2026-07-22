using System.Security.Cryptography;
using HIP.Application.Protocol;

namespace HIP.Application.Devices;

/// <summary>
/// Represents validated, canonical public verification material for a registered HIP device.
/// </summary>
/// <param name="Algorithm">Exact device-proof algorithm identifier.</param>
/// <param name="PublicKey">Unpadded base64url canonical SubjectPublicKeyInfo bytes.</param>
/// <param name="PublicKeyFingerprint">Algorithm-bound HIP fingerprint.</param>
public sealed record ValidatedDevicePublicKey(
    string Algorithm,
    string PublicKey,
    string PublicKeyFingerprint);

/// <summary>
/// Validates WebCrypto-compatible P-256 public keys and verifies their fixed-width ECDSA proofs.
/// </summary>
/// <remarks>
/// HIP device proof establishes possession of a private key only. It does not establish that a device is safe,
/// reputable, uncompromised, or controlled by the expected person after registration.
/// </remarks>
public sealed class Es256DeviceProofVerifier
{
    public const string Algorithm = "ECDSA-P256-SHA256";
    public const int MaximumEncodedPublicKeyCharacters = 512;
    public const int MaximumDecodedPublicKeyBytes = 256;
    public const int MaximumSigningPayloadBytes = 2_048;
    public const int EncodedSignatureCharacters = 86;
    public const int SignatureBytes = 64;

    private const string P256CurveOid = "1.2.840.10045.3.1.7";

    /// <summary>
    /// Imports, curve-checks, and canonicalizes one public-only P-256 SubjectPublicKeyInfo value.
    /// </summary>
    public ValidatedDevicePublicKey ValidatePublicKey(string algorithm, string publicKey)
    {
        if (!string.Equals(algorithm, Algorithm, StringComparison.Ordinal))
        {
            throw new NotSupportedException("The requested HIP device-proof algorithm is not supported.");
        }

        if (string.IsNullOrWhiteSpace(publicKey) || publicKey.Length > MaximumEncodedPublicKeyCharacters)
        {
            throw new ArgumentException("The device public key is missing or exceeds the supported size.", nameof(publicKey));
        }

        if (!DeviceRegistrationEncoding.TryDecodeBase64Url(
                publicKey,
                MaximumDecodedPublicKeyBytes,
                out var encodedKey))
        {
            throw new ArgumentException(
                "The device public key must be canonical unpadded base64url.",
                nameof(publicKey));
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(encodedKey, out var bytesRead);
            if (bytesRead != encodedKey.Length)
            {
                throw new ArgumentException("The device public key contains trailing data.", nameof(publicKey));
            }

            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (!string.Equals(parameters.Curve.Oid.Value, P256CurveOid, StringComparison.Ordinal) ||
                parameters.Q.X is not { Length: 32 } ||
                parameters.Q.Y is not { Length: 32 })
            {
                throw new ArgumentException("The device public key must use the P-256 curve.", nameof(publicKey));
            }

            var canonicalBytes = key.ExportSubjectPublicKeyInfo();
            if (!encodedKey.AsSpan().SequenceEqual(canonicalBytes))
            {
                throw new ArgumentException(
                    "The device public key must use canonical SubjectPublicKeyInfo encoding.",
                    nameof(publicKey));
            }

            return new ValidatedDevicePublicKey(
                Algorithm,
                DeviceRegistrationEncoding.Base64UrlEncode(canonicalBytes),
                HipPublicKeyFingerprint.ComputeSha256(Algorithm, canonicalBytes));
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                "The device public key is not a valid P-256 SubjectPublicKeyInfo value.",
                nameof(publicKey),
                exception);
        }
    }

    /// <summary>
    /// Verifies an exact bounded signing input using WebCrypto's 64-byte IEEE-P1363 signature format.
    /// </summary>
    public bool VerifySignature(
        ValidatedDevicePublicKey publicKey,
        ReadOnlySpan<byte> signingInput,
        string signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (signingInput.IsEmpty || signingInput.Length > MaximumSigningPayloadBytes ||
            signature is null || signature.Length != EncodedSignatureCharacters ||
            !DeviceRegistrationEncoding.TryDecodeBase64Url(signature, SignatureBytes, out var signatureBytes) ||
            signatureBytes.Length != SignatureBytes)
        {
            return false;
        }

        try
        {
            var validated = ValidatePublicKey(publicKey.Algorithm, publicKey.PublicKey);
            if (!string.Equals(
                    validated.PublicKeyFingerprint,
                    publicKey.PublicKeyFingerprint,
                    StringComparison.Ordinal))
            {
                return false;
            }

            using var key = ECDsa.Create();
            var encodedKey = DeviceRegistrationEncoding.DecodeCanonicalBase64Url(
                validated.PublicKey,
                MaximumDecodedPublicKeyBytes,
                "The persisted device public key is invalid.");
            key.ImportSubjectPublicKeyInfo(encodedKey, out var bytesRead);
            if (bytesRead != encodedKey.Length)
            {
                return false;
            }

            var digest = SHA256.HashData(signingInput);
            return key.VerifyHash(
                digest,
                signatureBytes,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}

/// <summary>Strict base64url helpers shared by the bounded device-registration workflow.</summary>
internal static class DeviceRegistrationEncoding
{
    public static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] DecodeCanonicalBase64Url(
        string value,
        int maximumDecodedBytes,
        string errorMessage)
    {
        if (!TryDecodeBase64Url(value, maximumDecodedBytes, out var decoded))
        {
            throw new ArgumentException(errorMessage, nameof(value));
        }

        return decoded;
    }

    public static bool TryDecodeBase64Url(string value, int maximumDecodedBytes, out byte[] decoded)
    {
        decoded = [];
        if (string.IsNullOrEmpty(value) || maximumDecodedBytes <= 0 || value.Length % 4 == 1)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')
            {
                return false;
            }
        }

        var maximumEncodedCharacters = ((maximumDecodedBytes + 2) / 3) * 4;
        if (value.Length > maximumEncodedCharacters)
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
            return decoded.Length <= maximumDecodedBytes &&
                   string.Equals(Base64UrlEncode(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            decoded = [];
            return false;
        }
    }
}
