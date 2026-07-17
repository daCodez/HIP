using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Application.Protocol;

#pragma warning disable SYSLIB5006 // .NET 10 marks the FIPS 204 API experimental; runtime support is checked explicitly.

/// <summary>
/// ML-DSA-65 provider backed only by the platform implementation exposed by .NET 10.
/// </summary>
/// <remarks>
/// API and platform-support guidance:
/// https://learn.microsoft.com/dotnet/core/whats-new/dotnet-10/libraries
/// https://learn.microsoft.com/dotnet/api/system.security.cryptography.mldsa?view=net-10.0
/// </remarks>
public sealed class MlDsa65SignatureProvider : IHipSignatureProvider
{
    public const string Algorithm = "ML-DSA-65";
    public const int MaximumContentHashBytes = 1_024;
    public const int MaximumPemCharacters = 32_768;
    public const int MaximumEncodedSignatureCharacters = 4_500;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>Gets whether the current operating-system cryptography stack supports ML-DSA.</summary>
    public static bool IsRuntimeSupported => MLDsa.IsSupported;

    /// <inheritdoc />
    public SignatureProviderCapabilities Capabilities { get; } = new(
        Algorithm,
        SignatureAlgorithmFamily.PostQuantum,
        SignatureProviderOperations.Sign | SignatureProviderOperations.Verify,
        IsAvailable: MLDsa.IsSupported,
        IsDevelopmentOnly: false);

    /// <summary>Generates an ML-DSA-65 key and exports standard PKCS#8 and SubjectPublicKeyInfo PEM.</summary>
    public HipKeyPair GenerateKeyPair()
    {
        EnsureSupported();
        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        return new HipKeyPair(
            key.ExportSubjectPublicKeyInfoPem(),
            key.ExportPkcs8PrivateKeyPem(),
            Algorithm,
            IsProductionSafe: true);
    }

    /// <inheritdoc />
    public string SignHash(string contentHash, string privateKey)
    {
        var data = ValidateContentHash(contentHash);
        ValidatePem(privateKey, nameof(privateKey));
        EnsureSupported();

        using var key = MLDsa.ImportFromPem(privateKey);
        EnsureMlDsa65(key, nameof(privateKey));
        return Base64UrlEncode(key.SignData(data));
    }

    /// <inheritdoc />
    public bool VerifySignature(string contentHash, string signatureValue, string publicKey)
    {
        var data = ValidateContentHash(contentHash);
        ValidatePem(publicKey, nameof(publicKey));
        var signature = Base64UrlDecode(signatureValue);
        EnsureSupported();

        if (signature.Length != MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes)
        {
            throw new ArgumentException(
                $"ML-DSA-65 signatures must contain {MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes} bytes.",
                nameof(signatureValue));
        }

        using var key = MLDsa.ImportFromPem(publicKey);
        EnsureMlDsa65(key, nameof(publicKey));
        return key.VerifyData(data, signature);
    }

    private static byte[] ValidateContentHash(string contentHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentHash);
        byte[] data;
        try
        {
            data = StrictUtf8.GetBytes(contentHash);
        }
        catch (EncoderFallbackException exception)
        {
            throw new ArgumentException("The content hash must contain valid Unicode data.", nameof(contentHash), exception);
        }

        if (data.Length > MaximumContentHashBytes)
        {
            throw new ArgumentException(
                $"The content hash cannot exceed {MaximumContentHashBytes} UTF-8 bytes.",
                nameof(contentHash));
        }

        return data;
    }

    private static void ValidatePem(string pem, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem, parameterName);
        if (pem.Length > MaximumPemCharacters)
        {
            throw new ArgumentException(
                $"ML-DSA key material cannot exceed {MaximumPemCharacters} characters.",
                parameterName);
        }
    }

    private static byte[] Base64UrlDecode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumEncodedSignatureCharacters)
        {
            throw new FormatException(
                $"ML-DSA signature encoding cannot exceed {MaximumEncodedSignatureCharacters} characters.");
        }

        foreach (var item in value)
        {
            if (!char.IsAsciiLetterOrDigit(item) && item is not '-' and not '_')
            {
                throw new FormatException("ML-DSA signature is not canonical base64url.");
            }
        }

        var base64 = value.Replace('-', '+').Replace('_', '/');
        var remainder = base64.Length % 4;
        if (remainder == 1)
        {
            throw new FormatException("ML-DSA signature is not valid base64url.");
        }

        if (remainder > 0)
        {
            base64 = base64.PadRight(base64.Length + 4 - remainder, '=');
        }

        return Convert.FromBase64String(base64);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void EnsureSupported()
    {
        if (!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ML-DSA-65 is unavailable because the current operating-system cryptography stack does not support ML-DSA.");
        }
    }

    private static void EnsureMlDsa65(MLDsa key, string parameterName)
    {
        if (!key.Algorithm.Equals(MLDsaAlgorithm.MLDsa65))
        {
            throw new ArgumentException("The supplied key is not an ML-DSA-65 key.", parameterName);
        }
    }
}

#pragma warning restore SYSLIB5006
