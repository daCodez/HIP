using System.Text.Json.Serialization;
namespace HIP.Domain.Protocol;

/// <summary>
/// Public cryptographic origin and integrity metadata. A signature does not establish safety, reputation, or trustworthiness.
/// </summary>
public sealed record HipProtocolSignature
{
    /// <summary>The evidence scope used for HIP origin and integrity signatures.</summary>
    public const string OriginAndIntegrityScope = "origin-and-integrity";
    /// <summary>The canonical JSON profile used by version-one HIP signatures.</summary>
    public const string Rfc8785Canonicalization = "RFC8785";
    /// <summary>Maximum public key identifier length.</summary>
    public const int MaximumKeyIdLength = 128;
    /// <summary>Maximum algorithm identifier length.</summary>
    public const int MaximumAlgorithmLength = 128;
    /// <summary>Maximum encoded signature value length.</summary>
    public const int MaximumValueLength = 16_384;

    /// <summary>Creates validated public HIP signature metadata.</summary>
    /// <param name="scope">Evidence scope, which must be <see cref="OriginAndIntegrityScope"/>.</param>
    /// <param name="keyId">Stable public verification-key identifier.</param>
    /// <param name="algorithm">Exact public algorithm identifier.</param>
    /// <param name="algorithmFamily">Broad public cryptographic family.</param>
    /// <param name="canonicalization">Canonicalization profile, which must be <see cref="Rfc8785Canonicalization"/>.</param>
    /// <param name="value">Provider-produced encoded signature value.</param>
    [JsonConstructor]
    public HipProtocolSignature(
        string scope,
        string keyId,
        string algorithm,
        HIP.Domain.Identity.SignatureAlgorithmFamily algorithmFamily,
        string canonicalization,
        string value)
    {
        if (!string.Equals(scope, OriginAndIntegrityScope, StringComparison.Ordinal))
        {
            throw new ArgumentException($"HIP protocol signatures must use the '{OriginAndIntegrityScope}' evidence scope.", nameof(scope));
        }

        if (!Enum.IsDefined(algorithmFamily))
        {
            throw new ArgumentOutOfRangeException(nameof(algorithmFamily), algorithmFamily, "HIP signature algorithm family is unsupported.");
        }

        if (!string.Equals(canonicalization, Rfc8785Canonicalization, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"HIP protocol signatures must use the '{Rfc8785Canonicalization}' canonicalization profile.",
                nameof(canonicalization));
        }

        Scope = scope;
        KeyId = RequiredIdentifier(keyId, nameof(keyId), MaximumKeyIdLength);
        Algorithm = RequiredToken(algorithm, nameof(algorithm), MaximumAlgorithmLength);
        AlgorithmFamily = algorithmFamily;
        Canonicalization = canonicalization;
        Value = RequiredIdentifier(value, nameof(value), MaximumValueLength);
    }

    /// <summary>Gets the public evidence scope.</summary>
    [JsonPropertyName("scope"), JsonPropertyOrder(0)]
    public string Scope { get; }

    /// <summary>Gets the stable public verification-key identifier.</summary>
    [JsonPropertyName("keyId"), JsonPropertyOrder(1)]
    public string KeyId { get; }

    /// <summary>Gets the exact public algorithm identifier.</summary>
    [JsonPropertyName("algorithm"), JsonPropertyOrder(2)]
    public string Algorithm { get; }

    /// <summary>Gets the broad cryptographic family.</summary>
    [JsonPropertyName("algorithmFamily"), JsonPropertyOrder(3)]
    public HIP.Domain.Identity.SignatureAlgorithmFamily AlgorithmFamily { get; }

    /// <summary>Gets the canonicalization profile.</summary>
    [JsonPropertyName("canonicalization"), JsonPropertyOrder(4)]
    public string Canonicalization { get; }

    /// <summary>Gets the encoded signature value.</summary>
    [JsonPropertyName("value"), JsonPropertyOrder(5)]
    public string Value { get; }

    private static string RequiredIdentifier(string? value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("HIP protocol identifiers are required.", parameterName);
        }

        if (value.Length > maximumLength)
        {
            throw new ArgumentException($"HIP protocol identifiers cannot exceed {maximumLength} characters.", parameterName);
        }

        if (value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException("HIP protocol identifiers cannot contain whitespace or control characters.", parameterName);
        }

        return value;
    }

    private static string RequiredToken(string? value, string parameterName, int maximumLength)
    {
        var token = RequiredIdentifier(value, parameterName, maximumLength);
        if (!token.All(character =>
                character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':'))
        {
            throw new ArgumentException(
                "HIP protocol tokens may contain only letters, digits, hyphens, underscores, periods, and colons.",
                parameterName);
        }

        return token;
    }
}
