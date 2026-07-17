using System.Text.Json.Serialization;
using HIP.Domain.Identity;

namespace HIP.Domain.Protocol;

/// <summary>
/// Cryptographic origin and integrity metadata. A signature does not establish safety, reputation, or trustworthiness.
/// </summary>
public sealed record HipProtocolSignature
{
    public const string OriginAndIntegrityScope = "origin-and-integrity";
    public const int MaximumKeyIdLength = 128;
    public const int MaximumAlgorithmLength = 128;
    public const int MaximumValueLength = 16_384;

    [JsonConstructor]
    public HipProtocolSignature(
        string scope,
        string keyId,
        string algorithm,
        SignatureAlgorithmFamily algorithmFamily,
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

        Scope = scope;
        KeyId = HipProtocolValidation.RequiredIdentifier(keyId, nameof(keyId), MaximumKeyIdLength);
        Algorithm = HipProtocolValidation.RequiredToken(algorithm, nameof(algorithm), MaximumAlgorithmLength);
        AlgorithmFamily = algorithmFamily;
        Value = HipProtocolValidation.RequiredIdentifier(value, nameof(value), MaximumValueLength);
    }

    [JsonPropertyName("scope")]
    [JsonPropertyOrder(0)]
    public string Scope { get; }

    [JsonPropertyName("keyId")]
    [JsonPropertyOrder(1)]
    public string KeyId { get; }

    [JsonPropertyName("algorithm")]
    [JsonPropertyOrder(2)]
    public string Algorithm { get; }

    [JsonPropertyName("algorithmFamily")]
    [JsonPropertyOrder(3)]
    public SignatureAlgorithmFamily AlgorithmFamily { get; }

    [JsonPropertyName("value")]
    [JsonPropertyOrder(4)]
    public string Value { get; }
}
