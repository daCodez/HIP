using System.Text.Json.Serialization;

namespace HIP.Domain.Protocol;

public sealed record HipContentDigest
{
    public const string Sha256Algorithm = "sha256";
    public const int Sha256HexLength = 64;

    [JsonConstructor]
    public HipContentDigest(string algorithm, string value)
    {
        if (!string.Equals(algorithm, Sha256Algorithm, StringComparison.Ordinal))
        {
            throw new ArgumentException("HIP content digest algorithm is unsupported.", nameof(algorithm));
        }

        if (value is null || value.Length != Sha256HexLength ||
            !value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f'))
        {
            throw new ArgumentException("HIP sha256 digests must contain exactly 64 lowercase hexadecimal characters.", nameof(value));
        }

        Algorithm = algorithm;
        Value = value;
    }

    [JsonPropertyName("algorithm")]
    [JsonPropertyOrder(0)]
    public string Algorithm { get; }

    [JsonPropertyName("value")]
    [JsonPropertyOrder(1)]
    public string Value { get; }

    public static HipContentDigest FromPrefixedString(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("HIP content digest is required.", nameof(value));
        }

        var separator = value.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == value.Length - 1)
        {
            throw new ArgumentException("HIP content digests must use the algorithm:value format.", nameof(value));
        }

        return new HipContentDigest(value[..separator], value[(separator + 1)..]);
    }

    public string ToPrefixedString() => $"{Algorithm}:{Value}";
}
