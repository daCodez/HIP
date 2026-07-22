using System.Text.Json.Serialization;

namespace HIP.Domain.Protocol;

public sealed record HipProtocolEnvelope
{
    public const int MaximumMessageIdLength = 128;
    public const int MinimumNonceBytes = 16;
    public const int MaximumNonceBytes = 64;

    [JsonConstructor]
    public HipProtocolEnvelope(
        HipProtocolVersion version,
        string messageId,
        string nonce,
        HipProtocolIssuer issuer,
        HipProtocolSubject subject,
        HipContentDigest contentDigest,
        HipProtocolClaims claims,
        HipProtocolSignature signature,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc)
    {
        if (!version.IsSupported)
        {
            throw new NotSupportedException($"HIP protocol version '{version}' is unsupported.");
        }

        Version = version;
        MessageId = HipProtocolValidation.RequiredToken(
            messageId,
            nameof(messageId),
            MaximumMessageIdLength);
        Nonce = HipProtocolValidation.RequiredCanonicalBase64Url(
            nonce,
            nameof(nonce),
            MinimumNonceBytes,
            MaximumNonceBytes);
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        ContentDigest = contentDigest ?? throw new ArgumentNullException(nameof(contentDigest));
        Claims = claims ?? throw new ArgumentNullException(nameof(claims));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        IssuedAtUtc = HipProtocolValidation.RequiredUtcTimestamp(issuedAtUtc, nameof(issuedAtUtc));
        ExpiresAtUtc = HipProtocolValidation.RequiredUtcTimestamp(expiresAtUtc, nameof(expiresAtUtc));

        if (ExpiresAtUtc <= IssuedAtUtc)
        {
            throw new ArgumentException("HIP protocol expiry must be later than issuance.", nameof(expiresAtUtc));
        }
    }

    [JsonPropertyName("version")]
    [JsonPropertyOrder(0)]
    public HipProtocolVersion Version { get; }

    [JsonPropertyName("messageId")]
    [JsonPropertyOrder(1)]
    public string MessageId { get; }

    [JsonPropertyName("nonce")]
    [JsonPropertyOrder(2)]
    public string Nonce { get; }

    [JsonPropertyName("issuer")]
    [JsonPropertyOrder(3)]
    public HipProtocolIssuer Issuer { get; }

    [JsonPropertyName("subject")]
    [JsonPropertyOrder(4)]
    public HipProtocolSubject Subject { get; }

    [JsonPropertyName("contentDigest")]
    [JsonPropertyOrder(5)]
    public HipContentDigest ContentDigest { get; }

    [JsonPropertyName("claims")]
    [JsonPropertyOrder(6)]
    public HipProtocolClaims Claims { get; }

    [JsonPropertyName("signature")]
    [JsonPropertyOrder(7)]
    public HipProtocolSignature Signature { get; }

    [JsonPropertyName("issuedAtUtc")]
    [JsonPropertyOrder(8)]
    public DateTimeOffset IssuedAtUtc { get; }

    [JsonPropertyName("expiresAtUtc")]
    [JsonPropertyOrder(9)]
    public DateTimeOffset ExpiresAtUtc { get; }
}
