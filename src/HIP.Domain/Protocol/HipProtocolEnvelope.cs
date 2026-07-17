using System.Text.Json.Serialization;

namespace HIP.Domain.Protocol;

public sealed record HipProtocolEnvelope
{
    [JsonConstructor]
    public HipProtocolEnvelope(
        HipProtocolVersion version,
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

    [JsonPropertyName("issuer")]
    [JsonPropertyOrder(1)]
    public HipProtocolIssuer Issuer { get; }

    [JsonPropertyName("subject")]
    [JsonPropertyOrder(2)]
    public HipProtocolSubject Subject { get; }

    [JsonPropertyName("contentDigest")]
    [JsonPropertyOrder(3)]
    public HipContentDigest ContentDigest { get; }

    [JsonPropertyName("claims")]
    [JsonPropertyOrder(4)]
    public HipProtocolClaims Claims { get; }

    [JsonPropertyName("signature")]
    [JsonPropertyOrder(5)]
    public HipProtocolSignature Signature { get; }

    [JsonPropertyName("issuedAtUtc")]
    [JsonPropertyOrder(6)]
    public DateTimeOffset IssuedAtUtc { get; }

    [JsonPropertyName("expiresAtUtc")]
    [JsonPropertyOrder(7)]
    public DateTimeOffset ExpiresAtUtc { get; }
}
