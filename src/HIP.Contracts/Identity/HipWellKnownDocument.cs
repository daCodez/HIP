namespace HIP.Domain.Identity;

/// <summary>Public HIP identity document served from a domain's well-known endpoint.</summary>
public sealed record HipWellKnownDocument(
    string Domain,
    string HipIdentityId,
    IReadOnlyCollection<SigningKey> PublicKeys,
    DateTimeOffset IssuedAtUtc,
    string SchemaVersion = "1",
    string? VerificationChallenge = null,
    DateTimeOffset? ExpiresAtUtc = null,
    HIP.Domain.Protocol.HipProtocolSignature? Signature = null);

/// <summary>Public verification key advertised by a HIP identity document.</summary>
public sealed record SigningKey(
    string KeyId,
    string Algorithm,
    string PublicKey);
