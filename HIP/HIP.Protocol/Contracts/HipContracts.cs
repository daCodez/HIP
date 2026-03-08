namespace HIP.Protocol.Contracts;

public static class HipProtocolVersions
{
    public const string V1 = "1.0";
    // Experimental versioned canonical profile for binary signable format.
    public const string V1Binary = "1.1-binary";
}

public enum HipDecision
{
    Allow,
    Challenge,
    Warn,
    RateLimit,
    Quarantine,
    Block
}

public enum HipErrorCode
{
    InvalidSignature,
    ReplayDetected,
    TimestampExpired,
    UnsupportedVersion,
    InvalidEnvelope,
    UnknownIdentity,
    DeviceNotTrusted,
    LowReputation,
    PolicyViolation,
    ChallengeRequired,
    KeyRevoked
}

public sealed record HipIdentityDocument(
    string HipVersion,
    string HipId,
    string PublicKeyId,
    string PublicKey,
    string Algorithm,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ExpiresUtc = null,
    IReadOnlyList<string>? DeviceBindings = null,
    IReadOnlyDictionary<string, string>? Metadata = null,
    IReadOnlyDictionary<string, string>? Extensions = null);

public sealed record HipHello(string HipVersion, string SenderHipId, string? ReceiverHipId, string Nonce, DateTimeOffset TimestampUtc);
public sealed record HipChallenge(string HipVersion, string ChallengeId, string SenderHipId, string VerifierHipId, string Nonce, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc);
public sealed record HipProof(string HipVersion, string ChallengeId, string SenderHipId, string Signature, DateTimeOffset TimestampUtc);

public sealed record HipTrustAssertion(
    string ClaimType,
    string ClaimValue,
    string Source,
    DateTimeOffset TimestampUtc);

public sealed record HipMessageEnvelope(
    string HipVersion,
    string MessageType,
    string SenderHipId,
    string? ReceiverHipId,
    DateTimeOffset TimestampUtc,
    string Nonce,
    string PayloadHash,
    string Signature,
    string CorrelationId,
    string? DeviceId = null,
    IReadOnlyList<HipTrustAssertion>? TrustClaims = null,
    IReadOnlyDictionary<string, string>? Extensions = null);

public sealed record HipPolicyDecision(
    HipDecision Decision,
    string Reason,
    IReadOnlyList<string> AppliedPolicyIds,
    DateTimeOffset TimestampUtc);

public sealed record HipTrustReceipt(
    string ReceiptId,
    string HipVersion,
    string InteractionType,
    string SenderHipId,
    string? ReceiverHipId,
    DateTimeOffset TimestampUtc,
    string MessageHash,
    string? DeviceId,
    IReadOnlyList<string> Checks,
    HipDecision Decision,
    IReadOnlyList<string> AppliedPolicyIds,
    int? ReputationSnapshot,
    string ReceiptSignature);

public sealed record HipError(
    HipErrorCode Code,
    string Message,
    string? CorrelationId,
    string? Details = null);
