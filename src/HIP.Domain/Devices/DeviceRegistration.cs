namespace HIP.Domain.Devices;

/// <summary>Identifies the bounded HIP client family associated with a registered device key.</summary>
public enum DevicePlatformType
{
    BrowserExtension = 0,
    SecondLifeHud = 1,
    Other = 2
}

/// <summary>Describes only the cryptographic assurance established during device registration.</summary>
public enum DeviceTrustState
{
    ProofOfPossessionVerified = 0
}

/// <summary>Tracks the terminal revocation state of a registered device.</summary>
public enum DeviceRevocationState
{
    Active = 0,
    Revoked = 1
}

/// <summary>Tracks whether a short-lived proof challenge remains usable.</summary>
public enum DeviceRegistrationChallengeState
{
    Pending = 0,
    Consumed = 1
}

/// <summary>
/// Retains the minimum server-side facts needed to verify one device proof without retaining its nonce or payload.
/// </summary>
public sealed record DeviceRegistrationChallenge(
    string ChallengeId,
    string DeviceId,
    string FriendlyName,
    DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKey,
    string PublicKeyFingerprint,
    string SigningInputDigest,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DeviceRegistrationChallengeState State,
    DateTimeOffset? ConsumedAtUtc);

/// <summary>Represents one owner-bound device and its public verification material.</summary>
public sealed record RegisteredDevice(
    string DeviceId,
    string FriendlyName,
    DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKey,
    string PublicKeyFingerprint,
    DeviceTrustState TrustState,
    DeviceRevocationState RevocationState,
    DateTimeOffset RegisteredAtUtc,
    DateTimeOffset LastSeenAtUtc,
    DateTimeOffset? RevokedAtUtc);

/// <summary>Versioned, privacy-scoped aggregate for one consumer's registration challenges and devices.</summary>
public sealed record DeviceRegistrationAggregate(
    string OwnerScopeId,
    long Version,
    IReadOnlyList<DeviceRegistrationChallenge> Challenges,
    IReadOnlyList<RegisteredDevice> Devices);

/// <summary>Immutable global binding that prevents a key or device identifier from being claimed elsewhere.</summary>
public sealed record DeviceRegistrationBinding(
    string BindingType,
    string BindingId,
    string OwnerScopeId,
    string DeviceId);
