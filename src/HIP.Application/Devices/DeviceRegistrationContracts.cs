using HIP.Domain.Audit;
using HIP.Domain.Devices;

namespace HIP.Application.Devices;

/// <summary>Stable application outcomes mapped to non-sensitive HTTP responses by HIP hosts.</summary>
public enum DeviceRegistrationOutcome
{
    Succeeded = 0,
    InvalidRequest = 1,
    InvalidProof = 2,
    Expired = 3,
    Conflict = 4,
    NotFound = 5,
    Unavailable = 6
}

/// <summary>Stable, privacy-safe device-registration result messages.</summary>
public static class DeviceRegistrationMessages
{
    public const string Succeeded = "The device registration operation succeeded.";
    public const string InvalidRequest = "The device registration request is invalid.";
    public const string InvalidProof = "The device registration proof is invalid.";
    public const string Expired = "The device registration challenge has expired.";
    public const string Conflict = "The device registration request conflicts with existing state.";
    public const string ResourceUnavailable = "The requested device registration resource is unavailable.";
    public const string Unavailable = "HIP device registration is unavailable.";
}

/// <summary>Bounded public metadata used to start proof-of-possession registration.</summary>
public sealed record StartDeviceRegistrationRequest(
    string FriendlyName,
    DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKey);

/// <summary>Exact payload and signature returned by the client when completing a challenge.</summary>
public sealed record CompleteDeviceRegistrationRequest(
    string SigningInput,
    string Signature);

/// <summary>Short-lived canonical bytes that a browser signs without reconstructing JSON.</summary>
public sealed record DeviceRegistrationChallengeResponse(
    string ChallengeId,
    string DeviceId,
    string SigningInput,
    DateTimeOffset ExpiresAtUtc,
    string KeyAlgorithm,
    string SignatureEncoding);

/// <summary>Public-safe device projection that intentionally excludes the raw public key and owner scope.</summary>
public sealed record DeviceRegistrationDeviceResponse(
    string DeviceId,
    string FriendlyName,
    DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKeyFingerprint,
    DeviceTrustState TrustState,
    DeviceRevocationState RevocationState,
    DateTimeOffset RegisteredAtUtc,
    DateTimeOffset LastSeenAtUtc,
    DateTimeOffset? RevokedAtUtc);

public sealed record DeviceRegistrationChallengeResult(
    DeviceRegistrationOutcome Outcome,
    string Message,
    DeviceRegistrationChallengeResponse? Challenge = null);

public sealed record DeviceRegistrationCompletionResult(
    DeviceRegistrationOutcome Outcome,
    string Message,
    DeviceRegistrationDeviceResponse? Device = null);

public sealed record DeviceRegistrationRevocationResult(
    DeviceRegistrationOutcome Outcome,
    string Message,
    DeviceRegistrationDeviceResponse? Device = null);

/// <summary>Bounded policy for one consumer's device-registration aggregate.</summary>
public sealed record DeviceRegistrationPolicy(
    TimeSpan ChallengeLifetime,
    int MaximumPendingChallenges,
    int MaximumDevices,
    int MaximumRetainedDevices,
    int MaximumRetainedChallenges,
    int MaximumFriendlyNameUtf8Bytes,
    int MaximumClientVersionUtf8Bytes,
    int MaximumOwnerIdUtf8Bytes)
{
    public static DeviceRegistrationPolicy Default { get; } = new(
        TimeSpan.FromMinutes(5),
        MaximumPendingChallenges: 5,
        MaximumDevices: 25,
        MaximumRetainedDevices: 25,
        MaximumRetainedChallenges: 25,
        MaximumFriendlyNameUtf8Bytes: 128,
        MaximumClientVersionUtf8Bytes: 64,
        MaximumOwnerIdUtf8Bytes: 512);
}

/// <summary>Atomic repository transition result.</summary>
public enum DeviceRegistrationSaveOutcome
{
    Succeeded = 0,
    VersionConflict = 1,
    BindingConflict = 2
}

/// <summary>
/// Captures the exact version observed for one current or legacy owner partition. Version zero
/// means the partition was absent and must remain absent until the guarded transition commits.
/// </summary>
public sealed record DeviceRegistrationOwnerVersionGuard(
    string OwnerScopeId,
    long ExpectedVersion);

/// <summary>Commits one aggregate version together with immutable bindings and privacy-safe audit facts.</summary>
public sealed record DeviceRegistrationTransitionBatch(
    DeviceRegistrationAggregate Aggregate,
    long ExpectedVersion,
    IReadOnlyCollection<DeviceRegistrationBinding> NewBindings,
    IReadOnlyCollection<AuditLogEntry> AuditEntries,
    IReadOnlyCollection<DeviceRegistrationOwnerVersionGuard>? OwnerVersionGuards = null);

public interface IDeviceRegistrationRepository
{
    Task<DeviceRegistrationAggregate?> GetAsync(
        string ownerScopeId,
        CancellationToken cancellationToken);

    Task<RegisteredDevice?> GetDeviceAsync(
        string deviceId,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("Direct device lookup is not available from this repository implementation.");

    Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
        DeviceRegistrationTransitionBatch transition,
        CancellationToken cancellationToken);
}

public interface IDeviceRegistrationService
{
    Task<DeviceRegistrationChallengeResult> IssueChallengeAsync(
        string ownerId,
        StartDeviceRegistrationRequest request,
        CancellationToken cancellationToken);

    Task<DeviceRegistrationCompletionResult> CompleteAsync(
        string ownerId,
        string challengeId,
        CompleteDeviceRegistrationRequest request,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<DeviceRegistrationDeviceResponse>> ListAsync(
        string ownerId,
        CancellationToken cancellationToken);

    Task<DeviceRegistrationRevocationResult> RevokeAsync(
        string ownerId,
        string deviceId,
        CancellationToken cancellationToken);
}
