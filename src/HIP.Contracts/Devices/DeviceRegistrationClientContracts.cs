namespace HIP.Application.Devices;

/// <summary>Bounded public metadata used to start proof-of-possession registration.</summary>
/// <param name="FriendlyName">User-facing device name.</param>
/// <param name="PlatformType">Bounded HIP client family.</param>
/// <param name="ClientVersion">Client-supplied version used for compatibility diagnostics.</param>
/// <param name="KeyAlgorithm">Public-key algorithm identifier.</param>
/// <param name="PublicKey">Public verification key. Private key material must never be submitted.</param>
public sealed record StartDeviceRegistrationRequest(
    string FriendlyName,
    HIP.Domain.Devices.DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKey);

/// <summary>Exact payload and signature returned by the client when completing a challenge.</summary>
/// <param name="SigningInput">Server-issued canonical challenge payload.</param>
/// <param name="Signature">Client signature over the exact canonical payload.</param>
public sealed record CompleteDeviceRegistrationRequest(
    string SigningInput,
    string Signature);

/// <summary>Short-lived canonical bytes that a client signs without reconstructing JSON.</summary>
/// <param name="ChallengeId">Opaque registration challenge identifier.</param>
/// <param name="DeviceId">Opaque candidate device identifier.</param>
/// <param name="SigningInput">Exact canonical payload the client must sign.</param>
/// <param name="ExpiresAtUtc">Challenge expiration timestamp.</param>
/// <param name="KeyAlgorithm">Required public-key algorithm identifier.</param>
/// <param name="SignatureEncoding">Required signature encoding.</param>
public sealed record DeviceRegistrationChallengeResponse(
    string ChallengeId,
    string DeviceId,
    string SigningInput,
    DateTimeOffset ExpiresAtUtc,
    string KeyAlgorithm,
    string SignatureEncoding);

/// <summary>Public-safe device projection that excludes the raw public key and owner scope.</summary>
/// <param name="DeviceId">Opaque registered device identifier.</param>
/// <param name="FriendlyName">User-facing device name.</param>
/// <param name="PlatformType">Bounded HIP client family.</param>
/// <param name="ClientVersion">Registered client version.</param>
/// <param name="KeyAlgorithm">Registered public-key algorithm identifier.</param>
/// <param name="PublicKeyFingerprint">Stable fingerprint of the registered public verification key.</param>
/// <param name="TrustState">Cryptographic assurance established during registration.</param>
/// <param name="RevocationState">Whether the registration remains active.</param>
/// <param name="RegisteredAtUtc">Registration completion timestamp.</param>
/// <param name="LastSeenAtUtc">Most recent authenticated device activity.</param>
/// <param name="RevokedAtUtc">Revocation timestamp when revoked.</param>
public sealed record DeviceRegistrationDeviceResponse(
    string DeviceId,
    string FriendlyName,
    HIP.Domain.Devices.DevicePlatformType PlatformType,
    string ClientVersion,
    string KeyAlgorithm,
    string PublicKeyFingerprint,
    HIP.Domain.Devices.DeviceTrustState TrustState,
    HIP.Domain.Devices.DeviceRevocationState RevocationState,
    DateTimeOffset RegisteredAtUtc,
    DateTimeOffset LastSeenAtUtc,
    DateTimeOffset? RevokedAtUtc);
