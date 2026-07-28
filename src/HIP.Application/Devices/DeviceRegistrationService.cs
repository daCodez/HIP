using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Devices;
using HIP.Domain.Review;

namespace HIP.Application.Devices;

/// <summary>
/// Coordinates bounded, owner-scoped device proof without retaining raw nonces, payloads, signatures, or private keys.
/// </summary>
public sealed class DeviceRegistrationService(
    IDeviceRegistrationRepository repository,
    Es256DeviceProofVerifier proofVerifier,
    ICanonicalJsonService canonicalJsonService,
    DeviceRegistrationKeyDerivation keyDerivation,
    IAuditLogService auditLogService,
    TimeProvider timeProvider,
    DeviceRegistrationPolicy policy) : IDeviceRegistrationService
{
    private const int MaximumSaveAttempts = 4;
    private const string SignatureEncoding = "IEEE-P1363-BASE64URL";
    private const string KeyBindingType = "device-public-key";
    private const string DeviceBindingType = "device-id";

    public async Task<DeviceRegistrationChallengeResult> IssueChallengeAsync(
        string ownerId,
        StartDeviceRegistrationRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryValidateOwner(ownerId, out var ownerScopeIds) ||
            !TryValidateStartRequest(request, out var friendlyName, out var clientVersion, out var publicKey))
        {
            return ChallengeFailure(DeviceRegistrationOutcome.InvalidRequest);
        }

        var ownerScopeId = ownerScopeIds[0];
        for (var attempt = 0; attempt < MaximumSaveAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = timeProvider.GetUtcNow();
            var ownerAggregates = await LoadOwnerAggregatesAsync(ownerScopeIds, cancellationToken).ConfigureAwait(false);
            var ownerVersionGuards = OwnerVersionGuards(ownerScopeIds, ownerAggregates);
            var existing = ownerAggregates.SingleOrDefault(aggregate =>
                string.Equals(aggregate.OwnerScopeId, ownerScopeId, StringComparison.Ordinal));
            var current = existing ?? new DeviceRegistrationAggregate(ownerScopeId, 0, [], []);
            if (ownerAggregates.Sum(aggregate => aggregate.Devices.Count(device =>
                    device.RevocationState == DeviceRevocationState.Active)) >=
                    policy.MaximumDevices ||
                ownerAggregates.Sum(aggregate => aggregate.Challenges.Count(challenge =>
                    challenge.State == DeviceRegistrationChallengeState.Pending &&
                    now < challenge.ExpiresAtUtc)) >= policy.MaximumPendingChallenges ||
                ownerAggregates.SelectMany(aggregate => aggregate.Challenges).Any(challenge =>
                    challenge.State == DeviceRegistrationChallengeState.Pending &&
                    now < challenge.ExpiresAtUtc &&
                    string.Equals(challenge.PublicKeyFingerprint, publicKey.PublicKeyFingerprint, StringComparison.Ordinal)))
            {
                return ChallengeFailure(DeviceRegistrationOutcome.Conflict);
            }

            var challengeId = NewOpaqueId("drc");
            var deviceId = NewOpaqueId("dev");
            var expiresAtUtc = now.Add(policy.ChallengeLifetime);
            var signingInput = CreateSigningInput(
                challengeId,
                deviceId,
                ownerScopeId,
                friendlyName,
                request.PlatformType,
                clientVersion,
                publicKey,
                now,
                expiresAtUtc);
            var challenge = new DeviceRegistrationChallenge(
                challengeId,
                deviceId,
                friendlyName,
                request.PlatformType,
                clientVersion,
                publicKey.Algorithm,
                publicKey.PublicKey,
                publicKey.PublicKeyFingerprint,
                Digest(signingInput),
                now,
                expiresAtUtc,
                DeviceRegistrationChallengeState.Pending,
                ConsumedAtUtc: null);
            var challenges = current.Challenges
                .Where(item => item.State == DeviceRegistrationChallengeState.Pending ||
                               item.ExpiresAtUtc > now.Subtract(policy.ChallengeLifetime))
                .Append(challenge)
                .TakeLast(policy.MaximumRetainedChallenges)
                .ToArray();
            var updated = current with
            {
                Version = current.Version + 1,
                Challenges = challenges
            };
            var audit = CreateChallengeAudit(ownerScopeId, challenge);
            var saved = await repository.TrySaveAsync(
                    new DeviceRegistrationTransitionBatch(
                        updated,
                        current.Version,
                        [],
                        [audit],
                        ownerVersionGuards),
                    cancellationToken)
                .ConfigureAwait(false);
            if (saved == DeviceRegistrationSaveOutcome.Succeeded)
            {
                return new DeviceRegistrationChallengeResult(
                    DeviceRegistrationOutcome.Succeeded,
                    DeviceRegistrationMessages.Succeeded,
                    new DeviceRegistrationChallengeResponse(
                        challengeId,
                        deviceId,
                        DeviceRegistrationEncoding.Base64UrlEncode(signingInput),
                        expiresAtUtc,
                        publicKey.Algorithm,
                        SignatureEncoding));
            }

            if (saved == DeviceRegistrationSaveOutcome.BindingConflict)
            {
                return ChallengeFailure(DeviceRegistrationOutcome.Conflict);
            }
        }

        return ChallengeFailure(DeviceRegistrationOutcome.Conflict);
    }

    public async Task<DeviceRegistrationCompletionResult> CompleteAsync(
        string ownerId,
        string challengeId,
        CompleteDeviceRegistrationRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryValidateOwner(ownerId, out var ownerScopeIds) || string.IsNullOrWhiteSpace(challengeId))
        {
            return CompletionFailure(DeviceRegistrationOutcome.NotFound);
        }

        if (request is null ||
            !DeviceRegistrationEncoding.TryDecodeBase64Url(
                request.SigningInput,
                Es256DeviceProofVerifier.MaximumSigningPayloadBytes,
                out var signingInput))
        {
            return CompletionFailure(DeviceRegistrationOutcome.InvalidProof);
        }

        for (var attempt = 0; attempt < MaximumSaveAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ownerAggregates = await LoadOwnerAggregatesAsync(ownerScopeIds, cancellationToken).ConfigureAwait(false);
            var ownerVersionGuards = OwnerVersionGuards(ownerScopeIds, ownerAggregates);
            var matchingAggregates = ownerAggregates
                .Where(aggregate => aggregate.Challenges.Any(item =>
                    string.Equals(item.ChallengeId, challengeId, StringComparison.Ordinal)))
                .ToArray();
            if (matchingAggregates.Length == 0)
            {
                return CompletionFailure(DeviceRegistrationOutcome.NotFound);
            }

            if (matchingAggregates.Length != 1)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Conflict);
            }

            var current = matchingAggregates[0];
            var ownerScopeId = current.OwnerScopeId;
            var challenge = current.Challenges.Single(item =>
                string.Equals(item.ChallengeId, challengeId, StringComparison.Ordinal));
            if (challenge.State != DeviceRegistrationChallengeState.Pending)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Conflict);
            }

            var now = timeProvider.GetUtcNow();
            if (now >= challenge.ExpiresAtUtc)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Expired);
            }

            if (!DigestMatches(challenge.SigningInputDigest, signingInput) ||
                !proofVerifier.VerifySignature(
                    new ValidatedDevicePublicKey(
                        challenge.KeyAlgorithm,
                        challenge.PublicKey,
                        challenge.PublicKeyFingerprint),
                    signingInput,
                    request.Signature))
            {
                return CompletionFailure(DeviceRegistrationOutcome.InvalidProof);
            }

            now = timeProvider.GetUtcNow();
            if (now >= challenge.ExpiresAtUtc)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Expired);
            }

            if (ownerAggregates.Sum(aggregate => aggregate.Devices.Count(device =>
                    device.RevocationState == DeviceRevocationState.Active)) >=
                policy.MaximumDevices)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Conflict);
            }

            var device = new RegisteredDevice(
                challenge.DeviceId,
                challenge.FriendlyName,
                challenge.PlatformType,
                challenge.ClientVersion,
                challenge.KeyAlgorithm,
                challenge.PublicKey,
                challenge.PublicKeyFingerprint,
                DeviceTrustState.ProofOfPossessionVerified,
                DeviceRevocationState.Active,
                now,
                now,
                RevokedAtUtc: null);
            var consumedChallenge = challenge with
            {
                State = DeviceRegistrationChallengeState.Consumed,
                ConsumedAtUtc = now
            };
            var updated = current with
            {
                Version = current.Version + 1,
                Challenges = current.Challenges
                    .Select(item => string.Equals(item.ChallengeId, challengeId, StringComparison.Ordinal)
                        ? consumedChallenge
                        : item)
                    .ToArray(),
                Devices = RetainDevicesForRegistration(current.Devices).Append(device).ToArray()
            };
            DeviceRegistrationBinding[] bindings =
            [
                new(KeyBindingType, device.PublicKeyFingerprint, ownerScopeId, device.DeviceId),
                new(DeviceBindingType, device.DeviceId, ownerScopeId, device.DeviceId)
            ];
            var audit = CreateAudit(
                ownerScopeId,
                device,
                "ConsumerDevice.Registered",
                "A consumer device completed proof-of-possession registration.",
                AuditSeverity.Medium,
                now);
            var saved = await repository.TrySaveAsync(
                    new DeviceRegistrationTransitionBatch(
                        updated,
                        current.Version,
                        bindings,
                        [audit],
                        ownerVersionGuards),
                    cancellationToken)
                .ConfigureAwait(false);
            if (saved == DeviceRegistrationSaveOutcome.Succeeded)
            {
                return new DeviceRegistrationCompletionResult(
                    DeviceRegistrationOutcome.Succeeded,
                    DeviceRegistrationMessages.Succeeded,
                    ToResponse(device));
            }

            if (saved == DeviceRegistrationSaveOutcome.BindingConflict)
            {
                return CompletionFailure(DeviceRegistrationOutcome.Conflict);
            }
        }

        return CompletionFailure(DeviceRegistrationOutcome.Conflict);
    }

    public async Task<IReadOnlyCollection<DeviceRegistrationDeviceResponse>> ListAsync(
        string ownerId,
        CancellationToken cancellationToken)
    {
        if (!TryValidateOwner(ownerId, out var ownerScopeIds))
        {
            return [];
        }

        var ownerAggregates = await LoadOwnerAggregatesAsync(ownerScopeIds, cancellationToken).ConfigureAwait(false);
        var devices = MergeDevices(ownerAggregates);
        return devices
            .OrderByDescending(device => device.RegisteredAtUtc)
            .Select(ToResponse)
            .ToArray();
    }

    public async Task<DeviceRegistrationRevocationResult> RevokeAsync(
        string ownerId,
        string deviceId,
        CancellationToken cancellationToken)
    {
        if (!TryValidateOwner(ownerId, out var ownerScopeIds) || string.IsNullOrWhiteSpace(deviceId))
        {
            return RevocationFailure(DeviceRegistrationOutcome.NotFound);
        }

        for (var attempt = 0; attempt < MaximumSaveAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ownerAggregates = await LoadOwnerAggregatesAsync(ownerScopeIds, cancellationToken).ConfigureAwait(false);
            var ownerVersionGuards = OwnerVersionGuards(ownerScopeIds, ownerAggregates);
            var matchingAggregates = ownerAggregates
                .Where(aggregate => aggregate.Devices.Any(item =>
                    string.Equals(item.DeviceId, deviceId, StringComparison.Ordinal)))
                .ToArray();
            if (matchingAggregates.Length == 0)
            {
                return RevocationFailure(DeviceRegistrationOutcome.NotFound);
            }

            if (matchingAggregates.Length != 1)
            {
                return RevocationFailure(DeviceRegistrationOutcome.Conflict);
            }

            var current = matchingAggregates[0];
            var ownerScopeId = current.OwnerScopeId;
            var device = current.Devices.Single(item =>
                string.Equals(item.DeviceId, deviceId, StringComparison.Ordinal));
            if (device.RevocationState == DeviceRevocationState.Revoked)
            {
                return new DeviceRegistrationRevocationResult(
                    DeviceRegistrationOutcome.Succeeded,
                    DeviceRegistrationMessages.Succeeded,
                    ToResponse(device));
            }

            var now = timeProvider.GetUtcNow();
            var revoked = device with
            {
                RevocationState = DeviceRevocationState.Revoked,
                RevokedAtUtc = now
            };
            var updated = current with
            {
                Version = current.Version + 1,
                Devices = current.Devices
                    .Select(item => string.Equals(item.DeviceId, deviceId, StringComparison.Ordinal) ? revoked : item)
                    .ToArray()
            };
            var audit = CreateAudit(
                ownerScopeId,
                revoked,
                "ConsumerDevice.Revoked",
                "A consumer device was irreversibly revoked.",
                AuditSeverity.High,
                now);
            var saved = await repository.TrySaveAsync(
                    new DeviceRegistrationTransitionBatch(
                        updated,
                        current.Version,
                        [],
                        [audit],
                        ownerVersionGuards),
                    cancellationToken)
                .ConfigureAwait(false);
            if (saved == DeviceRegistrationSaveOutcome.Succeeded)
            {
                return new DeviceRegistrationRevocationResult(
                    DeviceRegistrationOutcome.Succeeded,
                    DeviceRegistrationMessages.Succeeded,
                    ToResponse(revoked));
            }
        }

        return RevocationFailure(DeviceRegistrationOutcome.Conflict);
    }

    private bool TryValidateOwner(string ownerId, out IReadOnlyList<string> ownerScopeIds)
    {
        ownerScopeIds = [];
        if (string.IsNullOrWhiteSpace(ownerId) ||
            Encoding.UTF8.GetByteCount(ownerId) > policy.MaximumOwnerIdUtf8Bytes)
        {
            return false;
        }

        ownerScopeIds = keyDerivation.OwnerScopeIds(ownerId);
        return true;
    }

    private async Task<IReadOnlyList<DeviceRegistrationAggregate>> LoadOwnerAggregatesAsync(
        IReadOnlyList<string> ownerScopeIds,
        CancellationToken cancellationToken)
    {
        var aggregates = new List<DeviceRegistrationAggregate>(ownerScopeIds.Count);
        foreach (var ownerScopeId in ownerScopeIds)
        {
            var aggregate = await repository.GetAsync(ownerScopeId, cancellationToken).ConfigureAwait(false);
            if (aggregate is not null)
            {
                aggregates.Add(aggregate);
            }
        }

        return aggregates;
    }

    private static IReadOnlyCollection<DeviceRegistrationOwnerVersionGuard> OwnerVersionGuards(
        IReadOnlyList<string> ownerScopeIds,
        IReadOnlyCollection<DeviceRegistrationAggregate> ownerAggregates)
    {
        var versions = ownerAggregates.ToDictionary(
            aggregate => aggregate.OwnerScopeId,
            aggregate => aggregate.Version,
            StringComparer.Ordinal);
        return Array.AsReadOnly(ownerScopeIds
            .Select(ownerScopeId => new DeviceRegistrationOwnerVersionGuard(
                ownerScopeId,
                versions.GetValueOrDefault(ownerScopeId)))
            .ToArray());
    }

    private static IReadOnlyCollection<RegisteredDevice> MergeDevices(
        IReadOnlyCollection<DeviceRegistrationAggregate> ownerAggregates)
    {
        var devicesById = new Dictionary<string, RegisteredDevice>(StringComparer.Ordinal);
        var deviceIdsByFingerprint = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var device in ownerAggregates.SelectMany(aggregate => aggregate.Devices))
        {
            if (devicesById.TryGetValue(device.DeviceId, out var existing) && existing != device)
            {
                throw new InvalidOperationException(
                    "Persisted device-registration rotation data contains an ambiguous device identifier.");
            }

            if (deviceIdsByFingerprint.TryGetValue(device.PublicKeyFingerprint, out var existingDeviceId) &&
                !string.Equals(existingDeviceId, device.DeviceId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Persisted device-registration rotation data contains an ambiguous public-key binding.");
            }

            devicesById.TryAdd(device.DeviceId, device);
            deviceIdsByFingerprint.TryAdd(device.PublicKeyFingerprint, device.DeviceId);
        }

        return devicesById.Values.ToArray();
    }

    private bool TryValidateStartRequest(
        StartDeviceRegistrationRequest request,
        out string friendlyName,
        out string clientVersion,
        out ValidatedDevicePublicKey publicKey)
    {
        friendlyName = string.Empty;
        clientVersion = string.Empty;
        publicKey = null!;
        if (request is null ||
            !Enum.IsDefined(request.PlatformType) ||
            string.IsNullOrWhiteSpace(request.FriendlyName) ||
            string.IsNullOrWhiteSpace(request.ClientVersion))
        {
            return false;
        }

        friendlyName = request.FriendlyName.Trim();
        clientVersion = request.ClientVersion.Trim();
        if (Encoding.UTF8.GetByteCount(friendlyName) > policy.MaximumFriendlyNameUtf8Bytes ||
            Encoding.UTF8.GetByteCount(clientVersion) > policy.MaximumClientVersionUtf8Bytes)
        {
            return false;
        }

        try
        {
            publicKey = proofVerifier.ValidatePublicKey(request.KeyAlgorithm, request.PublicKey);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or CryptographicException)
        {
            return false;
        }
    }

    private byte[] CreateSigningInput(
        string challengeId,
        string deviceId,
        string ownerScopeId,
        string friendlyName,
        DevicePlatformType platformType,
        string clientVersion,
        ValidatedDevicePublicKey publicKey,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc)
    {
        var nonce = DeviceRegistrationEncoding.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var payload = new
        {
            version = 1,
            purpose = "hip-device-registration-proof",
            challengeId,
            nonce,
            deviceId,
            ownerScopeId,
            algorithm = publicKey.Algorithm,
            publicKeyFingerprint = publicKey.PublicKeyFingerprint,
            friendlyName,
            platformType = platformType.ToString(),
            clientVersion,
            issuedAtUtc,
            expiresAtUtc
        };
        return canonicalJsonService.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(payload));
    }

    private AuditLogEntry CreateAudit(
        string ownerScopeId,
        RegisteredDevice device,
        string action,
        string summary,
        AuditSeverity severity,
        DateTimeOffset createdAtUtc) =>
        AuditLogIntegrity.Seal(auditLogService.CreateEntry(
            ownerScopeId,
            action,
            TargetType.DeviceKey,
            device.DeviceId,
            summary,
            severity,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["keyAlgorithm"] = device.KeyAlgorithm,
                ["publicKeyFingerprint"] = device.PublicKeyFingerprint,
                ["trustState"] = device.TrustState.ToString(),
                ["revocationState"] = device.RevocationState.ToString()
            },
            actorRole: "Consumer") with
        {
            CreatedAtUtc = createdAtUtc
        });

    private IReadOnlyCollection<RegisteredDevice> RetainDevicesForRegistration(
        IReadOnlyCollection<RegisteredDevice> devices)
    {
        var active = devices
            .Where(device => device.RevocationState == DeviceRevocationState.Active)
            .ToArray();
        var revokedSlots = Math.Max(0, policy.MaximumRetainedDevices - active.Length - 1);
        var retainedRevoked = devices
            .Where(device => device.RevocationState == DeviceRevocationState.Revoked)
            .OrderByDescending(device => device.RevokedAtUtc ?? device.RegisteredAtUtc)
            .Take(revokedSlots);
        return active.Concat(retainedRevoked).ToArray();
    }

    private AuditLogEntry CreateChallengeAudit(
        string ownerScopeId,
        DeviceRegistrationChallenge challenge) =>
        AuditLogIntegrity.Seal(auditLogService.CreateEntry(
            ownerScopeId,
            "ConsumerDevice.RegistrationChallengeIssued",
            TargetType.DeviceKey,
            challenge.DeviceId,
            "A short-lived consumer device registration challenge was issued.",
            AuditSeverity.Low,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["keyAlgorithm"] = challenge.KeyAlgorithm,
                ["publicKeyFingerprint"] = challenge.PublicKeyFingerprint,
                ["platformType"] = challenge.PlatformType.ToString(),
                ["expiresAtUtc"] = challenge.ExpiresAtUtc.ToString("O")
            },
            actorRole: "Consumer") with
        {
            CreatedAtUtc = challenge.IssuedAtUtc
        });

    private static DeviceRegistrationDeviceResponse ToResponse(RegisteredDevice device) =>
        new(
            device.DeviceId,
            device.FriendlyName,
            device.PlatformType,
            device.ClientVersion,
            device.KeyAlgorithm,
            device.PublicKeyFingerprint,
            device.TrustState,
            device.RevocationState,
            device.RegisteredAtUtc,
            device.LastSeenAtUtc,
            device.RevokedAtUtc);

    private static string NewOpaqueId(string prefix) =>
        $"{prefix}_{DeviceRegistrationEncoding.Base64UrlEncode(RandomNumberGenerator.GetBytes(18))}";

    private static string Digest(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    private static bool DigestMatches(string expected, ReadOnlySpan<byte> value)
    {
        const string prefix = "sha256:";
        if (!expected.StartsWith(prefix, StringComparison.Ordinal) || expected.Length != prefix.Length + 64)
        {
            return false;
        }

        try
        {
            var expectedBytes = Convert.FromHexString(expected[prefix.Length..]);
            var actualBytes = SHA256.HashData(value);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static DeviceRegistrationChallengeResult ChallengeFailure(DeviceRegistrationOutcome outcome) =>
        new(outcome, Message(outcome));

    private static DeviceRegistrationCompletionResult CompletionFailure(DeviceRegistrationOutcome outcome) =>
        new(outcome, Message(outcome));

    private static DeviceRegistrationRevocationResult RevocationFailure(DeviceRegistrationOutcome outcome) =>
        new(outcome, Message(outcome));

    private static string Message(DeviceRegistrationOutcome outcome) => outcome switch
    {
        DeviceRegistrationOutcome.Succeeded => DeviceRegistrationMessages.Succeeded,
        DeviceRegistrationOutcome.InvalidRequest => DeviceRegistrationMessages.InvalidRequest,
        DeviceRegistrationOutcome.InvalidProof => DeviceRegistrationMessages.InvalidProof,
        DeviceRegistrationOutcome.Expired => DeviceRegistrationMessages.Expired,
        DeviceRegistrationOutcome.Conflict => DeviceRegistrationMessages.Conflict,
        DeviceRegistrationOutcome.NotFound => DeviceRegistrationMessages.ResourceUnavailable,
        _ => DeviceRegistrationMessages.Unavailable
    };
}
