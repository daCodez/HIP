using HIP.Application.Reporting;
using HIP.Domain.Devices;

namespace HIP.Application.Devices;

/// <summary>
/// Enforces the storage-independent invariants for one device-registration aggregate transition.
/// </summary>
public static class DeviceRegistrationTransitionValidator
{
    private const string DeviceBindingType = "device-id";
    private const string KeyBindingType = "device-public-key";
    private const string OwnerScopePrefix = "owner-hmac-sha256-v1:";
    private const string DigestPrefix = "sha256:";
    private const int MaximumRetainedChallenges = 25;
    private const int MaximumRegisteredDevices = 25;
    private const int MaximumAuditEntriesPerTransition = 8;

    /// <summary>Validates the self-contained shape of a proposed aggregate transition.</summary>
    public static void ValidateTransition(DeviceRegistrationTransitionBatch transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        ArgumentNullException.ThrowIfNull(transition.Aggregate);
        ArgumentNullException.ThrowIfNull(transition.NewBindings);
        ArgumentNullException.ThrowIfNull(transition.AuditEntries);
        if (transition.ExpectedVersion < 0 ||
            transition.ExpectedVersion == long.MaxValue ||
            transition.Aggregate.Version != transition.ExpectedVersion + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(transition),
                "A device-registration transition must advance its expected aggregate version exactly once.");
        }

        ValidateStoredAggregate(
            transition.Aggregate,
            transition.Aggregate.OwnerScopeId,
            transition.Aggregate.Version);
        ValidateOwnerVersionGuards(transition);
        if (transition.NewBindings.Count is 1 or > 2 ||
            transition.NewBindings.Select(BindingRecordKey).Distinct().Count() != transition.NewBindings.Count)
        {
            throw new ArgumentException(
                "A device-registration transition contains invalid or duplicate global bindings.",
                nameof(transition));
        }

        foreach (var binding in transition.NewBindings)
        {
            ValidateNewBinding(binding, transition.Aggregate);
        }

        if (transition.AuditEntries.Count is < 1 or > MaximumAuditEntriesPerTransition ||
            transition.AuditEntries.Any(entry => entry is null) ||
            transition.AuditEntries.Any(entry => string.IsNullOrWhiteSpace(entry.AuditLogId)) ||
            transition.AuditEntries.Select(entry => entry.AuditLogId).Distinct(StringComparer.Ordinal).Count() !=
            transition.AuditEntries.Count)
        {
            throw new ArgumentException(
                "A device-registration transition contains invalid or duplicate audit facts.",
                nameof(transition));
        }
    }

    /// <summary>
    /// Returns the bounded current-first owner snapshot that repositories must validate atomically.
    /// Older callers without an explicit rotation snapshot remain guarded by the containing partition.
    /// </summary>
    public static IReadOnlyCollection<DeviceRegistrationOwnerVersionGuard> ResolveOwnerVersionGuards(
        DeviceRegistrationTransitionBatch transition) =>
        transition.OwnerVersionGuards ??
        [new DeviceRegistrationOwnerVersionGuard(
            transition.Aggregate.OwnerScopeId,
            transition.ExpectedVersion)];

    /// <summary>Validates changes against the exact aggregate version that a repository read.</summary>
    public static void ValidateDelta(
        DeviceRegistrationAggregate? previous,
        DeviceRegistrationTransitionBatch transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        var aggregate = transition.Aggregate;
        if (previous is not null)
        {
            ValidateStoredAggregate(previous, aggregate.OwnerScopeId, transition.ExpectedVersion);
        }

        ValidateChallengeDelta(previous, transition);
        ValidateDeviceDelta(previous, transition);
        ValidateRegistrationCoupling(previous, transition);
    }

    /// <summary>Validates an aggregate restored from trusted encrypted storage.</summary>
    public static void ValidateStoredAggregate(
        DeviceRegistrationAggregate aggregate,
        string requestedOwnerScopeId,
        long rowVersion)
    {
        if (aggregate is null || aggregate.Challenges is null || aggregate.Devices is null)
        {
            throw new InvalidOperationException("Persisted device-registration data is incomplete.");
        }

        ValidateOwnerScopeId(requestedOwnerScopeId, nameof(requestedOwnerScopeId));
        if (!string.Equals(aggregate.OwnerScopeId, requestedOwnerScopeId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Persisted device-registration data did not match the requested owner scope.");
        }

        if (aggregate.Version < 0 || aggregate.Version != rowVersion)
        {
            throw new InvalidOperationException(
                "Persisted device-registration version metadata did not match the encrypted aggregate.");
        }

        if (aggregate.Challenges.Count > MaximumRetainedChallenges ||
            aggregate.Devices.Count > MaximumRegisteredDevices ||
            aggregate.Challenges.Select(item => item.ChallengeId).Distinct(StringComparer.Ordinal).Count() !=
            aggregate.Challenges.Count ||
            aggregate.Challenges.Select(item => item.DeviceId).Distinct(StringComparer.Ordinal).Count() !=
            aggregate.Challenges.Count ||
            aggregate.Devices.Select(item => item.DeviceId).Distinct(StringComparer.Ordinal).Count() !=
            aggregate.Devices.Count ||
            aggregate.Devices.Select(item => item.PublicKeyFingerprint).Distinct(StringComparer.Ordinal).Count() !=
            aggregate.Devices.Count)
        {
            throw new InvalidOperationException("Persisted device-registration collections violate bounded uniqueness.");
        }

        foreach (var challenge in aggregate.Challenges)
        {
            ValidateChallenge(challenge);
        }

        foreach (var device in aggregate.Devices)
        {
            ValidateDevice(device);
        }
    }

    /// <summary>Validates the privacy-scoped identifier used as the aggregate storage key.</summary>
    public static void ValidateOwnerScopeId(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (!value.StartsWith(OwnerScopePrefix, StringComparison.Ordinal) ||
            value.Length != OwnerScopePrefix.Length + 64 ||
            !IsLowerHex(value.AsSpan(OwnerScopePrefix.Length)))
        {
            throw new ArgumentException("The device-registration owner scope is invalid.", parameterName);
        }
    }

    private static void ValidateOwnerVersionGuards(DeviceRegistrationTransitionBatch transition)
    {
        var guards = ResolveOwnerVersionGuards(transition).ToArray();
        if (guards.Length is < 1 or > PrivacyHashingOptions.MaximumKeyCount ||
            guards.Any(guard => guard is null ||
                                guard.ExpectedVersion < 0 ||
                                guard.ExpectedVersion == long.MaxValue) ||
            guards.Select(guard => guard.OwnerScopeId).Distinct(StringComparer.Ordinal).Count() != guards.Length)
        {
            throw new ArgumentException(
                "A device-registration transition requires a bounded unique owner-version snapshot.",
                nameof(transition));
        }

        foreach (var guard in guards)
        {
            ValidateOwnerScopeId(guard.OwnerScopeId, nameof(transition));
        }

        if (!guards.Any(guard =>
                string.Equals(
                    guard.OwnerScopeId,
                    transition.Aggregate.OwnerScopeId,
                    StringComparison.Ordinal) &&
                guard.ExpectedVersion == transition.ExpectedVersion))
        {
            throw new ArgumentException(
                "A device-registration transition must guard its containing owner partition at the expected version.",
                nameof(transition));
        }
    }

    private static void ValidateChallengeDelta(
        DeviceRegistrationAggregate? previous,
        DeviceRegistrationTransitionBatch transition)
    {
        var aggregate = transition.Aggregate;
        var previousChallenges = previous?.Challenges.ToDictionary(
                challenge => challenge.ChallengeId,
                StringComparer.Ordinal) ??
            new Dictionary<string, DeviceRegistrationChallenge>(StringComparer.Ordinal);
        var currentChallenges = aggregate.Challenges.ToDictionary(
            challenge => challenge.ChallengeId,
            StringComparer.Ordinal);
        var addedChallenges = aggregate.Challenges
            .Where(challenge => !previousChallenges.ContainsKey(challenge.ChallengeId))
            .ToArray();

        if (addedChallenges.Length > 1 ||
            addedChallenges.Any(challenge =>
                challenge.State != DeviceRegistrationChallengeState.Pending ||
                challenge.ConsumedAtUtc is not null) ||
            (addedChallenges.Length == 1 && previousChallenges.Values.Any(challenge =>
                challenge.IssuedAtUtc > addedChallenges[0].IssuedAtUtc)))
        {
            throw new ArgumentException(
                "A transition can add only one new pending challenge in chronological order.",
                nameof(transition));
        }

        foreach (var previousChallenge in previousChallenges.Values)
        {
            if (!currentChallenges.TryGetValue(previousChallenge.ChallengeId, out var currentChallenge))
            {
                var addedChallenge = addedChallenges.SingleOrDefault();
                if (addedChallenge is null ||
                    (previousChallenge.State != DeviceRegistrationChallengeState.Consumed &&
                     previousChallenge.ExpiresAtUtc > addedChallenge.IssuedAtUtc))
                {
                    throw new ArgumentException(
                        "Only consumed or expired challenges can be pruned while issuing a new challenge.",
                        nameof(transition));
                }

                continue;
            }

            ValidateExistingChallengeTransition(previousChallenge, currentChallenge, transition);
        }
    }

    private static void ValidateExistingChallengeTransition(
        DeviceRegistrationChallenge previous,
        DeviceRegistrationChallenge current,
        DeviceRegistrationTransitionBatch transition)
    {
        if (!string.Equals(previous.DeviceId, current.DeviceId, StringComparison.Ordinal) ||
            !string.Equals(previous.FriendlyName, current.FriendlyName, StringComparison.Ordinal) ||
            previous.PlatformType != current.PlatformType ||
            !string.Equals(previous.ClientVersion, current.ClientVersion, StringComparison.Ordinal) ||
            !string.Equals(previous.KeyAlgorithm, current.KeyAlgorithm, StringComparison.Ordinal) ||
            !string.Equals(previous.PublicKey, current.PublicKey, StringComparison.Ordinal) ||
            !string.Equals(previous.PublicKeyFingerprint, current.PublicKeyFingerprint, StringComparison.Ordinal) ||
            !string.Equals(previous.SigningInputDigest, current.SigningInputDigest, StringComparison.Ordinal) ||
            previous.IssuedAtUtc != current.IssuedAtUtc ||
            previous.ExpiresAtUtc != current.ExpiresAtUtc ||
            (previous.State == DeviceRegistrationChallengeState.Consumed &&
             (current.State != DeviceRegistrationChallengeState.Consumed ||
              current.ConsumedAtUtc != previous.ConsumedAtUtc)) ||
            (previous.State == DeviceRegistrationChallengeState.Pending &&
             current.State == DeviceRegistrationChallengeState.Pending &&
             current.ConsumedAtUtc is not null))
        {
            throw new ArgumentException(
                "An existing registration challenge cannot change its proof material or reverse consumption.",
                nameof(transition));
        }
    }

    private static void ValidateDeviceDelta(
        DeviceRegistrationAggregate? previous,
        DeviceRegistrationTransitionBatch transition)
    {
        var aggregate = transition.Aggregate;
        var previousDevices = previous?.Devices.ToDictionary(
                device => device.DeviceId,
                StringComparer.Ordinal) ??
            new Dictionary<string, RegisteredDevice>(StringComparer.Ordinal);
        var currentDevices = aggregate.Devices.ToDictionary(
            device => device.DeviceId,
            StringComparer.Ordinal);
        var addedDevices = aggregate.Devices
            .Where(device => !previousDevices.ContainsKey(device.DeviceId))
            .ToArray();

        foreach (var previousDevice in previousDevices.Values)
        {
            if (!currentDevices.TryGetValue(previousDevice.DeviceId, out var currentDevice))
            {
                if (previousDevice.RevocationState != DeviceRevocationState.Revoked || addedDevices.Length == 0)
                {
                    throw new ArgumentException(
                        "Only a revoked device can be pruned while registering its replacement.",
                        nameof(transition));
                }

                continue;
            }

            ValidateExistingDeviceTransition(previousDevice, currentDevice, transition);
        }

        var expectedBindings = addedDevices
            .SelectMany(device => new[]
            {
                new DeviceRegistrationBinding(
                    DeviceBindingType,
                    device.DeviceId,
                    aggregate.OwnerScopeId,
                    device.DeviceId),
                new DeviceRegistrationBinding(
                    KeyBindingType,
                    device.PublicKeyFingerprint,
                    aggregate.OwnerScopeId,
                    device.DeviceId)
            })
            .ToHashSet();
        var requestedBindings = transition.NewBindings.ToHashSet();
        if (transition.NewBindings.Count != expectedBindings.Count ||
            requestedBindings.Count != transition.NewBindings.Count ||
            !requestedBindings.SetEquals(expectedBindings))
        {
            throw new ArgumentException(
                "Each newly registered device requires exactly its immutable device-id and public-key bindings.",
                nameof(transition));
        }
    }

    private static void ValidateExistingDeviceTransition(
        RegisteredDevice previous,
        RegisteredDevice current,
        DeviceRegistrationTransitionBatch transition)
    {
        if (!string.Equals(previous.FriendlyName, current.FriendlyName, StringComparison.Ordinal) ||
            previous.PlatformType != current.PlatformType ||
            !string.Equals(previous.ClientVersion, current.ClientVersion, StringComparison.Ordinal) ||
            !string.Equals(previous.PublicKey, current.PublicKey, StringComparison.Ordinal) ||
            !string.Equals(previous.PublicKeyFingerprint, current.PublicKeyFingerprint, StringComparison.Ordinal) ||
            !string.Equals(previous.KeyAlgorithm, current.KeyAlgorithm, StringComparison.Ordinal) ||
            previous.TrustState != current.TrustState ||
            previous.RegisteredAtUtc != current.RegisteredAtUtc ||
            previous.LastSeenAtUtc > current.LastSeenAtUtc ||
            (previous.RevocationState == DeviceRevocationState.Active &&
             current.RevocationState == DeviceRevocationState.Revoked &&
             current.RevokedAtUtc < previous.LastSeenAtUtc) ||
            (previous.RevocationState == DeviceRevocationState.Revoked &&
             (current.RevocationState != DeviceRevocationState.Revoked ||
              current.RevokedAtUtc != previous.RevokedAtUtc ||
              current.LastSeenAtUtc != previous.LastSeenAtUtc)))
        {
            throw new ArgumentException(
                "An existing registered device cannot change immutable identity or reverse revocation.",
                nameof(transition));
        }
    }

    private static void ValidateRegistrationCoupling(
        DeviceRegistrationAggregate? previous,
        DeviceRegistrationTransitionBatch transition)
    {
        var aggregate = transition.Aggregate;
        var previousChallenges = previous?.Challenges.ToDictionary(
                challenge => challenge.ChallengeId,
                StringComparer.Ordinal) ??
            new Dictionary<string, DeviceRegistrationChallenge>(StringComparer.Ordinal);
        var previousDeviceIds = previous?.Devices
            .Select(device => device.DeviceId)
            .ToHashSet(StringComparer.Ordinal) ?? new HashSet<string>(StringComparer.Ordinal);
        var newlyConsumedChallenges = aggregate.Challenges
            .Where(challenge =>
                challenge.State == DeviceRegistrationChallengeState.Consumed &&
                previousChallenges.TryGetValue(challenge.ChallengeId, out var previousChallenge) &&
                previousChallenge.State == DeviceRegistrationChallengeState.Pending)
            .ToDictionary(challenge => challenge.DeviceId, StringComparer.Ordinal);
        var addedDevices = aggregate.Devices
            .Where(device => !previousDeviceIds.Contains(device.DeviceId))
            .ToArray();

        if (newlyConsumedChallenges.Count != addedDevices.Length)
        {
            throw new ArgumentException(
                "Each consumed proof challenge must register exactly one matching device in the same transition.",
                nameof(transition));
        }

        foreach (var device in addedDevices)
        {
            if (!newlyConsumedChallenges.TryGetValue(device.DeviceId, out var challenge) ||
                !string.Equals(device.FriendlyName, challenge.FriendlyName, StringComparison.Ordinal) ||
                device.PlatformType != challenge.PlatformType ||
                !string.Equals(device.ClientVersion, challenge.ClientVersion, StringComparison.Ordinal) ||
                !string.Equals(device.KeyAlgorithm, challenge.KeyAlgorithm, StringComparison.Ordinal) ||
                !string.Equals(device.PublicKey, challenge.PublicKey, StringComparison.Ordinal) ||
                !string.Equals(
                    device.PublicKeyFingerprint,
                    challenge.PublicKeyFingerprint,
                    StringComparison.Ordinal) ||
                device.TrustState != DeviceTrustState.ProofOfPossessionVerified ||
                device.RevocationState != DeviceRevocationState.Active ||
                device.RegisteredAtUtc != challenge.ConsumedAtUtc ||
                device.LastSeenAtUtc != challenge.ConsumedAtUtc ||
                device.RevokedAtUtc is not null)
            {
                throw new ArgumentException(
                    "A registered device must exactly match the proof challenge consumed for it.",
                    nameof(transition));
            }
        }
    }

    private static void ValidateChallenge(DeviceRegistrationChallenge challenge)
    {
        if (challenge is null ||
            string.IsNullOrWhiteSpace(challenge.ChallengeId) ||
            string.IsNullOrWhiteSpace(challenge.DeviceId) ||
            string.IsNullOrWhiteSpace(challenge.FriendlyName) ||
            string.IsNullOrWhiteSpace(challenge.ClientVersion) ||
            string.IsNullOrWhiteSpace(challenge.KeyAlgorithm) ||
            string.IsNullOrWhiteSpace(challenge.PublicKey) ||
            string.IsNullOrWhiteSpace(challenge.PublicKeyFingerprint) ||
            !IsLowerHexDigest(challenge.SigningInputDigest) ||
            challenge.IssuedAtUtc.Offset != TimeSpan.Zero ||
            challenge.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            challenge.ExpiresAtUtc <= challenge.IssuedAtUtc ||
            !Enum.IsDefined(challenge.PlatformType) ||
            !Enum.IsDefined(challenge.State) ||
            (challenge.ConsumedAtUtc is { } consumedAtUtc && consumedAtUtc.Offset != TimeSpan.Zero) ||
            (challenge.State == DeviceRegistrationChallengeState.Pending && challenge.ConsumedAtUtc is not null) ||
            (challenge.State == DeviceRegistrationChallengeState.Consumed &&
             (challenge.ConsumedAtUtc is null ||
              challenge.ConsumedAtUtc < challenge.IssuedAtUtc ||
              challenge.ConsumedAtUtc >= challenge.ExpiresAtUtc)))
        {
            throw new InvalidOperationException("Persisted device-registration challenge data is invalid.");
        }
    }

    private static void ValidateDevice(RegisteredDevice device)
    {
        if (device is null ||
            string.IsNullOrWhiteSpace(device.DeviceId) ||
            string.IsNullOrWhiteSpace(device.FriendlyName) ||
            string.IsNullOrWhiteSpace(device.ClientVersion) ||
            string.IsNullOrWhiteSpace(device.KeyAlgorithm) ||
            string.IsNullOrWhiteSpace(device.PublicKey) ||
            string.IsNullOrWhiteSpace(device.PublicKeyFingerprint) ||
            !Enum.IsDefined(device.PlatformType) ||
            !Enum.IsDefined(device.TrustState) ||
            !Enum.IsDefined(device.RevocationState) ||
            device.RegisteredAtUtc.Offset != TimeSpan.Zero ||
            device.LastSeenAtUtc.Offset != TimeSpan.Zero ||
            device.LastSeenAtUtc < device.RegisteredAtUtc ||
            (device.RevokedAtUtc is { } revokedAtUtc && revokedAtUtc.Offset != TimeSpan.Zero) ||
            (device.RevocationState == DeviceRevocationState.Active && device.RevokedAtUtc is not null) ||
            (device.RevocationState == DeviceRevocationState.Revoked &&
             (device.RevokedAtUtc is null || device.RevokedAtUtc < device.LastSeenAtUtc)))
        {
            throw new InvalidOperationException("Persisted registered-device data is invalid.");
        }
    }

    private static void ValidateNewBinding(
        DeviceRegistrationBinding binding,
        DeviceRegistrationAggregate aggregate)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!string.Equals(binding.OwnerScopeId, aggregate.OwnerScopeId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A device binding did not match its owner aggregate.", nameof(binding));
        }

        var device = aggregate.Devices.SingleOrDefault(item =>
            string.Equals(item.DeviceId, binding.DeviceId, StringComparison.Ordinal));
        var valid = binding.BindingType switch
        {
            DeviceBindingType => device is not null &&
                                 string.Equals(binding.BindingId, device.DeviceId, StringComparison.Ordinal),
            KeyBindingType => device is not null &&
                              string.Equals(
                                  binding.BindingId,
                                  device.PublicKeyFingerprint,
                                  StringComparison.Ordinal),
            _ => false
        };
        if (!valid)
        {
            throw new ArgumentException(
                "A global device binding did not match a registered device in its owner aggregate.",
                nameof(binding));
        }
    }

    private static string BindingRecordKey(DeviceRegistrationBinding binding) =>
        $"{binding.BindingType}\0{binding.BindingId}";

    private static bool IsLowerHexDigest(string value) =>
        value is not null &&
        value.StartsWith(DigestPrefix, StringComparison.Ordinal) &&
        value.Length == DigestPrefix.Length + 64 &&
        IsLowerHex(value.AsSpan(DigestPrefix.Length));

    private static bool IsLowerHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if ((character < '0' || character > '9') &&
                (character < 'a' || character > 'f'))
            {
                return false;
            }
        }

        return true;
    }
}
