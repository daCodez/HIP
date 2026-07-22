using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;
using HIP.Application.ServiceClients;
using Microsoft.Extensions.Options;

namespace HIP.Infrastructure.Security;

/// <summary>Enforces privileged service-client mutation budgets through privacy-safe distributed counters.</summary>
public sealed class DistributedServiceClientManagementMutationLimiter
    : IServiceClientManagementMutationLimiter
{
    private const string RedisKeyPrefix = "hip:v1:service-client-management-mutation:actor:";
    private const string HmacDomain = "HIP-Service-Client-Management-Mutation-Limiter-v1";

    private readonly IAtomicFixedWindowCounterStore counterStore;
    private readonly IReadOnlyList<byte[]> privacyHmacKeys;
    private readonly TimeSpan window;
    private readonly int actorMutationLimit;

    /// <summary>Creates a fail-closed limiter over shared distributed state.</summary>
    public DistributedServiceClientManagementMutationLimiter(
        IAtomicFixedWindowCounterStore counterStore,
        PrivacyHashingOptions privacyHashingOptions,
        IOptions<ServiceClientManagementMutationLimiterOptions> options)
    {
        ArgumentNullException.ThrowIfNull(counterStore);
        ArgumentNullException.ThrowIfNull(privacyHashingOptions);
        ArgumentNullException.ThrowIfNull(options);

        var resolvedOptions = options.Value;
        var validationFailure = resolvedOptions.Validate();
        if (validationFailure is not null)
        {
            throw new OptionsValidationException(
                ServiceClientManagementMutationLimiterOptions.SectionName,
                typeof(ServiceClientManagementMutationLimiterOptions),
                [validationFailure]);
        }

        this.counterStore = counterStore;
        privacyHmacKeys = ServiceClientLimiterPrivacyKeyRing.Resolve(privacyHashingOptions);
        window = resolvedOptions.Window;
        actorMutationLimit = resolvedOptions.ActorMutationLimit;
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryAcquireAsync(
        string actorId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsCanonicalActorId(actorId))
        {
            throw new ArgumentException(
                "Service-client management limiter actor is not in a bounded exact form.",
                nameof(actorId));
        }

        var allowed = true;
        foreach (var privacyHmacKey in privacyHmacKeys)
        {
            var count = await counterStore.IncrementAsync(
                BuildRedisKey(privacyHmacKey, actorId),
                window,
                cancellationToken);
            if (count < 1)
            {
                throw new InvalidOperationException(
                    "Distributed service-client management counter returned an invalid value.");
            }

            allowed &= count <= actorMutationLimit;
        }

        return allowed;
    }

    private static string BuildRedisKey(byte[] privacyHmacKey, string actorId)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, privacyHmacKey);
        AppendLengthPrefixed(hmac, HmacDomain);
        AppendLengthPrefixed(hmac, actorId);
        return RedisKeyPrefix + Convert.ToHexString(hmac.GetHashAndReset()).ToLowerInvariant();
    }

    private static bool IsCanonicalActorId(string actorId) =>
        actorId is { Length: > 0 and <= ServiceClientManagementMutationLimiterOptions.MaximumActorIdentityUtf8Bytes } &&
        !char.IsWhiteSpace(actorId[0]) &&
        !char.IsWhiteSpace(actorId[^1]) &&
        Encoding.UTF8.GetByteCount(actorId) <=
        ServiceClientManagementMutationLimiterOptions.MaximumActorIdentityUtf8Bytes &&
        !actorId.Any(character => char.IsControl(character) || char.IsSurrogate(character));

    private static void AppendLengthPrefixed(IncrementalHash hmac, string value)
    {
        var valueBytes = Encoding.UTF8.GetBytes(value);
        Span<byte> lengthBytes = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lengthBytes, valueBytes.Length);
        hmac.AppendData(lengthBytes);
        hmac.AppendData(valueBytes);
    }
}
