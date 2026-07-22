using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;
using HIP.Application.ServiceClients;
using Microsoft.Extensions.Options;

namespace HIP.Infrastructure.Security;

/// <summary>
/// Enforces service-client pre-verification work budgets through distributed privacy-safe counters.
/// </summary>
public sealed class DistributedServiceClientAuthenticationAttemptLimiter
    : IServiceClientAuthenticationAttemptLimiter
{
    private const string RedisKeyPrefix = "hip:v1:service-client-auth:";
    private const string HmacDomain = "HIP-Service-Client-Authentication-Attempt-Limiter-v1";

    private readonly IAtomicFixedWindowCounterStore counterStore;
    private readonly IReadOnlyList<byte[]> privacyHmacKeys;
    private readonly TimeSpan window;
    private readonly int sourceAttemptLimit;
    private readonly int sourceAndClientAttemptLimit;

    /// <summary>Creates a fail-closed limiter over shared distributed state.</summary>
    public DistributedServiceClientAuthenticationAttemptLimiter(
        IAtomicFixedWindowCounterStore counterStore,
        PrivacyHashingOptions privacyHashingOptions,
        IOptions<ServiceClientAuthenticationAttemptLimiterOptions> options)
    {
        ArgumentNullException.ThrowIfNull(counterStore);
        ArgumentNullException.ThrowIfNull(privacyHashingOptions);
        ArgumentNullException.ThrowIfNull(options);

        var resolvedOptions = options.Value;
        var validationFailure = resolvedOptions.Validate();
        if (validationFailure is not null)
        {
            throw new OptionsValidationException(
                ServiceClientAuthenticationAttemptLimiterOptions.SectionName,
                typeof(ServiceClientAuthenticationAttemptLimiterOptions),
                [validationFailure]);
        }

        this.counterStore = counterStore;
        privacyHmacKeys = ServiceClientLimiterPrivacyKeyRing.Resolve(privacyHashingOptions);
        window = resolvedOptions.Window;
        sourceAttemptLimit = resolvedOptions.SourceAttemptLimit;
        sourceAndClientAttemptLimit = resolvedOptions.SourceAndClientAttemptLimit;
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryAcquireAsync(
        string sourceIdentity,
        string apparentClientId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateExactIdentity(
            sourceIdentity,
            ServiceClientAuthenticationAttemptLimiterOptions.MaximumSourceIdentityUtf8Bytes,
            nameof(sourceIdentity));
        ValidateExactIdentity(
            apparentClientId,
            ServiceClientAuthenticationAttemptLimiterOptions.MaximumApparentClientIdUtf8Bytes,
            nameof(apparentClientId));

        // Count the broad source partition first. Even attempts rejected by the tighter pair budget consume this
        // ceiling, so rotating fabricated client identifiers cannot multiply expensive verifier work.
        var sourceAllowed = true;
        foreach (var privacyHmacKey in privacyHmacKeys)
        {
            var sourceCount = await counterStore.IncrementAsync(
                BuildRedisKey(privacyHmacKey, "source", sourceIdentity),
                window,
                cancellationToken);
            EnsureValidCount(sourceCount);
            sourceAllowed &= sourceCount <= sourceAttemptLimit;
        }

        if (!sourceAllowed)
        {
            return false;
        }

        var sourceAndClientAllowed = true;
        foreach (var privacyHmacKey in privacyHmacKeys)
        {
            var sourceAndClientCount = await counterStore.IncrementAsync(
                BuildRedisKey(privacyHmacKey, "source-client", sourceIdentity, apparentClientId),
                window,
                cancellationToken);
            EnsureValidCount(sourceAndClientCount);
            sourceAndClientAllowed &= sourceAndClientCount <= sourceAndClientAttemptLimit;
        }

        return sourceAndClientAllowed;
    }

    private static string BuildRedisKey(
        byte[] privacyHmacKey,
        string partition,
        params string[] exactParts)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, privacyHmacKey);
        AppendLengthPrefixed(hmac, HmacDomain);
        AppendLengthPrefixed(hmac, partition);
        foreach (var part in exactParts)
        {
            AppendLengthPrefixed(hmac, part);
        }

        return $"{RedisKeyPrefix}{partition}:{Convert.ToHexString(hmac.GetHashAndReset()).ToLowerInvariant()}";
    }

    private static void AppendLengthPrefixed(IncrementalHash hmac, string value)
    {
        var valueBytes = Encoding.UTF8.GetBytes(value);
        Span<byte> lengthBytes = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lengthBytes, valueBytes.Length);
        hmac.AppendData(lengthBytes);
        hmac.AppendData(valueBytes);
    }

    private static void ValidateExactIdentity(string value, int maximumUtf8Bytes, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (Encoding.UTF8.GetByteCount(value) > maximumUtf8Bytes ||
            value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException(
                "Service-client authentication limiter identity is not in a bounded exact form.",
                parameterName);
        }
    }

    private static void EnsureValidCount(long count)
    {
        if (count < 1)
        {
            throw new InvalidOperationException(
                "Distributed service-client authentication counter returned an invalid value.");
        }
    }
}
