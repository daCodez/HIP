using HIP.Domain.Protocol;

namespace HIP.Application.Security;

/// <summary>
/// Typed, fail-closed replay decision for a validated HIP envelope.
/// </summary>
public enum HipReplayProtectionStatus
{
    Unspecified = 0,
    Accepted,
    Expired,
    TimestampOutsideTolerance,
    ValidityWindowExceeded,
    DuplicateMessageId,
    DuplicateNonce,
    StateUnavailable
}

/// <summary>
/// Server-owned time limits applied before any distributed replay reservation.
/// </summary>
public sealed record HipReplayProtectionPolicy
{
    public static HipReplayProtectionPolicy Default { get; } = new(
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(5));

    public HipReplayProtectionPolicy(TimeSpan timestampTolerance, TimeSpan maximumValidityWindow)
    {
        if (timestampTolerance <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timestampTolerance),
                "Timestamp tolerance must be positive.");
        }

        if (maximumValidityWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumValidityWindow),
                "Maximum validity window must be positive.");
        }

        if (timestampTolerance.Ticks > TimeSpan.MaxValue.Ticks - maximumValidityWindow.Ticks)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumValidityWindow),
                "Maximum validity window plus timestamp tolerance must fit in a TimeSpan.");
        }

        TimestampTolerance = timestampTolerance;
        MaximumValidityWindow = maximumValidityWindow;
    }

    public TimeSpan TimestampTolerance { get; }

    public TimeSpan MaximumValidityWindow { get; }
}

/// <summary>
/// Result returned without exposing raw replay identifiers.
/// </summary>
public sealed record HipReplayProtectionResult(HipReplayProtectionStatus Status)
{
    public bool IsAccepted => Status == HipReplayProtectionStatus.Accepted;
}

public interface IHipReplayProtectionService
{
    Task<HipReplayProtectionResult> ValidateAndReserveAsync(
        HipProtocolEnvelope envelope,
        CancellationToken cancellationToken);
}

/// <summary>
/// Validates server-owned time policy, then reserves message and nonce state in deterministic order.
/// </summary>
public sealed class HipReplayProtectionService(
    IReplayMessageIdStore messageIdStore,
    IReplayNonceStore nonceStore,
    HipReplayProtectionPolicy policy,
    TimeProvider? timeProvider = null) : IHipReplayProtectionService
{
    private readonly IReplayMessageIdStore replayMessageIdStore =
        messageIdStore ?? throw new ArgumentNullException(nameof(messageIdStore));
    private readonly IReplayNonceStore replayNonceStore =
        nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
    private readonly HipReplayProtectionPolicy replayPolicy =
        policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<HipReplayProtectionResult> ValidateAndReserveAsync(
        HipProtocolEnvelope envelope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();

        var now = clock.GetUtcNow();
        if (envelope.ExpiresAtUtc <= now)
        {
            return Result(HipReplayProtectionStatus.Expired);
        }

        var issuanceSkew = envelope.IssuedAtUtc - now;
        if (issuanceSkew < -replayPolicy.TimestampTolerance ||
            issuanceSkew > replayPolicy.TimestampTolerance)
        {
            return Result(HipReplayProtectionStatus.TimestampOutsideTolerance);
        }

        if (envelope.ExpiresAtUtc - envelope.IssuedAtUtc > replayPolicy.MaximumValidityWindow)
        {
            return Result(HipReplayProtectionStatus.ValidityWindowExceeded);
        }

        // Retain reservations for the complete signed window plus clock tolerance. Using only
        // ExpiresAtUtc - this node's clock allows a faster node to expire shared replay state
        // while a slower, still-policy-compliant node can continue accepting the envelope.
        var reservationLifetime = envelope.ExpiresAtUtc - envelope.IssuedAtUtc +
            replayPolicy.TimestampTolerance;
        try
        {
            if (!await replayMessageIdStore.TryReserveAsync(
                    envelope.Issuer.Id,
                    envelope.MessageId,
                    reservationLifetime,
                    cancellationToken))
            {
                return Result(HipReplayProtectionStatus.DuplicateMessageId);
            }

            if (!await replayNonceStore.TryReserveAsync(
                    envelope.Issuer.Id,
                    envelope.Nonce,
                    reservationLifetime,
                    cancellationToken))
            {
                return Result(HipReplayProtectionStatus.DuplicateNonce);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipReplayProtectionStatus.StateUnavailable);
        }

        return envelope.ExpiresAtUtc <= clock.GetUtcNow()
            ? Result(HipReplayProtectionStatus.Expired)
            : Result(HipReplayProtectionStatus.Accepted);
    }

    private static HipReplayProtectionResult Result(HipReplayProtectionStatus status) => new(status);
}
