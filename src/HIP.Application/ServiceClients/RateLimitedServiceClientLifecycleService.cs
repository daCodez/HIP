using System.Text;

namespace HIP.Application.ServiceClients;

/// <summary>
/// Applies one shared, fail-closed actor budget before service-client mutation work reaches credential or storage code.
/// </summary>
public sealed class RateLimitedServiceClientLifecycleService(
    ServiceClientLifecycleService inner,
    IServiceClientManagementMutationLimiter mutationLimiter) : IServiceClientLifecycleService
{
    private readonly ServiceClientLifecycleService inner =
        inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly IServiceClientManagementMutationLimiter mutationLimiter =
        mutationLimiter ?? throw new ArgumentNullException(nameof(mutationLimiter));

    /// <inheritdoc />
    public async Task<ServiceClientCreateResult> CreateAsync(
        string actorId,
        string ownerId,
        CreateServiceClientRequest request,
        CancellationToken cancellationToken)
    {
        var rejectedOutcome = await ReserveMutationAsync(actorId, cancellationToken).ConfigureAwait(false);
        if (rejectedOutcome is { } outcome)
        {
            ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.Create, outcome);
            return new ServiceClientCreateResult(outcome, Message(outcome));
        }

        return await inner.CreateAsync(actorId, ownerId, request, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<ServiceClientListResult> ListAsync(
        string ownerId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken) =>
        inner.ListAsync(ownerId, cursor, pageSize, cancellationToken);

    /// <inheritdoc />
    public async Task<ServiceClientRotationResult> RotateCredentialAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken)
    {
        var rejectedOutcome = await ReserveMutationAsync(actorId, cancellationToken).ConfigureAwait(false);
        if (rejectedOutcome is { } outcome)
        {
            ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.RotateCredential, outcome);
            return new ServiceClientRotationResult(outcome, Message(outcome));
        }

        return await inner.RotateCredentialAsync(
                actorId,
                ownerId,
                clientId,
                expectedAggregateVersion,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ServiceClientRevocationResult> RevokeAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken)
    {
        var rejectedOutcome = await ReserveMutationAsync(actorId, cancellationToken).ConfigureAwait(false);
        if (rejectedOutcome is { } outcome)
        {
            ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.Revoke, outcome);
            return new ServiceClientRevocationResult(outcome, Message(outcome));
        }

        return await inner.RevokeAsync(
                actorId,
                ownerId,
                clientId,
                expectedAggregateVersion,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<ServiceClientLifecycleOutcome?> ReserveMutationAsync(
        string actorId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsCanonicalActorId(actorId))
        {
            return ServiceClientLifecycleOutcome.InvalidRequest;
        }

        try
        {
            return await mutationLimiter.TryAcquireAsync(actorId, cancellationToken).ConfigureAwait(false)
                ? null
                : ServiceClientLifecycleOutcome.Throttled;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return ServiceClientLifecycleOutcome.Unavailable;
        }
    }

    private static bool IsCanonicalActorId(string actorId) =>
        actorId is { Length: > 0 and <= ServiceClientManagementMutationLimiterOptions.MaximumActorIdentityUtf8Bytes } &&
        !char.IsWhiteSpace(actorId[0]) &&
        !char.IsWhiteSpace(actorId[^1]) &&
        Encoding.UTF8.GetByteCount(actorId) <=
        ServiceClientManagementMutationLimiterOptions.MaximumActorIdentityUtf8Bytes &&
        !actorId.Any(character => char.IsControl(character) || char.IsSurrogate(character));

    private static string Message(ServiceClientLifecycleOutcome outcome) => outcome switch
    {
        ServiceClientLifecycleOutcome.InvalidRequest => ServiceClientLifecycleMessages.InvalidRequest,
        ServiceClientLifecycleOutcome.Throttled => ServiceClientLifecycleMessages.Throttled,
        _ => ServiceClientLifecycleMessages.Unavailable
    };
}
