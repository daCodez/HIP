namespace HIP.Application.ServiceClients;

/// <summary>Reserves a shared actor-scoped budget before privileged service-client mutation work.</summary>
public interface IServiceClientManagementMutationLimiter
{
    /// <summary>
    /// Returns true only when the exact trusted actor may perform one additional create, rotation, or revocation.
    /// </summary>
    ValueTask<bool> TryAcquireAsync(
        string actorId,
        CancellationToken cancellationToken = default);
}

/// <summary>Bounds privileged service-client mutations with one distributed fixed window per exact actor.</summary>
public sealed class ServiceClientManagementMutationLimiterOptions
{
    public const string SectionName = "HipSecurity:ServiceClientManagementMutations";
    public const int MaximumActorIdentityUtf8Bytes = 512;
    public const int MaximumMutationLimit = 10_000;

    private static readonly TimeSpan MinimumWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaximumWindow = TimeSpan.FromHours(1);

    /// <summary>Gets or sets the relative TTL established by an actor's first mutation.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Gets or sets the maximum combined create, rotate, and revoke operations per actor and window.</summary>
    public int ActorMutationLimit { get; set; } = 10;

    /// <summary>Returns a stable validation failure, or null when the options are safely bounded.</summary>
    public string? Validate()
    {
        if (Window < MinimumWindow || Window > MaximumWindow)
        {
            return "Service-client management mutation window must be between one second and one hour.";
        }

        return ActorMutationLimit is < 1 or > MaximumMutationLimit
            ? $"Service-client actor mutation limit must be between 1 and {MaximumMutationLimit}."
            : null;
    }
}

/// <summary>
/// Safe application-only fallback used when a runtime host has not supplied distributed mutation state.
/// </summary>
public sealed class UnavailableServiceClientManagementMutationLimiter
    : IServiceClientManagementMutationLimiter
{
    /// <inheritdoc />
    public ValueTask<bool> TryAcquireAsync(
        string actorId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromException<bool>(new InvalidOperationException(
            "Distributed service-client management mutation limiting is unavailable."));
    }
}
