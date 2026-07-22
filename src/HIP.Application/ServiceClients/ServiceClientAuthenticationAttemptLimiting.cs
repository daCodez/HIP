namespace HIP.Application.ServiceClients;

/// <summary>
/// Atomically increments one distributed counter whose expiry is established by the first increment.
/// </summary>
/// <remarks>
/// Callers must supply privacy-safe opaque keys. Implementations must perform the increment and first-expiry
/// assignment as one atomic operation so every HIP instance observes the same fixed window.
/// </remarks>
public interface IAtomicFixedWindowCounterStore
{
    /// <summary>
    /// Increments one counter and returns its new value. The first increment starts the relative TTL window.
    /// </summary>
    ValueTask<long> IncrementAsync(
        string key,
        TimeSpan window,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Applies the distributed pre-verification work budget for one apparent service-client authentication attempt.
/// </summary>
public interface IServiceClientAuthenticationAttemptLimiter
{
    /// <summary>
    /// Attempts to reserve both the source-wide and source-plus-apparent-client budgets.
    /// </summary>
    /// <param name="sourceIdentity">
    /// A bounded, already-canonical exact source identity, such as the ordinal remote IP representation.
    /// </param>
    /// <param name="apparentClientId">
    /// The bounded exact client identifier presented before credential verification. It need not identify a real client.
    /// </param>
    /// <param name="cancellationToken">Token used to cancel distributed state access.</param>
    /// <returns>True only when both distributed budgets allow the attempt.</returns>
    ValueTask<bool> TryAcquireAsync(
        string sourceIdentity,
        string apparentClientId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Bounds deliberately expensive service-client secret verification before any password derivation work begins.
/// </summary>
/// <remarks>
/// Defaults permit at most thirty attempts against one apparent client and one hundred twenty total attempts from one
/// source during a one-minute TTL window. The source ceiling prevents attackers from evading the tighter budget by
/// rotating fabricated client identifiers. Limits apply to all pre-verification attempts, including successful calls;
/// ordinary endpoint rate limits remain a separate, route-specific control.
/// </remarks>
public sealed class ServiceClientAuthenticationAttemptLimiterOptions
{
    public const string SectionName = "HipSecurity:ServiceClientAuthenticationAttempts";
    public const int MaximumSourceIdentityUtf8Bytes = 256;
    public const int MaximumApparentClientIdUtf8Bytes = 128;
    public const int MaximumAttemptLimit = 10_000;

    private static readonly TimeSpan MinimumWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaximumWindow = TimeSpan.FromHours(1);

    /// <summary>Gets or sets the relative TTL established by the first increment.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Gets or sets the maximum pre-verification attempts from one exact source during the window.</summary>
    public int SourceAttemptLimit { get; set; } = 120;

    /// <summary>
    /// Gets or sets the maximum attempts for one exact source and apparent-client pair during the window.
    /// </summary>
    public int SourceAndClientAttemptLimit { get; set; } = 30;

    /// <summary>Returns a stable validation failure message, or null when the options are safe.</summary>
    public string? Validate()
    {
        if (Window < MinimumWindow || Window > MaximumWindow)
        {
            return "Service-client authentication attempt window must be between one second and one hour.";
        }

        if (SourceAttemptLimit is < 1 or > MaximumAttemptLimit)
        {
            return $"Service-client source attempt limit must be between 1 and {MaximumAttemptLimit}.";
        }

        if (SourceAndClientAttemptLimit is < 1 or > MaximumAttemptLimit ||
            SourceAndClientAttemptLimit > SourceAttemptLimit)
        {
            return "Service-client source-and-client attempt limit must be positive and cannot exceed the source limit.";
        }

        return null;
    }
}
