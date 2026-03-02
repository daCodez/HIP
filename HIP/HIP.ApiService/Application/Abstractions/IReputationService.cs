namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Provides reputation scoring and security-event ingestion.
/// </summary>
public interface IReputationService
{
    /// <summary>
    /// Gets the current score for a given identity.
    /// </summary>
    /// <param name="identityId">Identity id to score.</param>
    /// <param name="cancellationToken">Cancellation token for the lookup operation.</param>
    /// <returns>Current numeric reputation score.</returns>
    Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a stable factor breakdown for score explainability/debugging.
    /// </summary>
    Task<ReputationScoreBreakdown> GetScoreBreakdownAsync(string identityId, CancellationToken cancellationToken);

    /// <summary>
    /// Records a security-relevant event that may influence reputation over time.
    /// </summary>
    /// <param name="identityId">Identity id that the event applies to.</param>
    /// <param name="eventType">Machine-readable event type.</param>
    /// <param name="cancellationToken">Cancellation token for the write operation.</param>
    Task RecordSecurityEventAsync(string identityId, string eventType, CancellationToken cancellationToken);
}

/// <summary>
/// Explainable reputation-score factors.
/// </summary>
public sealed record ReputationScoreBreakdown(
    string IdentityId,
    int Score,
    double AcceptanceComponent,
    double FeedbackComponent,
    double TrustComponent,
    double AggregatePenaltyComponent,
    double EventPenaltyComponent,
    int EventCount,
    DateTimeOffset ComputedAtUtc);
