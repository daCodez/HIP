using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

/// <summary>
/// Privacy-safe sender profile row for the administrative reputation view.
/// </summary>
public sealed record AdminSenderProfileSummary(
    string SenderId,
    int CurrentScore,
    RiskStatus Status,
    int EventCount,
    int ConfirmedAbuseCount,
    int AccidentalIssueCount,
    DateTimeOffset LastUpdatedUtc);

/// <summary>
/// Privacy-safe reputation event shown for one selected sender.
/// </summary>
public sealed record AdminSenderReputationEvent(
    ReputationEventType EventType,
    ReputationEventSeverity Severity,
    int ScoreImpact,
    string Reason,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool IsConfirmed,
    bool IsAccidental);

/// <summary>
/// Detailed administrative projection for one stored sender profile.
/// </summary>
public sealed record AdminSenderProfileDetail(
    AdminSenderProfileSummary Profile,
    IReadOnlyCollection<string> Explanations,
    IReadOnlyCollection<AdminSenderReputationEvent> Events);

/// <summary>
/// Reads stored sender reputation without exposing reporter identity or private content.
/// </summary>
public interface IAdminSenderProfileService
{
    /// <summary>Lists the newest stored sender profiles.</summary>
    Task<IReadOnlyCollection<AdminSenderProfileSummary>> ListAsync(CancellationToken cancellationToken);

    /// <summary>Gets one stored sender profile and its bounded reputation history.</summary>
    Task<AdminSenderProfileDetail?> GetAsync(string senderId, CancellationToken cancellationToken);
}

/// <summary>
/// Builds bounded sender-profile projections from durable reputation profiles and events.
/// </summary>
public sealed class AdminSenderProfileService(
    IReputationProfileRepository profileRepository,
    IReputationEventRepository eventRepository) : IAdminSenderProfileService
{
    private const int MaximumProfiles = 100;
    private const int MaximumEvents = 50;

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AdminSenderProfileSummary>> ListAsync(
        CancellationToken cancellationToken) =>
        (await profileRepository.ListAsync(ReputationSubjectType.Sender, cancellationToken).ConfigureAwait(false))
            .OrderByDescending(profile => profile.LastUpdatedUtc)
            .ThenBy(profile => profile.TargetId, StringComparer.OrdinalIgnoreCase)
            .Take(MaximumProfiles)
            .Select(ToSummary)
            .ToArray();

    /// <inheritdoc />
    public async Task<AdminSenderProfileDetail?> GetAsync(
        string senderId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(senderId))
        {
            return null;
        }

        var profile = await profileRepository
            .GetAsync(ReputationSubjectType.Sender, senderId, cancellationToken)
            .ConfigureAwait(false);
        if (profile is null)
        {
            return null;
        }

        var events = await eventRepository
            .ListAsync(ReputationSubjectType.Sender, profile.TargetId, cancellationToken)
            .ConfigureAwait(false);
        return new AdminSenderProfileDetail(
            ToSummary(profile),
            profile.Explanations.ToArray(),
            events
                .OrderByDescending(item => item.CreatedAtUtc)
                .Take(MaximumEvents)
                .Select(item => new AdminSenderReputationEvent(
                    item.EventType,
                    item.Severity,
                    item.ScoreImpact,
                    item.Reason,
                    item.CreatedAtUtc,
                    item.ExpiresAtUtc,
                    item.IsConfirmed,
                    item.IsAccidental))
                .ToArray());
    }

    private static AdminSenderProfileSummary ToSummary(ReputationProfile profile) =>
        new(
            profile.TargetId,
            profile.CurrentScore,
            profile.Status,
            profile.EventCount,
            profile.ConfirmedAbuseCount,
            profile.AccidentalIssueCount,
            profile.LastUpdatedUtc);
}
