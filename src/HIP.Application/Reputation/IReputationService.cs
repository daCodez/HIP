using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

public interface IReputationService
{
    Task<ReputationProfile> GetProfileAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken);

    Task<ReputationProfile> ApplyEventAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken);

    Task<ReputationProfile> SubmitFeedbackAsync(ReputationFeedbackRequest feedback, CancellationToken cancellationToken);

    Task<ReputationProfile> RecalculateAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken);

    int CalculateScore(IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc);

    RiskStatus CalculateStatus(int score);

    IReadOnlyCollection<string> Explain(ReputationProfile profile, IReadOnlyCollection<ReputationEvent> events);
}
