namespace HIP.ApiService.Application.Abstractions;

public interface IReplayAssessmentService
{
    ReplayAssessment RegisterReplay(string identityId, string messageId);
}

public sealed record ReplayAssessment(
    string Classification,
    int RecentReplayCount,
    bool ShouldPenalize);
