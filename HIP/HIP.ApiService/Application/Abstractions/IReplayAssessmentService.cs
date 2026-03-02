namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Classifies replay patterns for adaptive mitigation decisions.
/// </summary>
public interface IReplayAssessmentService
{
    /// <summary>
    /// Registers a replay event and returns the latest classification.
    /// </summary>
    /// <param name="identityId">Identity that triggered the replay.</param>
    /// <param name="messageId">Replayed message id.</param>
    /// <returns>Replay assessment snapshot after registration.</returns>
    ReplayAssessment RegisterReplay(string identityId, string messageId);
}

/// <summary>
/// Represents replay severity and whether reputation penalties should apply.
/// </summary>
/// <param name="Classification">Human/machine friendly replay classification label.</param>
/// <param name="RecentReplayCount">Number of recent replay observations for the identity.</param>
/// <param name="ShouldPenalize">Indicates whether caller should apply a security penalty.</param>
public sealed record ReplayAssessment(
    string Classification,
    int RecentReplayCount,
    bool ShouldPenalize);
