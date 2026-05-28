using HIP.Domain.Scoring;

namespace HIP.Domain.Safety;

public sealed record SafetyResult(
    Uri OriginalUri,
    Uri? FinalDestination,
    SafetyAction Action,
    HipScoreResult ScoreResult,
    string Reason,
    bool CanContinueAnyway);
