namespace HIP.Reputation.Domain;

public static class ReputationConstants
{
    public const int BaseScore = 50;
    public const int AcceptanceRatioWeight = 25;
    public const int FeedbackScoreWeight = 15;
    public const int TrustOverTimeWeight = 5;
    public const int PenaltyWeight = 30;

    // Time-decay controls for event-driven reputation penalties.
    public const double EventPenaltyHalfLifeDays = 14;
    public const int ReplayAbusePenaltyUnits = 30;
    public const int PolicyBlockedPenaltyUnits = 10;
    public const int ReplayBenignPenaltyUnits = 0;
}
