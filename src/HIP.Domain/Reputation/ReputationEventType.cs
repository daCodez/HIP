namespace HIP.Domain.Reputation;

public enum ReputationEventType
{
    PositiveReport,
    AccidentalIssue,
    SuspiciousReport,
    RepeatedAbuse,
    ConfirmedMaliciousBehavior,
    FalsePositiveCorrection,
    ManualCorrection
}
