namespace HIP.Domain.Review;

public enum ReviewType
{
    SuspiciousFinding = 0,
    GeneratedRule = 1,
    ReputationOverride = 2,
    Appeal = 3,
    FalsePositive = 4,
    SafetyReport = 5
}
