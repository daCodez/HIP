namespace HIP.Domain.Reputation;

public enum ReporterTrustLevel
{
    Anonymous = 0,
    Verified = 1,
    Trusted = 2,
    Moderator = 3,
    Admin = 4,
    KnownFalseReporter = 5
}
