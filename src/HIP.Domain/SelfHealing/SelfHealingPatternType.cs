namespace HIP.Domain.SelfHealing;

public enum SelfHealingPatternType
{
    RepeatedShortenerAbuse = 0,
    BrokenUpUrlPattern = 1,
    ObfuscatedUrlPattern = 2,
    RewardBaitPattern = 3,
    UrgencyScamPattern = 4,
    NewDomainCluster = 5,
    RepeatedSenderReports = 6,
    SuspiciousRedirectPattern = 7
}
