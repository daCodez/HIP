namespace HIP.Domain.SelfHealing;

public enum FindingType
{
    Unknown = 0,
    ShortenedUrlAbuse = 1,
    ObfuscatedUrl = 2,
    NewDomainWithRisk = 3,
    RepeatedSuspiciousSender = 4,
    SuspiciousRedirectChain = 5,
    FinancialScamLanguage = 6,
    PhishingLanguage = 7,
    KnownBadDomain = 8
}
