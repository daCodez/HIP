namespace HIP.Application.Rules;

public static class SupportedRuleFields
{
    public static readonly IReadOnlySet<string> Values = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "domain.ageDays",
        "domain.name",
        "domain.score",
        "domain.reputationScore",
        "url.usesShortener",
        "url.isObfuscated",
        "url.redirectCount",
        "url.hasKnownRisk",
        "sender.reputationScore",
        "sender.score",
        "content.riskScore",
        "content.containsUrgencyLanguage",
        "content.containsFinancialPromise",
        "identity.signatureValid"
    };
}
