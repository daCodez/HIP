using HIP.Application.Rules;
using HIP.Domain.Risk;

namespace HIP.Application.Simulation;

public static class RuleSimulationSeedData
{
    public static IReadOnlyCollection<RuleSimulationTestCase> DefaultCases() =>
    [
        Case("Known safe link", 1200, false, false, 0, 90, 88, 5, false, null, null),
        Case("Known scam link", 4, true, false, 3, 20, 12, 80, true, RiskStatus.HighRisk, true),
        Case("Shortened link", 8, true, false, 1, 55, 35, 20, true, RiskStatus.HighRisk, true),
        Case("Broken-up link", 45, false, true, 0, 50, 45, 40, false, null, null),
        Case("Obfuscated link", 90, false, true, 2, 45, 38, 65, false, null, null),
        Case("Fake chat message", 12, true, false, 1, 35, 32, 75, true, RiskStatus.HighRisk, true),
        Case("Anonymized finding", 20, true, false, 4, 40, 30, 55, true, RiskStatus.HighRisk, true),
        Case("Browser page link", 900, false, false, 0, 70, 72, 10, false, null, null),
        Case("Email-style message", 30, true, false, 1, 42, 38, 72, false, null, null),
        Case("File metadata placeholder", 180, false, false, 0, 65, 68, 30, false, null, null)
    ];

    private static RuleSimulationTestCase Case(
        string name,
        int domainAgeDays,
        bool usesShortener,
        bool isObfuscated,
        int redirectCount,
        int senderScore,
        int domainScore,
        int contentRiskScore,
        bool expectedMatch,
        RiskStatus? expectedRiskLevel,
        bool? expectedSafetyPageRouting) =>
        new(
            name,
            new FactSet(new Dictionary<string, object?>
            {
                ["url"] = usesShortener ? "https://bit.ly/example" : "https://example.com/path",
                ["domain.name"] = domainScore <= 40 ? "risky.example" : "example.com",
                ["domain.ageDays"] = domainAgeDays,
                ["domain.score"] = domainScore,
                ["domain.reputationScore"] = domainScore,
                ["url.usesShortener"] = usesShortener,
                ["url.isObfuscated"] = isObfuscated,
                ["url.redirectCount"] = redirectCount,
                ["url.hasKnownRisk"] = domainScore <= 40,
                ["sender.score"] = senderScore,
                ["sender.reputationScore"] = senderScore,
                ["content.riskScore"] = contentRiskScore,
                ["content.containsUrgencyLanguage"] = contentRiskScore >= 60,
                ["content.containsFinancialPromise"] = contentRiskScore >= 70,
                ["identity.signatureValid"] = false
            }),
            expectedMatch,
            expectedRiskLevel,
            expectedSafetyPageRouting);
}
