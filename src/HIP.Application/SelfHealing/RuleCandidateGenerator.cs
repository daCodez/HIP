using System.Text.Json;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed class RuleCandidateGenerator(
    IRuleSimulationService simulationService,
    IRuleRollbackService rollbackService) : IRuleCandidateGenerator
{
    private const string EngineName = "HIP Self-Healing Engine";

    public GeneratedRuleCandidate Generate(PatternCluster cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);

        var domain = ClusterDomain(cluster);
        var severity = MapSeverity(cluster.AverageRiskLevel);
        var safeActionOnly = IsLowRiskSafeCandidate(cluster);
        var requiresApproval = RequiresApproval(cluster.AverageRiskLevel, safeActionOnly);
        var recommendedMode = requiresApproval ? RuleMode.Watch : RuleMode.Active;
        var actions = BuildActions(cluster, safeActionOnly).ToArray();
        var conditions = BuildConditions(cluster, domain).ToArray();
        var ruleId = $"self-healing-{Slug(cluster.PatternType.ToString())}-{Slug(domain)}";

        if (cluster.AverageRiskLevel == RiskStatus.Critical)
        {
            requiresApproval = true;
            recommendedMode = RuleMode.Watch;
        }

        var proposedRule = new TrustRule(
            ruleId,
            $"Self-healing: {cluster.PatternType} on {domain}",
            cluster.Summary,
            true,
            recommendedMode,
            severity,
            conditions,
            actions,
            requiresApproval,
            true,
            EngineName,
            $"Generated from pattern cluster {cluster.ClusterId}: {cluster.Summary}",
            requiresApproval ? ApprovalStatus.Pending : ApprovalStatus.NotRequired,
            0m,
            1);

        var simulationRule = proposedRule with { Mode = RuleMode.Active };
        var simulation = simulationService.Simulate(simulationRule, BuildSimulationCases(cluster, domain, safeActionOnly));
        proposedRule = proposedRule with { ConfidenceScore = simulation.ConfidenceScore * 100m };
        var status = ClassifyStatus(requiresApproval, recommendedMode);
        var rollback = rollbackService.CreatePlan(ruleId, "Disable generated self-healing rule and restore previous rule version if false positives or user harm are detected.");

        return new GeneratedRuleCandidate(
            $"candidate-{ruleId}",
            cluster.ClusterId,
            proposedRule,
            DateTimeOffset.UtcNow,
            proposedRule.CreatedReason,
            simulation,
            simulation.ConfidenceScore,
            recommendedMode,
            proposedRule.ApprovalStatus,
            rollback,
            status);
    }

    private static IEnumerable<RuleCondition> BuildConditions(PatternCluster cluster, string domain)
    {
        yield return new RuleCondition("domain.name", RuleOperator.Equals, JsonSerializer.SerializeToElement(domain));

        switch (cluster.PatternType)
        {
            case FindingType.ShortenedUrlAbuse:
                yield return new RuleCondition("url.usesShortener", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
            case FindingType.ObfuscatedUrl:
                yield return new RuleCondition("url.isObfuscated", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
            case FindingType.SuspiciousRedirectChain:
                yield return new RuleCondition("url.redirectCount", RuleOperator.GreaterThanOrEqual, JsonSerializer.SerializeToElement(3));
                break;
            case FindingType.KnownBadDomain:
                yield return new RuleCondition("url.hasKnownRisk", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
            case FindingType.RepeatedSuspiciousSender:
                yield return new RuleCondition("sender.reputationScore", RuleOperator.LessThanOrEqual, JsonSerializer.SerializeToElement(35));
                break;
            case FindingType.FinancialScamLanguage:
                yield return new RuleCondition("content.containsFinancialPromise", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
            case FindingType.PhishingLanguage:
                yield return new RuleCondition("content.containsUrgencyLanguage", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
            case FindingType.NewDomainWithRisk:
                yield return new RuleCondition("domain.ageDays", RuleOperator.LessThan, JsonSerializer.SerializeToElement(30));
                break;
            case FindingType.Unknown:
            default:
                yield return new RuleCondition("url.hasKnownRisk", RuleOperator.Equals, JsonSerializer.SerializeToElement(true));
                break;
        }
    }

    private static IEnumerable<RuleAction> BuildActions(PatternCluster cluster, bool safeActionOnly)
    {
        yield return new RuleAction(RuleActionType.AddReason, JsonSerializer.SerializeToElement(cluster.Summary));

        if (safeActionOnly)
        {
            yield return new RuleAction(RuleActionType.MarkForSimulation, JsonSerializer.SerializeToElement(true));
            yield break;
        }

        yield return new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement(cluster.AverageRiskLevel.ToString()));
        yield return new RuleAction(RuleActionType.RouteToSafetyPage, JsonSerializer.SerializeToElement(true));

        if (cluster.AverageRiskLevel is RiskStatus.Dangerous or RiskStatus.Critical)
        {
            yield return new RuleAction(RuleActionType.RequireReview, JsonSerializer.SerializeToElement(true));
        }
    }

    private static IReadOnlyCollection<RuleSimulationTestCase> BuildSimulationCases(PatternCluster cluster, string domain, bool safeActionOnly)
    {
        var matchingFacts = new Dictionary<string, object?>
        {
            ["domain.name"] = domain,
            ["domain.ageDays"] = 7,
            ["url.usesShortener"] = cluster.PatternType == FindingType.ShortenedUrlAbuse,
            ["url.isObfuscated"] = cluster.PatternType == FindingType.ObfuscatedUrl,
            ["url.redirectCount"] = cluster.PatternType == FindingType.SuspiciousRedirectChain ? 4 : 0,
            ["url.hasKnownRisk"] = cluster.PatternType is FindingType.KnownBadDomain or FindingType.Unknown,
            ["sender.reputationScore"] = cluster.PatternType == FindingType.RepeatedSuspiciousSender ? 20 : 80,
            ["content.containsUrgencyLanguage"] = cluster.PatternType == FindingType.PhishingLanguage,
            ["content.containsFinancialPromise"] = cluster.PatternType == FindingType.FinancialScamLanguage,
            ["identity.signatureValid"] = false
        };

        var safeFacts = new Dictionary<string, object?>
        {
            ["domain.name"] = "known-safe.example",
            ["domain.ageDays"] = 1400,
            ["url.usesShortener"] = false,
            ["url.isObfuscated"] = false,
            ["url.redirectCount"] = 0,
            ["url.hasKnownRisk"] = false,
            ["sender.reputationScore"] = 90,
            ["content.containsUrgencyLanguage"] = false,
            ["content.containsFinancialPromise"] = false,
            ["identity.signatureValid"] = true
        };

        return
        [
            new("Generated pattern should match", new FactSet(matchingFacts), true, safeActionOnly ? null : cluster.AverageRiskLevel, safeActionOnly ? null : true),
            new("Known safe facts should not match", new FactSet(safeFacts), false, null, null)
        ];
    }

    private static bool IsLowRiskSafeCandidate(PatternCluster cluster) =>
        (cluster.AverageRiskLevel is RiskStatus.Unknown or RiskStatus.Caution) &&
        cluster.PatternType is FindingType.Unknown;

    private static bool RequiresApproval(RiskStatus riskLevel, bool safeActionOnly) =>
        !safeActionOnly && riskLevel is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    private static RuleSeverity MapSeverity(RiskStatus riskLevel) => riskLevel switch
    {
        RiskStatus.Critical => RuleSeverity.Critical,
        RiskStatus.Dangerous => RuleSeverity.Dangerous,
        RiskStatus.HighRisk => RuleSeverity.HighRisk,
        RiskStatus.Caution => RuleSeverity.Caution,
        RiskStatus.Trusted or RiskStatus.ProbablySafe => RuleSeverity.Low,
        _ => RuleSeverity.Low
    };

    private static GeneratedRuleCandidateStatus ClassifyStatus(bool requiresApproval, RuleMode recommendedMode)
    {
        if (requiresApproval)
        {
            return GeneratedRuleCandidateStatus.NeedsApproval;
        }

        return recommendedMode == RuleMode.Active
            ? GeneratedRuleCandidateStatus.AutoEnforced
            : GeneratedRuleCandidateStatus.WatchMode;
    }

    private static string ClusterDomain(PatternCluster cluster) =>
        cluster.Findings.FirstOrDefault()?.Domain.Trim().ToLowerInvariant() ?? "unknown";

    private static string Slug(string value)
    {
        var characters = value.Trim().ToLowerInvariant().Select(character =>
            char.IsLetterOrDigit(character) ? character : '-');
        return string.Join('-', new string(characters.ToArray()).Split('-', StringSplitOptions.RemoveEmptyEntries));
    }
}
