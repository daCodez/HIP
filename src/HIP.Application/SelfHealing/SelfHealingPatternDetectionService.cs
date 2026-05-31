using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed class SelfHealingPatternDetectionService(
    IPatternDetectionService patternDetectionService,
    IRuleCandidateGenerator ruleCandidateGenerator,
    IGeneratedRuleCandidateRepository candidateRepository) : ISelfHealingPatternDetectionService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public async Task<SelfHealingPatternDetectionResult> DetectAsync(
        IReadOnlyCollection<SuspiciousFinding> findings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(findings);
        EnsurePrivacySafe(findings);

        var clusters = patternDetectionService.DetectPatterns(findings);
        var suggestions = new List<SelfHealingPatternSuggestion>();

        foreach (var cluster in clusters)
        {
            suggestions.Add(await GenerateRuleAsync(cluster, cancellationToken));
        }

        var recommendation = suggestions.Any(suggestion => suggestion.ApprovalRequired)
            ? "Review generated self-healing suggestions before enforcement."
            : "No generated high-impact suggestions require approval.";

        return new SelfHealingPatternDetectionResult(clusters, suggestions, recommendation);
    }

    public async Task<SelfHealingPatternSuggestion> GenerateRuleAsync(
        PatternCluster cluster,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cluster);
        EnsurePrivacySafe(cluster.Findings);

        var candidate = ruleCandidateGenerator.Generate(cluster);
        await candidateRepository.SaveAsync(candidate, cancellationToken);
        return ToSuggestion(cluster, candidate);
    }

    public Task<IReadOnlyCollection<GeneratedRuleCandidate>> ListSuggestionsAsync(CancellationToken cancellationToken) =>
        candidateRepository.ListAsync(cancellationToken);

    public async Task<GeneratedRuleCandidate?> ApproveSuggestionAsync(string candidateId, CancellationToken cancellationToken)
    {
        var candidate = await candidateRepository.GetAsync(candidateId, cancellationToken);
        if (candidate is null)
        {
            return null;
        }

        var approved = candidate with
        {
            ApprovalStatus = ApprovalStatus.Approved,
            Status = candidate.RecommendedMode == RuleMode.Active
                ? GeneratedRuleCandidateStatus.AutoEnforced
                : GeneratedRuleCandidateStatus.WatchMode,
            ProposedRule = candidate.ProposedRule with { ApprovalStatus = ApprovalStatus.Approved }
        };

        await candidateRepository.SaveAsync(approved, cancellationToken);
        return approved;
    }

    public async Task<GeneratedRuleCandidate?> RejectSuggestionAsync(string candidateId, CancellationToken cancellationToken)
    {
        var candidate = await candidateRepository.GetAsync(candidateId, cancellationToken);
        if (candidate is null)
        {
            return null;
        }

        var rejected = candidate with
        {
            ApprovalStatus = ApprovalStatus.Rejected,
            Status = GeneratedRuleCandidateStatus.Rejected,
            ProposedRule = candidate.ProposedRule with { ApprovalStatus = ApprovalStatus.Rejected }
        };

        await candidateRepository.SaveAsync(rejected, cancellationToken);
        return rejected;
    }

    private static SelfHealingPatternSuggestion ToSuggestion(PatternCluster cluster, GeneratedRuleCandidate candidate) =>
        new(
            cluster.ClusterId,
            MapPatternType(cluster),
            Math.Round(candidate.ConfidenceScore * 100m, 2),
            cluster.FindingCount,
            cluster.Summary,
            cluster.AverageRiskLevel,
            JsonSerializer.Serialize(new
            {
                generatedBy = "SelfHealingPatternDetector",
                evidenceSummary = cluster.Summary,
                rule = candidate.ProposedRule
            }, JsonOptions),
            candidate.ProposedRule.SimulationRequired,
            candidate.ProposedRule.RequiresApproval,
            candidate.RecommendedMode,
            candidate.CandidateId);

    private static SelfHealingPatternType MapPatternType(PatternCluster cluster)
    {
        if (cluster.PatternType == FindingType.BrokenUpUrl ||
            cluster.Findings.Any(finding =>
                finding.Reason.Contains("broken-up", StringComparison.OrdinalIgnoreCase) ||
                finding.PrivacySafeEvidence.Values.Any(value => value.Contains("broken-up", StringComparison.OrdinalIgnoreCase))))
        {
            return SelfHealingPatternType.BrokenUpUrlPattern;
        }

        return cluster.PatternType switch
        {
            FindingType.ShortenedUrlAbuse => SelfHealingPatternType.RepeatedShortenerAbuse,
            FindingType.ObfuscatedUrl => SelfHealingPatternType.ObfuscatedUrlPattern,
            FindingType.RewardBait or FindingType.FinancialScamLanguage => SelfHealingPatternType.RewardBaitPattern,
            FindingType.UrgencyScam or FindingType.PhishingLanguage => SelfHealingPatternType.UrgencyScamPattern,
            FindingType.NewDomainWithRisk => SelfHealingPatternType.NewDomainCluster,
            FindingType.RepeatedSuspiciousSender => SelfHealingPatternType.RepeatedSenderReports,
            FindingType.SuspiciousRedirectChain => SelfHealingPatternType.SuspiciousRedirectPattern,
            _ => SelfHealingPatternType.ObfuscatedUrlPattern
        };
    }

    private static void EnsurePrivacySafe(IEnumerable<SuspiciousFinding> findings)
    {
        foreach (var finding in findings)
        {
            if (finding.PrivacySafeEvidence.Keys.Any(IsPrivateContentKey) ||
                finding.PrivacySafeEvidence.Values.Any(IsPrivateContentValue))
            {
                throw new ArgumentException("Self-healing pattern detection accepts only privacy-safe evidence.");
            }
        }
    }

    private static bool IsPrivateContentKey(string key) =>
        key.Contains("privateChatLog", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("messageBody", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("password", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("token", StringComparison.OrdinalIgnoreCase);

    private static bool IsPrivateContentValue(string value) =>
        value.Contains("private chat log", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("password:", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("token=", StringComparison.OrdinalIgnoreCase);
}
