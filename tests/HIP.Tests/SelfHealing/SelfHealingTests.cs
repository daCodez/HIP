using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;

namespace HIP.Tests.SelfHealing;

public sealed class SelfHealingTests
{
    [Test]
    public void Pattern_detection_groups_similar_findings()
    {
        var service = new PatternDetectionService();
        var findings = Findings(FindingType.ShortenedUrlAbuse, "suspicious.example", RiskStatus.HighRisk, 3);

        var clusters = service.DetectPatterns(findings);

        Assert.That(clusters, Has.Count.EqualTo(1));
        Assert.That(clusters.Single().FindingCount, Is.EqualTo(3));
        Assert.That(clusters.Single().PatternType, Is.EqualTo(FindingType.ShortenedUrlAbuse));
    }

    [Test]
    public void Pattern_detection_ignores_unrelated_single_findings()
    {
        var service = new PatternDetectionService();
        var findings = new[]
        {
            Finding("one", FindingType.ShortenedUrlAbuse, "one.example", RiskStatus.HighRisk),
            Finding("two", FindingType.ObfuscatedUrl, "two.example", RiskStatus.HighRisk)
        };

        var clusters = service.DetectPatterns(findings);

        Assert.That(clusters, Is.Empty);
    }

    [Test]
    public void Rule_candidate_is_generated_from_cluster()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.ProposedRule.RuleId, Does.StartWith("self-healing-shortenedurlabuse"));
        Assert.That(candidate.ProposedRule.CreatedBy, Is.EqualTo("HIP Self-Healing Engine"));
        Assert.That(candidate.ProposedRule.Conditions.Any(condition => condition.Field == "url.usesShortener"), Is.True);
    }

    [Test]
    public void Generated_rule_requires_simulation()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.ProposedRule.SimulationRequired, Is.True);
    }

    [Test]
    public void Generated_rule_automatically_runs_simulation()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.SimulationResult.TotalTestCases, Is.GreaterThan(0));
        Assert.That(candidate.SimulationResult.PassedCount, Is.GreaterThan(0));
    }

    [Test]
    public void Confidence_score_comes_from_simulation_result()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.ConfidenceScore, Is.EqualTo(candidate.SimulationResult.ConfidenceScore));
        Assert.That(candidate.ProposedRule.ConfidenceScore, Is.EqualTo(candidate.SimulationResult.ConfidenceScore * 100m));
    }

    [Test]
    public void High_risk_generated_rule_requires_approval()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.ProposedRule.RequiresApproval, Is.True);
        Assert.That(candidate.ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
        Assert.That(candidate.RecommendedMode, Is.EqualTo(RuleMode.Watch));
    }

    [Test]
    public void Critical_generated_rule_is_forced_into_watch_mode()
    {
        var candidate = GenerateCandidate(FindingType.KnownBadDomain, RiskStatus.Critical);

        Assert.That(candidate.ProposedRule.RequiresApproval, Is.True);
        Assert.That(candidate.RecommendedMode, Is.EqualTo(RuleMode.Watch));
        Assert.That(candidate.ProposedRule.Mode, Is.EqualTo(RuleMode.Watch));
    }

    [Test]
    public void Low_risk_safe_rule_can_be_active()
    {
        var candidate = GenerateCandidate(FindingType.Unknown, RiskStatus.Caution);

        Assert.That(candidate.ProposedRule.RequiresApproval, Is.False);
        Assert.That(candidate.ApprovalStatus, Is.EqualTo(ApprovalStatus.NotRequired));
        Assert.That(candidate.RecommendedMode, Is.EqualTo(RuleMode.Active));
        Assert.That(candidate.ProposedRule.Actions.All(action => action.Type is RuleActionType.AddReason or RuleActionType.MarkForSimulation), Is.True);
    }

    [Test]
    public void Rollback_plan_is_created()
    {
        var candidate = GenerateCandidate(FindingType.ShortenedUrlAbuse, RiskStatus.HighRisk);

        Assert.That(candidate.RollbackPlan.CanRollback, Is.True);
        Assert.That(candidate.RollbackPlan.AffectedRuleId, Is.EqualTo(candidate.ProposedRule.RuleId));
        Assert.That(candidate.RollbackPlan.RollbackReason, Does.Contain("false positives"));
    }

    [Test]
    public void Privacy_safe_finding_model_does_not_require_private_chat_logs()
    {
        var finding = Finding("privacy", FindingType.PhishingLanguage, "safe-evidence.example", RiskStatus.Caution);

        Assert.That(finding.PrivacySafeEvidence.Keys, Does.Not.Contain("privateChatLog"));
        Assert.That(typeof(SuspiciousFinding).GetProperties().Select(property => property.Name), Does.Not.Contain("PrivateChatLog"));
    }

    private static GeneratedRuleCandidate GenerateCandidate(FindingType type, RiskStatus risk)
    {
        var patternDetection = new PatternDetectionService();
        var cluster = patternDetection.DetectPatterns(Findings(type, "suspicious.example", risk, 3)).Single();
        return Generator().Generate(cluster);
    }

    private static RuleCandidateGenerator Generator()
    {
        var matching = new RuleMatchingEngine();
        var applier = new RuleActionApplier(matching);
        return new RuleCandidateGenerator(new RuleSimulationService(applier), new RuleRollbackService());
    }

    private static IReadOnlyCollection<SuspiciousFinding> Findings(FindingType type, string domain, RiskStatus risk, int count) =>
        Enumerable.Range(1, count)
            .Select(index => Finding($"finding-{index}", type, domain, risk, DateTimeOffset.UtcNow.AddMinutes(-index)))
            .ToArray();

    private static SuspiciousFinding Finding(string id, FindingType type, string domain, RiskStatus risk) =>
        Finding(id, type, domain, risk, DateTimeOffset.UtcNow);

    private static SuspiciousFinding Finding(string id, FindingType type, string domain, RiskStatus risk, DateTimeOffset detectedAtUtc) =>
        new(
            id,
            type,
            domain,
            $"sha256:{id}",
            "browser-extension",
            risk,
            "Privacy-safe suspicious URL signal.",
            detectedAtUtc,
            FindingSourceType.BrowserExtension,
            ReporterTrustLevel.High,
            new Dictionary<string, string>
            {
                ["evidenceType"] = "anonymized-url-signal",
                ["containsPrivateChatLog"] = "false"
            });
}
