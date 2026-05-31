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

    [Test]
    public async Task Repeated_shortener_abuse_pattern_outputs_suggestion()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.ShortenedUrlAbuse, "short.example", RiskStatus.HighRisk, 3);

        var result = await service.DetectAsync(findings, CancellationToken.None);
        var suggestion = result.Suggestions.Single();

        Assert.Multiple(() =>
        {
            Assert.That(suggestion.PatternType, Is.EqualTo(SelfHealingPatternType.RepeatedShortenerAbuse));
            Assert.That(suggestion.EvidenceCount, Is.EqualTo(3));
            Assert.That(suggestion.SuggestedRuleJson, Does.Contain("generatedBy"));
            Assert.That(suggestion.SuggestedRuleJson, Does.Contain("SelfHealingPatternDetector"));
        });
    }

    [Test]
    public async Task Broken_up_url_pattern_is_detected_from_privacy_safe_evidence()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.BrokenUpUrl, "broken.example", RiskStatus.HighRisk, 2);

        var result = await service.DetectAsync(findings, CancellationToken.None);

        Assert.That(result.Suggestions.Single().PatternType, Is.EqualTo(SelfHealingPatternType.BrokenUpUrlPattern));
    }

    [Test]
    public async Task Obfuscated_url_pattern_is_detected()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.ObfuscatedUrl, "obfuscated.example", RiskStatus.HighRisk, 2);

        var result = await service.DetectAsync(findings, CancellationToken.None);

        Assert.That(result.Suggestions.Single().PatternType, Is.EqualTo(SelfHealingPatternType.ObfuscatedUrlPattern));
    }

    [Test]
    public void Pattern_detection_rejects_private_evidence()
    {
        var service = PatternSuggestionService();
        var findings = new[]
        {
            FindingWithEvidence("private-1", FindingType.ShortenedUrlAbuse, "private.example", RiskStatus.HighRisk, new Dictionary<string, string>
            {
                ["messageBody"] = "private chat log password: secret"
            }),
            FindingWithEvidence("private-2", FindingType.ShortenedUrlAbuse, "private.example", RiskStatus.HighRisk, new Dictionary<string, string>
            {
                ["evidenceType"] = "shortened-url"
            })
        };

        var exception = Assert.ThrowsAsync<ArgumentException>(() => service.DetectAsync(findings, CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("privacy-safe"));
    }

    [Test]
    public async Task Generated_suggestion_requires_simulation_and_high_impact_watch_mode()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.SuspiciousRedirectChain, "redirect.example", RiskStatus.Dangerous, 3);

        var suggestion = (await service.DetectAsync(findings, CancellationToken.None)).Suggestions.Single();

        Assert.Multiple(() =>
        {
            Assert.That(suggestion.SimulationRequired, Is.True);
            Assert.That(suggestion.ApprovalRequired, Is.True);
            Assert.That(suggestion.RecommendedMode, Is.EqualTo(RuleMode.Watch));
            Assert.That(suggestion.Summary, Does.Contain("findings"));
        });
    }

    [Test]
    public async Task Medium_or_high_risk_suggestion_requires_approval()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.RewardBait, "reward.example", RiskStatus.HighRisk, 2);

        var suggestion = (await service.DetectAsync(findings, CancellationToken.None)).Suggestions.Single();

        Assert.That(suggestion.ApprovalRequired, Is.True);
    }

    [Test]
    public async Task Low_risk_suggestion_can_recommend_active_mode_after_simulation_passes()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.Unknown, "unknown.example", RiskStatus.Caution, 2);

        var suggestion = (await service.DetectAsync(findings, CancellationToken.None)).Suggestions.Single();

        Assert.Multiple(() =>
        {
            Assert.That(suggestion.ApprovalRequired, Is.False);
            Assert.That(suggestion.RecommendedMode, Is.EqualTo(RuleMode.Active));
            Assert.That(suggestion.SimulationRequired, Is.True);
        });
    }

    [Test]
    public async Task Suggestions_can_be_listed_approved_and_rejected()
    {
        var service = PatternSuggestionService();
        var findings = PrivacySafeFindings(FindingType.ShortenedUrlAbuse, "approval.example", RiskStatus.HighRisk, 2);
        var suggestion = (await service.DetectAsync(findings, CancellationToken.None)).Suggestions.Single();

        var listed = await service.ListSuggestionsAsync(CancellationToken.None);
        var approved = await service.ApproveSuggestionAsync(suggestion.CandidateId, CancellationToken.None);
        var rejected = await service.RejectSuggestionAsync(suggestion.CandidateId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(listed, Has.Count.EqualTo(1));
            Assert.That(approved!.ApprovalStatus, Is.EqualTo(ApprovalStatus.Approved));
            Assert.That(rejected!.ApprovalStatus, Is.EqualTo(ApprovalStatus.Rejected));
            Assert.That(rejected.Status, Is.EqualTo(GeneratedRuleCandidateStatus.Rejected));
        });
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

    private static SelfHealingPatternDetectionService PatternSuggestionService() =>
        new(new PatternDetectionService(), Generator(), new InMemoryGeneratedRuleCandidateRepository());

    private static IReadOnlyCollection<SuspiciousFinding> Findings(FindingType type, string domain, RiskStatus risk, int count) =>
        Enumerable.Range(1, count)
            .Select(index => Finding($"finding-{index}", type, domain, risk, DateTimeOffset.UtcNow.AddMinutes(-index)))
            .ToArray();

    private static IReadOnlyCollection<SuspiciousFinding> PrivacySafeFindings(FindingType type, string domain, RiskStatus risk, int count) =>
        Enumerable.Range(1, count)
            .Select(index => FindingWithEvidence($"safe-finding-{index}", type, domain, risk, new Dictionary<string, string>
            {
                ["evidenceType"] = type == FindingType.BrokenUpUrl ? "broken-up-url-signal" : "anonymized-url-signal",
                ["containsPrivateContent"] = "false"
            }))
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

    private static SuspiciousFinding FindingWithEvidence(
        string id,
        FindingType type,
        string domain,
        RiskStatus risk,
        IReadOnlyDictionary<string, string> evidence) =>
        new(
            id,
            type,
            domain,
            $"sha256:{id}",
            "browser-extension",
            risk,
            type == FindingType.BrokenUpUrl ? "Broken-up URL pattern." : "Privacy-safe suspicious URL signal.",
            DateTimeOffset.UtcNow,
            FindingSourceType.BrowserExtension,
            ReporterTrustLevel.High,
            evidence);
}
