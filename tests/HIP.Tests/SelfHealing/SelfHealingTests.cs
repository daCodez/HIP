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

    /// <summary>
    /// Verifies the analysis service returns a review recommendation when any generated candidate needs approval.
    /// </summary>
    [Test]
    public void Analysis_service_recommends_review_when_generated_candidate_is_pending()
    {
        var cluster = Cluster("pending-cluster", RiskStatus.HighRisk);
        var detector = new StubPatternDetectionService([cluster]);
        var generator = new StubRuleCandidateGenerator(ApprovalStatus.Pending);
        var service = new SelfHealingAnalysisService(detector, generator);
        var findings = Findings(FindingType.ShortenedUrlAbuse, "pending.example", RiskStatus.HighRisk, 2);

        var result = service.Analyze(findings);

        Assert.Multiple(() =>
        {
            Assert.That(detector.LastFindings, Is.SameAs(findings));
            Assert.That(generator.GeneratedClusters.Single(), Is.EqualTo(cluster));
            Assert.That(result.Clusters.Single(), Is.EqualTo(cluster));
            Assert.That(result.GeneratedRuleCandidates.Single().ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
            Assert.That(result.Recommendation, Is.EqualTo("Review pending generated rules before enforcement."));
        });
    }

    /// <summary>
    /// Verifies the analysis service returns a no-approval recommendation when generated candidates are already safe to use.
    /// </summary>
    [Test]
    public void Analysis_service_recommends_no_approval_when_candidates_do_not_need_review()
    {
        var clusters = new[]
        {
            Cluster("first-cluster", RiskStatus.Caution),
            Cluster("second-cluster", RiskStatus.LimitedTrustData)
        };
        var detector = new StubPatternDetectionService(clusters);
        var generator = new StubRuleCandidateGenerator(ApprovalStatus.NotRequired);
        var service = new SelfHealingAnalysisService(detector, generator);

        var result = service.Analyze(Findings(FindingType.Unknown, "safe-generated.example", RiskStatus.Caution, 2));

        Assert.Multiple(() =>
        {
            Assert.That(generator.GeneratedClusters, Has.Count.EqualTo(2));
            Assert.That(result.Clusters, Has.Count.EqualTo(2));
            Assert.That(result.GeneratedRuleCandidates, Has.Count.EqualTo(2));
            Assert.That(result.GeneratedRuleCandidates.All(candidate => candidate.ApprovalStatus == ApprovalStatus.NotRequired), Is.EqualTo(true));
            Assert.That(result.Recommendation, Is.EqualTo("No high-impact generated rules require approval."));
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

    /// <summary>
    /// Builds a deterministic pattern cluster for analysis service orchestration tests.
    /// </summary>
    /// <param name="id">Cluster identifier.</param>
    /// <param name="risk">Average risk level for the cluster.</param>
    /// <returns>Pattern cluster with privacy-safe findings.</returns>
    private static PatternCluster Cluster(string id, RiskStatus risk) =>
        new(
            id,
            FindingType.ShortenedUrlAbuse,
            Findings(FindingType.ShortenedUrlAbuse, $"{id}.example", risk, 2),
            $"Detected {id}.",
            DateTimeOffset.Parse("2026-06-19T00:00:00Z"),
            DateTimeOffset.Parse("2026-06-19T00:05:00Z"),
            2,
            risk,
            0.85m);

    /// <summary>
    /// Builds a deterministic generated rule candidate for a pattern cluster.
    /// </summary>
    /// <param name="cluster">Cluster being converted to a candidate.</param>
    /// <param name="approvalStatus">Approval status to apply to the generated candidate.</param>
    /// <returns>Generated candidate for analysis service assertions.</returns>
    private static GeneratedRuleCandidate CandidateForCluster(PatternCluster cluster, ApprovalStatus approvalStatus) =>
        new(
            $"candidate-{cluster.ClusterId}",
            cluster.ClusterId,
            new TrustRule(
                $"rule-{cluster.ClusterId}",
                $"Rule for {cluster.ClusterId}",
                "Generated by the test candidate generator.",
                true,
                RuleMode.Watch,
                RuleSeverity.High,
                Array.Empty<RuleCondition>(),
                Array.Empty<RuleAction>(),
                approvalStatus == ApprovalStatus.Pending,
                true,
                "test",
                cluster.Summary,
                approvalStatus,
                90m,
                1),
            DateTimeOffset.Parse("2026-06-19T00:10:00Z"),
            "Generated for analysis service test.",
            new RuleSimulationResult(
                $"simulation-{cluster.ClusterId}",
                $"rule-{cluster.ClusterId}",
                true,
                1,
                1,
                0,
                1m,
                0m,
                0m,
                "Low",
                "Low",
                0.9m,
                "RequireApproval",
                "watch",
                "medium",
                Array.Empty<string>(),
                Array.Empty<RuleSimulationCaseResult>(),
                new RuleSimulationRollbackPlan(
                    $"rule-{cluster.ClusterId}",
                    null,
                    "Test rollback plan.",
                    true,
                    DateTimeOffset.Parse("2026-06-19T00:11:00Z")),
                Array.Empty<RuleSimulationCaseResult>()),
            0.9m,
            approvalStatus == ApprovalStatus.Pending ? RuleMode.Watch : RuleMode.Active,
            approvalStatus,
            new RuleRollbackPlan(
                null,
                "Test rollback plan.",
                $"rule-{cluster.ClusterId}",
                true,
                DateTimeOffset.Parse("2026-06-19T00:12:00Z")),
            approvalStatus == ApprovalStatus.Pending
                ? GeneratedRuleCandidateStatus.NeedsApproval
                : GeneratedRuleCandidateStatus.AutoEnforced);

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

    /// <summary>
    /// Test double that returns known clusters and records the findings it received.
    /// </summary>
    private sealed class StubPatternDetectionService(IReadOnlyCollection<PatternCluster> clusters) : IPatternDetectionService
    {
        /// <summary>
        /// Gets the last findings collection passed into the detector.
        /// </summary>
        public IReadOnlyCollection<SuspiciousFinding>? LastFindings { get; private set; }

        /// <inheritdoc />
        public IReadOnlyCollection<PatternCluster> DetectPatterns(IReadOnlyCollection<SuspiciousFinding> findings)
        {
            LastFindings = findings;
            return clusters;
        }
    }

    /// <summary>
    /// Test double that generates predictable candidates and records every cluster it processed.
    /// </summary>
    private sealed class StubRuleCandidateGenerator(ApprovalStatus approvalStatus) : IRuleCandidateGenerator
    {
        private readonly List<PatternCluster> generatedClusters = [];

        /// <summary>
        /// Gets the clusters that were converted into rule candidates.
        /// </summary>
        public IReadOnlyCollection<PatternCluster> GeneratedClusters => generatedClusters;

        /// <inheritdoc />
        public GeneratedRuleCandidate Generate(PatternCluster cluster)
        {
            generatedClusters.Add(cluster);
            return CandidateForCluster(cluster, approvalStatus);
        }
    }
}
