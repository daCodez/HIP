using System.Text.Json;
using FluentValidation;
using HIP.Application.Scoring;
using HIP.Application.SiteSafety;
using HIP.Domain.Risk;
using HIP.Domain.Scoring;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.Scoring;

/// <summary>
/// HIP-0306 compatibility gate for every mandatory scoring scenario in section 25.2 of the
/// master plan. Fixtures contain only synthetic, privacy-safe facts and never call a network provider.
/// </summary>
public sealed class HipMandatoryScoringRegressionTests
{
    public static IEnumerable<TestCaseData> FormalScenarios()
    {
        yield return Case("Trusted domain homepage", 95, 82, 0, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [], 93, RiskStatus.Trusted, RiskStatus.Trusted, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Trusted domain user-generated page", 95, 76, 0, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.TrustedParentDomain, HipScoringEvidenceFactType.UserGeneratedContent],
            69, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed,
            "score-cap:trusted-parent-user-generated");
        yield return Case("Unknown clean HTTPS site", 58, 60, 40, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.UnknownTarget, HipScoringEvidenceFactType.LimitedEvidence, HipScoringEvidenceFactType.HttpsTransportOnly],
            59, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Unknown login page", 58, 52, 30, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.UnknownTarget, HipScoringEvidenceFactType.LimitedEvidence],
            60, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Unknown payment page", 58, 45, 45, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.UnknownTarget, HipScoringEvidenceFactType.LimitedEvidence],
            53, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Executable download", 80, 58, 30, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.StrongExecutableDownloadRisk, HipScoringEvidenceFactType.IdentityWeak],
            39, RiskStatus.Suspicious, RiskStatus.Suspicious, HipTrustAssertionDisposition.Allowed,
            "score-cap:executable-weak-identity");
        yield return Case("Archive download", 70, 65, 25, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [], 70, RiskStatus.MostlyTrusted, RiskStatus.MostlyTrusted, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Shortened URL", 60, 55, 25, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [], 64, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Obfuscated URL", 60, 50, 35, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [], 59, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Known phishing hit", 90, 35, 80, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.ConfirmedPhishing],
            9, RiskStatus.Dangerous, RiskStatus.Dangerous, HipTrustAssertionDisposition.Allowed,
            "score-cap:confirmed-threat");
        yield return Case("Known malware hit", 90, 30, 90, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.ConfirmedMalware],
            9, RiskStatus.Dangerous, RiskStatus.Dangerous, HipTrustAssertionDisposition.Allowed,
            "score-cap:confirmed-threat");
        yield return Case("Provider timeout", 75, 65, 20, HipScoreConfidence.Low, HipEvidenceFreshness.Stale,
            [], 74, RiskStatus.MostlyTrusted, RiskStatus.LimitedTrustData,
            HipTrustAssertionDisposition.WithheldInsufficientEvidence, "confidence:low");
        yield return Case("Conflicting providers", 90, 90, 10, HipScoreConfidence.Conflicted, HipEvidenceFreshness.Fresh,
            [], 90, RiskStatus.Trusted, RiskStatus.Unknown,
            HipTrustAssertionDisposition.WithheldConflictingEvidence, "confidence:conflicted");
        yield return Case("Verified signature with risky content", 90, 45, 80, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [HipScoringEvidenceFactType.OriginSignatureVerified],
            52, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Many anonymous reports", 40, 45, 55, HipScoreConfidence.Medium, HipEvidenceFreshness.Fresh,
            [], 43, RiskStatus.Unknown, RiskStatus.Unknown, HipTrustAssertionDisposition.Allowed, null);
        yield return Case("Trusted reviewer report", 61, 60, 40, HipScoreConfidence.High, HipEvidenceFreshness.Fresh,
            [], 60, RiskStatus.LimitedTrustData, RiskStatus.LimitedTrustData, HipTrustAssertionDisposition.Allowed, null);
    }

    [TestCaseSource(nameof(FormalScenarios))]
    public void Mandatory_formal_scenario_has_stable_stages_and_presentation(Scenario scenario)
    {
        var result = Pipeline().Score(new HipScoringRequest(
            scenario.DomainTrustScore,
            scenario.PageTrustScore,
            scenario.ContentRiskScore,
            scenario.Confidence,
            scenario.Freshness,
            Reasons: [$"HIP-0306 scenario: {scenario.Name}."],
            Warnings: [],
            EvidenceContext: Evidence(scenario.Facts)));

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.EqualTo(scenario.DomainTrustScore));
            Assert.That(result.PageTrustScore, Is.EqualTo(scenario.PageTrustScore));
            Assert.That(result.ContentRiskScore, Is.EqualTo(scenario.ContentRiskScore));
            Assert.That(result.FinalHipScore, Is.EqualTo(scenario.FinalHipScore));
            Assert.That(result.FinalStatus, Is.EqualTo(scenario.FinalStatus));
            Assert.That(result.PresentationStatus, Is.EqualTo(scenario.PresentationStatus));
            Assert.That(result.Confidence, Is.EqualTo(scenario.Confidence));
            Assert.That(result.EvidenceFreshness, Is.EqualTo(scenario.Freshness));
            Assert.That(result.TrustAssertionDisposition, Is.EqualTo(scenario.Disposition));
            Assert.That(
                scenario.RequiredReasonCode is null ||
                result.ReasonEntries.Any(entry => entry.Code == scenario.RequiredReasonCode),
                Is.True,
                $"Scenario '{scenario.Name}' is missing reason code '{scenario.RequiredReasonCode}'.");
        });
    }

    [Test]
    public async Task Disabled_watch_and_approved_active_rules_preserve_the_enforcement_boundary()
    {
        var baseline = await Scanner().ScanAsync(Request("rule-baseline.example"), CancellationToken.None);
        var disabled = await ScanWithRule(Rule("Disabled rule", AdminSiteSafetyRuleStatus.Disabled, AdminSiteSafetyRuleMode.Enforced, approved: true));
        var watch = await ScanWithRule(Rule("Watch rule", AdminSiteSafetyRuleStatus.Active, AdminSiteSafetyRuleMode.WatchOnly, approved: true));
        var active = await ScanWithRule(Rule("Approved active rule", AdminSiteSafetyRuleStatus.Active, AdminSiteSafetyRuleMode.Enforced, approved: true));

        Assert.Multiple(() =>
        {
            Assert.That(disabled.Scoring!.FinalHipScore, Is.EqualTo(baseline.Scoring!.FinalHipScore));
            Assert.That(watch.Scoring!.FinalHipScore, Is.EqualTo(baseline.Scoring.FinalHipScore));
            Assert.That(watch.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(match => match.IsSimulationOnly));
            Assert.That(active.Scoring!.FinalHipScore, Is.LessThan(baseline.Scoring.FinalHipScore));
            Assert.That(active.Scoring.ReasonEntries.Select(entry => entry.Code), Does.Contain("rule:approved-active-rule"));
        });
    }

    [Test]
    public async Task Critical_override_is_rejected_without_approval_and_enforced_with_approval()
    {
        var unapproved = Rule(
            "Critical override",
            AdminSiteSafetyRuleStatus.Active,
            AdminSiteSafetyRuleMode.Enforced,
            approved: false,
            dangerous: true);
        var approved = Rule(
            "Critical override",
            AdminSiteSafetyRuleStatus.Active,
            AdminSiteSafetyRuleMode.Enforced,
            approved: true,
            dangerous: true);

        var validation = await new AdminSiteSafetyRuleValidator().ValidateAsync(unapproved);
        var result = await ScanWithRule(approved);

        Assert.Multiple(() =>
        {
            Assert.That(validation.IsValid, Is.False);
            Assert.That(validation.Errors, Has.Some.Property(nameof(FluentValidation.Results.ValidationFailure.ErrorMessage)).Contains("approval"));
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.Scoring!.FinalHipScore, Is.LessThanOrEqualTo(9));
            Assert.That(result.Scoring.EvidenceContext.Has(
                HipScoringEvidenceFactType.ApprovedCriticalRiskOverride), Is.True);
            Assert.That(result.Scoring.ReasonEntries.Select(entry => entry.Code),
                Does.Contain("score-cap:approved-critical-risk-override"));
        });
    }

    [Test]
    public async Task Built_in_confirmed_threat_is_not_mislabeled_as_an_admin_override()
    {
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://threat.example/",
                new SiteSafetyObservedSignals(KnownMalwareIndicator: true, TrustDataAvailable: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Scoring!.FinalHipScore, Is.LessThanOrEqualTo(9));
            Assert.That(result.Scoring.EvidenceContext.Has(HipScoringEvidenceFactType.ConfirmedMalware), Is.True);
            Assert.That(result.Scoring.EvidenceContext.Has(
                HipScoringEvidenceFactType.ApprovedCriticalRiskOverride), Is.False);
            Assert.That(result.Scoring.ReasonEntries.Select(entry => entry.Code),
                Does.Not.Contain("score-cap:approved-critical-risk-override"));
        });
    }

    private static TestCaseData Case(
        string name,
        int domainTrustScore,
        int pageTrustScore,
        int contentRiskScore,
        HipScoreConfidence confidence,
        HipEvidenceFreshness freshness,
        HipScoringEvidenceFactType[] facts,
        int finalHipScore,
        RiskStatus finalStatus,
        RiskStatus presentationStatus,
        HipTrustAssertionDisposition disposition,
        string? requiredReasonCode) =>
        new TestCaseData(new Scenario(
                name,
                domainTrustScore,
                pageTrustScore,
                contentRiskScore,
                confidence,
                freshness,
                facts,
                finalHipScore,
                finalStatus,
                presentationStatus,
                disposition,
                requiredReasonCode))
            .SetName($"HIP_0306_{name.Replace(' ', '_')}");

    private static HipScoringPipeline Pipeline() => new(new HipMandatoryScoreConstraintPolicy());

    private static HipScoringEvidenceContext Evidence(IEnumerable<HipScoringEvidenceFactType> facts) =>
        new(facts
            .Select(fact => new HipScoringEvidenceFact(fact, $"regression:{fact.ToString().ToLowerInvariant()}"))
            .ToArray());

    private static async Task<SiteSafetyScanResult> ScanWithRule(AdminSiteSafetyRule rule)
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(rule, CancellationToken.None);
        return await Scanner(repository).ScanAsync(Request("rule-baseline.example"), CancellationToken.None);
    }

    private static SiteSafetyScanner Scanner(IAdminSiteSafetyRuleRepository? repository = null) =>
        new(
            new SiteSafetyScanValidator(),
            NullLogger<SiteSafetyScanner>.Instance,
            [],
            new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero },
            repository);

    private static SiteSafetyScanRequest Request(string domain) =>
        new($"https://{domain}/", new SiteSafetyObservedSignals(TrustDataAvailable: true));

    private static AdminSiteSafetyRule Rule(
        string name,
        AdminSiteSafetyRuleStatus status,
        AdminSiteSafetyRuleMode mode,
        bool approved,
        bool dangerous = false) =>
        new(
            RuleId: name.ToLowerInvariant().Replace(' ', '-'),
            Name: name,
            Description: "HIP-0306 synthetic regression rule.",
            TargetType: AdminSiteSafetyRuleTargetType.PageContent,
            Conditions:
            [
                new AdminSiteSafetyRuleCondition(
                    "Domain",
                    AdminSiteSafetyRuleOperator.EndsWith,
                    JsonSerializer.SerializeToElement(".example"))
            ],
            Effects: new AdminSiteSafetyRuleEffects(
                IncreaseDownloadRisk: dangerous ? 100 : 75,
                AddReason: "HIP-0306 rule matched.",
                SetStatusOverride: dangerous ? SiteSafetyScanStatus.Dangerous : null),
            Severity: dangerous ? SiteSafetyRuleSeverity.Critical : SiteSafetyRuleSeverity.High,
            EvidenceQuality: SiteSafetyEvidenceQuality.Strong,
            Status: status,
            Mode: mode,
            CreatedBy: "regression-admin",
            CreatedAtUtc: new DateTimeOffset(2026, 7, 20, 0, 0, 0, TimeSpan.Zero),
            ApprovedBy: approved ? "independent-approver" : null,
            ApprovedAtUtc: approved ? new DateTimeOffset(2026, 7, 20, 0, 5, 0, TimeSpan.Zero) : null,
            Version: 1,
            PreviousVersionId: null,
            IsRollbackAvailable: false);

    public sealed record Scenario(
        string Name,
        int DomainTrustScore,
        int PageTrustScore,
        int ContentRiskScore,
        HipScoreConfidence Confidence,
        HipEvidenceFreshness Freshness,
        HipScoringEvidenceFactType[] Facts,
        int FinalHipScore,
        RiskStatus FinalStatus,
        RiskStatus PresentationStatus,
        HipTrustAssertionDisposition Disposition,
        string? RequiredReasonCode);
}
