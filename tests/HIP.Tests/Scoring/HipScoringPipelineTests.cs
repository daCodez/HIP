using HIP.Application;
using HIP.Application.Scoring;
using HIP.Domain.Risk;
using HIP.Domain.Scoring;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Scoring;

/// <summary>Locks the versioned HIP-0301 score-layer semantics to the master specification.</summary>
public sealed class HipScoringPipelineTests
{
    [Test]
    public void AddHipApplication_registers_the_formal_pipeline_and_mandatory_constraints()
    {
        var services = new ServiceCollection();
        services.AddHipApplication();
        using var provider = services.BuildServiceProvider();

        Assert.Multiple(() =>
        {
            Assert.That(provider.GetRequiredService<IHipScoringPipeline>(), Is.TypeOf<HipScoringPipeline>());
            Assert.That(provider.GetRequiredService<IHipScoreConstraintPolicy>(), Is.TypeOf<HipMandatoryScoreConstraintPolicy>());
        });
    }

    [Test]
    public void Pipeline_uses_the_documented_domain_page_and_inverse_content_weights()
    {
        var result = Pipeline().Score(Request(
            domainTrustScore: 80,
            pageTrustScore: 70,
            contentRiskScore: 20));

        Assert.Multiple(() =>
        {
            Assert.That(result.ModelVersion, Is.EqualTo(HipScoringResult.CurrentModelVersion));
            Assert.That(result.DomainTrustScore, Is.EqualTo(80));
            Assert.That(result.PageTrustScore, Is.EqualTo(70));
            Assert.That(result.ContentRiskScore, Is.EqualTo(20));
            Assert.That(result.FinalHipScore, Is.EqualTo(77));
            Assert.That(result.FinalStatus, Is.EqualTo(RiskStatus.MostlyTrusted));
            Assert.That(result.DomainTrust, Is.TypeOf<HipDomainTrustStage>());
            Assert.That(result.PageTrust, Is.TypeOf<HipPageTrustStage>());
            Assert.That(result.ContentRisk, Is.TypeOf<HipContentRiskStage>());
            Assert.That(result.FinalScore, Is.TypeOf<HipFinalScoreStage>());
            Assert.That(result.ConfidenceStage, Is.TypeOf<HipConfidenceStage>());
            Assert.That(result.FinalScoreHigherMeansMoreTrust, Is.True);
            Assert.That(result.ContentRiskScoreHigherMeansMoreRisk, Is.True);
        });
    }

    [Test]
    public void Pipeline_renormalizes_active_weights_when_page_evidence_is_absent()
    {
        var result = Pipeline().Score(Request(
            domainTrustScore: 80,
            pageTrustScore: null,
            contentRiskScore: 20));

        Assert.Multiple(() =>
        {
            Assert.That(result.PageTrustScore, Is.Null);
            Assert.That(result.FinalHipScore, Is.EqualTo(80));
            Assert.That(result.Warnings, Does.Contain("No page-specific trust score was available; HIP normalized the active domain and content weights."));
            Assert.That(result.TrustAssertionDisposition, Is.EqualTo(HipTrustAssertionDisposition.WithheldInsufficientEvidence));
            Assert.That(result.PresentationStatus, Is.EqualTo(RiskStatus.LimitedTrustData));
            Assert.That(result.CanAssertPositiveTrust, Is.False);
        });
    }

    [Test]
    public void Domain_only_scoring_marks_page_trust_not_applicable_without_treating_it_as_missing()
    {
        var result = Pipeline().Score(Request(
            domainTrustScore: 80,
            pageTrustScore: null,
            contentRiskScore: 20,
            confidence: HipScoreConfidence.High,
            freshness: HipEvidenceFreshness.Fresh,
            pageTrustExpected: false));

        Assert.Multiple(() =>
        {
            Assert.That(result.PageTrust.Availability, Is.EqualTo(HipPageTrustAvailability.NotApplicable));
            Assert.That(result.Warnings, Is.Empty);
            Assert.That(result.TrustAssertionDisposition, Is.EqualTo(HipTrustAssertionDisposition.Allowed));
            Assert.That(result.PresentationStatus, Is.EqualTo(RiskStatus.MostlyTrusted));
            Assert.That(result.CanAssertPositiveTrust, Is.True);
        });
    }

    [Test]
    public void Pipeline_rounds_midpoints_away_from_zero_deterministically()
    {
        var result = Pipeline().Score(Request(
            domainTrustScore: 0,
            pageTrustScore: null,
            contentRiskScore: 99));

        Assert.That(result.FinalHipScore, Is.EqualTo(1));
    }

    [TestCase(0, RiskStatus.Dangerous)]
    [TestCase(9, RiskStatus.Dangerous)]
    [TestCase(10, RiskStatus.HighRisk)]
    [TestCase(24, RiskStatus.HighRisk)]
    [TestCase(25, RiskStatus.Suspicious)]
    [TestCase(39, RiskStatus.Suspicious)]
    [TestCase(40, RiskStatus.Unknown)]
    [TestCase(49, RiskStatus.Unknown)]
    [TestCase(50, RiskStatus.LimitedTrustData)]
    [TestCase(69, RiskStatus.LimitedTrustData)]
    [TestCase(70, RiskStatus.MostlyTrusted)]
    [TestCase(84, RiskStatus.MostlyTrusted)]
    [TestCase(85, RiskStatus.Trusted)]
    [TestCase(100, RiskStatus.Trusted)]
    public void Pipeline_maps_master_spec_status_boundaries(int finalScore, RiskStatus expected)
    {
        var result = Pipeline().Score(Request(
            domainTrustScore: finalScore,
            pageTrustScore: finalScore,
            contentRiskScore: 100 - finalScore));

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(finalScore));
            Assert.That(result.FinalStatus, Is.EqualTo(expected));
        });
    }

    [Test]
    public void Confidence_and_freshness_do_not_change_the_final_score()
    {
        var pipeline = Pipeline();
        var highFresh = pipeline.Score(Request(
            domainTrustScore: 72,
            pageTrustScore: 64,
            contentRiskScore: 31,
            confidence: HipScoreConfidence.High,
            freshness: HipEvidenceFreshness.Fresh));
        var lowStale = pipeline.Score(Request(
            domainTrustScore: 72,
            pageTrustScore: 64,
            contentRiskScore: 31,
            confidence: HipScoreConfidence.Low,
            freshness: HipEvidenceFreshness.Stale));

        Assert.Multiple(() =>
        {
            Assert.That(lowStale.FinalHipScore, Is.EqualTo(highFresh.FinalHipScore));
            Assert.That(highFresh.Confidence, Is.EqualTo(HipScoreConfidence.High));
            Assert.That(lowStale.Confidence, Is.EqualTo(HipScoreConfidence.Low));
            Assert.That(highFresh.EvidenceFreshness, Is.EqualTo(HipEvidenceFreshness.Fresh));
            Assert.That(lowStale.EvidenceFreshness, Is.EqualTo(HipEvidenceFreshness.Stale));
            Assert.That(lowStale.PresentationStatus, Is.EqualTo(RiskStatus.LimitedTrustData));
            Assert.That(lowStale.CanAssertPositiveTrust, Is.False);
        });
    }

    [Test]
    public void Conflicting_evidence_withholds_positive_status_without_hiding_known_risk()
    {
        var highCalculatedScore = Pipeline().Score(Request(
            domainTrustScore: 90,
            pageTrustScore: 90,
            contentRiskScore: 10,
            confidence: HipScoreConfidence.Conflicted,
            freshness: HipEvidenceFreshness.Fresh));
        var knownRisk = Pipeline().Score(Request(
            domainTrustScore: 0,
            pageTrustScore: 0,
            contentRiskScore: 100,
            confidence: HipScoreConfidence.Conflicted,
            freshness: HipEvidenceFreshness.Stale));

        Assert.Multiple(() =>
        {
            Assert.That(highCalculatedScore.FinalHipScore, Is.EqualTo(90));
            Assert.That(highCalculatedScore.PresentationStatus, Is.EqualTo(RiskStatus.Unknown));
            Assert.That(highCalculatedScore.TrustAssertionDisposition, Is.EqualTo(HipTrustAssertionDisposition.WithheldConflictingEvidence));
            Assert.That(highCalculatedScore.Warnings, Has.Some.Contains("pending review"));
            Assert.That(knownRisk.PresentationStatus, Is.EqualTo(RiskStatus.Dangerous));
        });
    }

    [Test]
    public void Invalid_evidence_is_rejected_before_a_score_result_is_produced()
    {
        var request = Request(
            domainTrustScore: 90,
            pageTrustScore: 90,
            contentRiskScore: 10,
            confidence: HipScoreConfidence.High,
            freshness: HipEvidenceFreshness.Invalid);

        Assert.That(() => Pipeline().Score(request), Throws.ArgumentException);
    }

    [Test]
    public void Constraint_policy_runs_after_baseline_composition_and_can_explain_an_adjustment()
    {
        var policy = new RecordingConstraintPolicy();
        var pipeline = new HipScoringPipeline(policy);

        var result = pipeline.Score(Request(
            domainTrustScore: 80,
            pageTrustScore: 70,
            contentRiskScore: 20));

        Assert.Multiple(() =>
        {
            Assert.That(policy.ObservedBaseline, Is.EqualTo(77));
            Assert.That(policy.ObservedDomainTrustScore, Is.EqualTo(80));
            Assert.That(policy.ObservedContentRiskScore, Is.EqualTo(20));
            Assert.That(result.FinalHipScore, Is.EqualTo(42));
            Assert.That(result.FinalStatus, Is.EqualTo(RiskStatus.Unknown));
            Assert.That(result.Reasons, Does.Contain("A test-only constraint adjusted the composed score."));
            Assert.That(result.Warnings, Does.Contain("A test-only constraint warning was attached."));
        });
    }

    [Test]
    public void Typed_evidence_facts_reach_constraints_and_are_preserved_without_changing_the_default_score()
    {
        var evidence = new HipScoringEvidenceContext(
        [
            new(HipScoringEvidenceFactType.ConfirmedMalware, "test:confirmed-malware"),
            new(HipScoringEvidenceFactType.StrongExecutableDownloadRisk, "test:executable-download"),
            new(HipScoringEvidenceFactType.IdentityMissing, "test:identity-missing")
        ]);
        var policy = new EvidenceRecordingConstraintPolicy();
        var request = Request(80, 70, 20) with { EvidenceContext = evidence };

        var result = new HipScoringPipeline(policy).Score(request);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(77));
            Assert.That(policy.ObservedEvidence, Is.SameAs(evidence));
            Assert.That(result.EvidenceContext, Is.SameAs(evidence));
            Assert.That(result.EvidenceContext.Has(HipScoringEvidenceFactType.ConfirmedMalware), Is.True);
            Assert.That(result.EvidenceContext.Has(HipScoringEvidenceFactType.StrongExecutableDownloadRisk), Is.True);
            Assert.That(result.EvidenceContext.Has(HipScoringEvidenceFactType.IdentityMissing), Is.True);
        });
    }

    [Test]
    public void Existing_requests_default_to_an_empty_evidence_context()
    {
        var result = Pipeline().Score(Request(80, 70, 20));

        Assert.That(result.EvidenceContext.Facts, Is.Empty);
    }

    [Test]
    public void Typed_evidence_context_rejects_duplicate_types_and_non_protocol_sources()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => new HipScoringEvidenceContext(
                [
                    new(HipScoringEvidenceFactType.UnknownTarget, "test:unknown-one"),
                    new(HipScoringEvidenceFactType.UnknownTarget, "test:unknown-two")
                ]),
                Throws.ArgumentException);
            Assert.That(
                () => new HipScoringEvidenceContext(
                [
                    new(HipScoringEvidenceFactType.LimitedEvidence, "raw private page value")
                ]),
                Throws.ArgumentException);
            Assert.That(
                () => new HipScoringEvidenceContext(
                [
                    new(HipScoringEvidenceFactType.IdentityWeak, "test:identity-weak"),
                    new(HipScoringEvidenceFactType.StrongIdentityVerified, "test:identity-strong")
                ]),
                Throws.ArgumentException);
        });
    }

    [Test]
    public void Published_scoring_evidence_and_messages_cannot_be_mutated()
    {
        var evidence = new HipScoringEvidenceContext(
        [
            new(HipScoringEvidenceFactType.ConfirmedMalware, "test:confirmed-malware")
        ]);
        var result = Pipeline().Score(Request(80, 70, 20) with
        {
            EvidenceContext = evidence,
            Warnings = ["Original warning."]
        });

        var publishedFacts = (IList<HipScoringEvidenceFact>)result.EvidenceContext.Facts;
        var publishedReasons = (IList<string>)result.Reasons;
        var publishedWarnings = (IList<string>)result.Warnings;

        Assert.Multiple(() =>
        {
            Assert.That(
                () => publishedFacts[0] = new(
                    HipScoringEvidenceFactType.ConfirmedPhishing,
                    "test:confirmed-phishing"),
                Throws.TypeOf<NotSupportedException>());
            Assert.That(
                () => publishedReasons[0] = "Mutated reason.",
                Throws.TypeOf<NotSupportedException>());
            Assert.That(
                () => publishedWarnings[0] = "Mutated warning.",
                Throws.TypeOf<NotSupportedException>());
        });
    }

    [Test]
    public void Score_changing_constraint_without_an_explanation_is_rejected()
    {
        var pipeline = new HipScoringPipeline(new UnexplainedConstraintPolicy());

        Assert.That(
            () => pipeline.Score(Request(80, 70, 20)),
            Throws.InvalidOperationException.With.Message.Contains("must provide an explanation"));
    }

    [Test]
    public void Score_increasing_constraint_is_rejected()
    {
        var pipeline = new HipScoringPipeline(new ScoreIncreasingConstraintPolicy());

        Assert.That(
            () => pipeline.Score(Request(80, 70, 20)),
            Throws.InvalidOperationException.With.Message.Contains("cannot increase"));
    }

    [Test]
    public void Default_constraint_policy_is_an_explicit_no_op_for_hip_0301()
    {
        var request = Request(
            domainTrustScore: 80,
            pageTrustScore: 70,
            contentRiskScore: 20);

        var result = Pipeline().Score(request);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(77));
            Assert.That(result.Reasons, Is.EqualTo(request.Reasons));
            Assert.That(result.Warnings, Is.EqualTo(request.Warnings));
        });
    }

    [TestCase(-1, 50, 50)]
    [TestCase(101, 50, 50)]
    [TestCase(50, -1, 50)]
    [TestCase(50, 101, 50)]
    [TestCase(50, 50, -1)]
    [TestCase(50, 50, 101)]
    public void Pipeline_rejects_out_of_range_layer_scores(
        int domainTrustScore,
        int pageTrustScore,
        int contentRiskScore)
    {
        var request = Request(domainTrustScore, pageTrustScore, contentRiskScore);

        Assert.Throws<ArgumentOutOfRangeException>(() => Pipeline().Score(request));
    }

    [Test]
    public void Pipeline_rejects_missing_or_blank_explanations()
    {
        var missingReasons = Request(50, 50, 50) with { Reasons = [] };
        var blankWarnings = Request(50, 50, 50) with { Warnings = [" "] };

        Assert.Multiple(() =>
        {
            Assert.That(() => Pipeline().Score(missingReasons), Throws.ArgumentException);
            Assert.That(() => Pipeline().Score(blankWarnings), Throws.ArgumentException);
        });
    }

    private static HipScoringPipeline Pipeline() => new(new NoOpHipScoreConstraintPolicy());

    private static HipScoringRequest Request(
        int domainTrustScore,
        int? pageTrustScore,
        int contentRiskScore,
        HipScoreConfidence confidence = HipScoreConfidence.Medium,
        HipEvidenceFreshness freshness = HipEvidenceFreshness.Fresh,
        bool pageTrustExpected = true) =>
        new(
            domainTrustScore,
            pageTrustScore,
            contentRiskScore,
            confidence,
            freshness,
            Reasons: ["HIP composed distinct domain, page, and content layers."],
            Warnings: [],
            PageTrustExpected: pageTrustExpected);

    private sealed class RecordingConstraintPolicy : IHipScoreConstraintPolicy
    {
        public int? ObservedBaseline { get; private set; }

        public int? ObservedDomainTrustScore { get; private set; }

        public int? ObservedContentRiskScore { get; private set; }

        public HipScoreConstraintResult Apply(HipScoreConstraintContext context)
        {
            ObservedBaseline = context.BaselineHipScore.Value;
            ObservedDomainTrustScore = context.DomainTrust.Score.Value;
            ObservedContentRiskScore = context.ContentRisk.RiskScore.Value;
            return new HipScoreConstraintResult(
                FinalHipScore: 42,
                AdditionalReasons: ["A test-only constraint adjusted the composed score."],
                AdditionalWarnings: ["A test-only constraint warning was attached."]);
        }
    }

    private sealed class UnexplainedConstraintPolicy : IHipScoreConstraintPolicy
    {
        public HipScoreConstraintResult Apply(HipScoreConstraintContext context) =>
            new(42, [], []);
    }

    private sealed class ScoreIncreasingConstraintPolicy : IHipScoreConstraintPolicy
    {
        public HipScoreConstraintResult Apply(HipScoreConstraintContext context) =>
            new(
                context.BaselineHipScore.Value + 1,
                ["A test-only policy tried to increase the score."],
                []);
    }

    private sealed class EvidenceRecordingConstraintPolicy : IHipScoreConstraintPolicy
    {
        public HipScoringEvidenceContext? ObservedEvidence { get; private set; }

        public HipScoreConstraintResult Apply(HipScoreConstraintContext context)
        {
            ObservedEvidence = context.EvidenceContext;
            return new HipScoreConstraintResult(context.BaselineHipScore.Value, [], []);
        }
    }
}
