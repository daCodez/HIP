using HIP.Application.Scoring;
using HIP.Domain.Scoring;

namespace HIP.Tests.Scoring;

/// <summary>Locks the HIP-0303 stable scoring reason contract and mandatory catalog entries.</summary>
public sealed class HipScoringReasonCatalogTests
{
    [Test]
    public void Confirmed_threat_cap_publishes_a_stable_typed_catalog_entry()
    {
        var observedAtUtc = new DateTimeOffset(2026, 7, 20, 12, 30, 0, TimeSpan.Zero);
        var evidence = new HipScoringEvidenceContext(
        [
            new(
                HipScoringEvidenceFactType.ConfirmedMalware,
                "site-safety:confirmed-malware",
                observedAtUtc,
                HipEvidencePrivacyClassification.PublicMetadata)
        ]);
        var result = Pipeline().Score(Request(evidence));

        var entry = result.ReasonEntries.Single();
        Assert.Multiple(() =>
        {
            Assert.That(entry.Code, Is.EqualTo("score-cap:confirmed-threat"));
            Assert.That(entry.WarningCode, Is.EqualTo("warning:confirmed-threat"));
            Assert.That(entry.Impact.Kind, Is.EqualTo(HipScoreImpactKind.MaximumFinalScore));
            Assert.That(entry.Impact.Value, Is.EqualTo(9));
            Assert.That(entry.EvidenceSourceCode, Is.EqualTo("site-safety:confirmed-malware"));
            Assert.That(entry.EvidenceObservedAtUtc, Is.EqualTo(observedAtUtc));
            Assert.That(entry.PrivacyClassification, Is.EqualTo(HipEvidencePrivacyClassification.PublicMetadata));
            Assert.That(result.Reasons, Does.Contain(entry.Explanation));
            Assert.That(result.Warnings, Does.Contain(entry.Warning));
        });
    }

    [Test]
    public void Reason_entry_rejects_malformed_codes_and_inconsistent_impacts()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => Entry(code: "Not Canonical"),
                Throws.ArgumentException);
            Assert.That(
                () => Entry(impact: new HipScoreImpact(HipScoreImpactKind.MaximumFinalScore, null)),
                Throws.ArgumentException);
            Assert.That(
                () => Entry(impact: new HipScoreImpact(HipScoreImpactKind.None, 9)),
                Throws.ArgumentException);
        });
    }

    [Test]
    public void Published_reason_entries_cannot_be_mutated()
    {
        var evidence = new HipScoringEvidenceContext(
        [
            new(HipScoringEvidenceFactType.ConfirmedPhishing, "site-safety:confirmed-phishing")
        ]);
        var result = Pipeline().Score(Request(evidence));
        var entries = (IList<HipScoringReasonEntry>)result.ReasonEntries;

        Assert.That(() => entries.Clear(), Throws.TypeOf<NotSupportedException>());
    }

    [Test]
    public void Pipeline_generated_evidence_warnings_have_stable_catalog_codes_without_changing_the_score()
    {
        var result = Pipeline().Score(new HipScoringRequest(
            80,
            PageTrustScore: null,
            ContentRiskScore: 20,
            HipScoreConfidence.Low,
            HipEvidenceFreshness.Stale,
            Reasons: ["HIP composed the available score layers."],
            Warnings: []));

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(80));
            Assert.That(result.ReasonEntries.Select(entry => entry.Code), Is.EqualTo(new[]
            {
                "evidence:page-missing",
                "evidence:freshness-stale",
                "confidence:low"
            }));
            Assert.That(result.ReasonEntries, Has.All.Matches<HipScoringReasonEntry>(entry =>
                entry.Impact.Kind == HipScoreImpactKind.None && entry.Impact.Value is null));
            Assert.That(result.ReasonEntries.Select(entry => entry.WarningCode), Is.EqualTo(new[]
            {
                "warning:page-missing",
                "warning:evidence-freshness-stale",
                "warning:confidence-low"
            }));
        });
    }

    [Test]
    public void Scoring_result_rejects_duplicate_or_unbounded_reason_catalog_entries()
    {
        var duplicate = Entry();
        var tooMany = Enumerable.Range(0, HipScoringResult.MaximumReasonEntries + 1)
            .Select(index => Entry($"score-cap:test-{index}"))
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                () => Pipeline().Score(Request(HipScoringEvidenceContext.Empty) with
                {
                    ReasonEntries = [duplicate, duplicate]
                }),
                Throws.ArgumentException);
            Assert.That(
                () => Pipeline().Score(Request(HipScoringEvidenceContext.Empty) with
                {
                    ReasonEntries = tooMany
                }),
                Throws.TypeOf<ArgumentOutOfRangeException>());
        });
    }

    private static HipScoringReasonEntry Entry(
        string code = "score-cap:test",
        HipScoreImpact? impact = null) => new(
        code,
        "A bounded test explanation.",
        "warning:test",
        "A bounded test warning.",
        impact ?? new HipScoreImpact(HipScoreImpactKind.MaximumFinalScore, 39),
        "test:evidence",
        null,
        HipEvidencePrivacyClassification.DerivedMetadata);

    private static HipScoringPipeline Pipeline() => new(new HipMandatoryScoreConstraintPolicy());

    private static HipScoringRequest Request(HipScoringEvidenceContext evidence) => new(
        90,
        90,
        10,
        HipScoreConfidence.High,
        HipEvidenceFreshness.Fresh,
        Reasons: ["HIP composed distinct domain, page, and content layers."],
        Warnings: [],
        EvidenceContext: evidence);
}
