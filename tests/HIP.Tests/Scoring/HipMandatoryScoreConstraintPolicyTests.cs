using HIP.Application.Scoring;
using HIP.Domain.Scoring;

namespace HIP.Tests.Scoring;

/// <summary>Locks the HIP-0302 mandatory cap rules and their precedence.</summary>
public sealed class HipMandatoryScoreConstraintPolicyTests
{
    [TestCase(HipScoringEvidenceFactType.ConfirmedMalware)]
    [TestCase(HipScoringEvidenceFactType.ConfirmedPhishing)]
    public void Confirmed_threat_caps_the_final_score_in_the_dangerous_band(
        HipScoringEvidenceFactType confirmedThreat)
    {
        var result = Score(confirmedThreat);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalScore.BaselineScore.Value, Is.EqualTo(90));
            Assert.That(result.FinalHipScore, Is.EqualTo(9));
            Assert.That(result.Reasons, Does.Contain(
                "Confirmed malware or phishing evidence limits the final HIP score to 9."));
            Assert.That(result.Warnings, Does.Contain(
                "Confirmed threat evidence overrides otherwise positive trust signals."));
        });
    }

    [TestCase(HipScoringEvidenceFactType.IdentityMissing)]
    [TestCase(HipScoringEvidenceFactType.IdentityWeak)]
    public void Strong_executable_risk_with_insufficient_identity_caps_at_suspicious(
        HipScoringEvidenceFactType identityFact)
    {
        var result = Score(
            HipScoringEvidenceFactType.StrongExecutableDownloadRisk,
            identityFact);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(39));
            Assert.That(result.Reasons, Does.Contain(
                "Strong executable-download risk with missing or weak identity limits the final HIP score to 39."));
            Assert.That(result.Warnings, Does.Contain(
                "The executable download lacks sufficiently strong identity evidence."));
        });
    }

    [Test]
    public void Strong_executable_risk_without_identity_evidence_fails_closed()
    {
        var result = Score(HipScoringEvidenceFactType.StrongExecutableDownloadRisk);

        Assert.That(result.FinalHipScore, Is.EqualTo(39));
    }

    [Test]
    public void Explicit_strong_identity_avoids_only_the_executable_identity_cap()
    {
        var executableOnly = Score(
            HipScoringEvidenceFactType.StrongExecutableDownloadRisk,
            HipScoringEvidenceFactType.StrongIdentityVerified);
        var confirmedThreat = Score(
            HipScoringEvidenceFactType.StrongExecutableDownloadRisk,
            HipScoringEvidenceFactType.StrongIdentityVerified,
            HipScoringEvidenceFactType.ConfirmedMalware);

        Assert.Multiple(() =>
        {
            Assert.That(executableOnly.FinalHipScore, Is.EqualTo(90));
            Assert.That(confirmedThreat.FinalHipScore, Is.EqualTo(9));
        });
    }

    [Test]
    public void Unknown_target_with_limited_evidence_caps_at_limited_trust_data()
    {
        var result = Score(
            HipScoringEvidenceFactType.UnknownTarget,
            HipScoringEvidenceFactType.LimitedEvidence);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(69));
            Assert.That(result.Reasons, Does.Contain(
                "An unknown target with limited evidence cannot exceed a final HIP score of 69."));
            Assert.That(result.Warnings, Does.Contain(
                "HIP has too little evidence to make a positive trust assertion for this target."));
        });
    }

    [TestCase(HipScoringEvidenceFactType.RiskyExactPage)]
    [TestCase(HipScoringEvidenceFactType.UserGeneratedContent)]
    public void Trusted_parent_cannot_hide_exact_page_or_user_generated_risk(
        HipScoringEvidenceFactType pageFact)
    {
        var result = Score(HipScoringEvidenceFactType.TrustedParentDomain, pageFact);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(69));
            Assert.That(result.Reasons, Has.Some.Contains("trusted parent domain"));
            Assert.That(result.Warnings, Has.Some.Contains("exact page"));
        });
    }

    [TestCase(HipScoringEvidenceFactType.IdentityMissing)]
    [TestCase(HipScoringEvidenceFactType.UnknownTarget)]
    [TestCase(HipScoringEvidenceFactType.LimitedEvidence)]
    [TestCase(HipScoringEvidenceFactType.TrustedParentDomain)]
    [TestCase(HipScoringEvidenceFactType.UserGeneratedContent)]
    public void Paired_rules_do_not_cap_when_only_one_required_fact_is_present(
        HipScoringEvidenceFactType fact)
    {
        var result = Score(fact);

        Assert.That(result.FinalHipScore, Is.EqualTo(90));
    }

    [Test]
    public void Origin_and_transport_facts_do_not_increase_or_establish_safety()
    {
        var result = Score(
            HipScoringEvidenceFactType.HttpsTransportOnly,
            HipScoringEvidenceFactType.DomainControlVerified,
            HipScoringEvidenceFactType.OriginSignatureVerified);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(result.FinalScore.BaselineScore.Value));
            Assert.That(result.FinalHipScore, Is.EqualTo(90));
            Assert.That(result.Warnings, Is.Empty);
        });
    }

    [Test]
    public void Strongest_applicable_cap_wins_with_deterministic_explanations()
    {
        var result = Score(
            HipScoringEvidenceFactType.ConfirmedMalware,
            HipScoringEvidenceFactType.StrongExecutableDownloadRisk,
            HipScoringEvidenceFactType.IdentityWeak,
            HipScoringEvidenceFactType.UnknownTarget,
            HipScoringEvidenceFactType.LimitedEvidence,
            HipScoringEvidenceFactType.TrustedParentDomain,
            HipScoringEvidenceFactType.RiskyExactPage);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalHipScore, Is.EqualTo(9));
            Assert.That(result.Reasons.Skip(1), Is.EqualTo(new[]
            {
                "Confirmed malware or phishing evidence limits the final HIP score to 9.",
                "Strong executable-download risk with missing or weak identity limits the final HIP score to 39.",
                "An unknown target with limited evidence cannot exceed a final HIP score of 69.",
                "A trusted parent domain cannot hide risk on the exact page; the final HIP score is limited to 69."
            }));
        });
    }

    [Test]
    public void A_cap_never_raises_an_already_lower_baseline()
    {
        var request = Request(20, 20, 80) with
        {
            EvidenceContext = Evidence(
                HipScoringEvidenceFactType.UnknownTarget,
                HipScoringEvidenceFactType.LimitedEvidence)
        };

        var result = Pipeline().Score(request);

        Assert.Multiple(() =>
        {
            Assert.That(result.FinalScore.BaselineScore.Value, Is.EqualTo(20));
            Assert.That(result.FinalHipScore, Is.EqualTo(20));
            Assert.That(result.Reasons, Is.EqualTo(request.Reasons));
            Assert.That(result.Warnings, Is.Empty);
        });
    }

    private static HipScoringResult Score(params HipScoringEvidenceFactType[] facts) =>
        Pipeline().Score(Request(90, 90, 10) with { EvidenceContext = Evidence(facts) });

    private static HipScoringPipeline Pipeline() => new(new HipMandatoryScoreConstraintPolicy());

    private static HipScoringEvidenceContext Evidence(params HipScoringEvidenceFactType[] facts) =>
        new(facts.Select(fact => new HipScoringEvidenceFact(
                fact,
                $"test:{fact.ToString().ToLowerInvariant()}"))
            .ToArray());

    private static HipScoringRequest Request(
        int domainTrustScore,
        int pageTrustScore,
        int contentRiskScore) => new(
        domainTrustScore,
        pageTrustScore,
        contentRiskScore,
        HipScoreConfidence.High,
        HipEvidenceFreshness.Fresh,
        Reasons: ["HIP composed distinct domain, page, and content layers."],
        Warnings: []);
}
