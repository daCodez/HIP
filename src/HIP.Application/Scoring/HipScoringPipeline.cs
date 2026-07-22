using HIP.Domain.Scoring;

namespace HIP.Application.Scoring;

/// <summary>Validated layer values and evidence context supplied to the HIP-0301 pipeline.</summary>
public sealed record HipScoringRequest(
    int DomainTrustScore,
    int? PageTrustScore,
    int ContentRiskScore,
    HipScoreConfidence Confidence,
    HipEvidenceFreshness EvidenceFreshness,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Warnings,
    bool PageTrustExpected = true,
    HipScoringEvidenceContext? EvidenceContext = null,
    IReadOnlyCollection<HipScoringReasonEntry>? ReasonEntries = null);

/// <summary>Composed score supplied to the constraint seam implemented by HIP-0302.</summary>
public sealed record HipScoreConstraintContext(
    HipDomainTrustStage DomainTrust,
    HipPageTrustStage PageTrust,
    HipContentRiskStage ContentRisk,
    ScoreValue BaselineHipScore,
    HipConfidenceStage Confidence,
    HipScoringEvidenceContext? EvidenceContext = null);

/// <summary>Bounded score adjustment plus the explanations produced by one constraint policy.</summary>
public sealed record HipScoreConstraintResult(
    int FinalHipScore,
    IReadOnlyCollection<string> AdditionalReasons,
    IReadOnlyCollection<string> AdditionalWarnings,
    IReadOnlyCollection<HipScoringReasonEntry>? ReasonEntries = null);

/// <summary>Applies caps and overrides after baseline composition without hiding score direction.</summary>
public interface IHipScoreConstraintPolicy
{
    HipScoreConstraintResult Apply(HipScoreConstraintContext context);
}

/// <summary>HIP-0301 policy that preserves the baseline until formal caps ship in HIP-0302.</summary>
public sealed class NoOpHipScoreConstraintPolicy : IHipScoreConstraintPolicy
{
    public HipScoreConstraintResult Apply(HipScoreConstraintContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new HipScoreConstraintResult(context.BaselineHipScore.Value, [], []);
    }
}

public interface IHipScoringPipeline
{
    HipScoringResult Score(HipScoringRequest request);
}

/// <summary>
/// Evaluates the formal HIP stages in order: domain trust, optional page trust, content risk,
/// normalized baseline composition, constraints, then confidence/freshness explainability.
/// </summary>
public sealed class HipScoringPipeline(IHipScoreConstraintPolicy constraintPolicy) : IHipScoringPipeline
{
    private const decimal DomainWeight = 0.35m;
    private const decimal PageWeight = 0.30m;
    private const decimal ContentSafetyWeight = 0.35m;
    private const string MissingPageWarning =
        "No page-specific trust score was available; HIP normalized the active domain and content weights.";

    public HipScoringResult Score(HipScoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(constraintPolicy);

        ValidateContext(request);
        var domainTrust = HipDomainTrustStage.Evaluate(request.DomainTrustScore);
        var pageTrust = HipPageTrustStage.Evaluate(request.PageTrustScore, request.PageTrustExpected);
        var contentRisk = HipContentRiskStage.Evaluate(request.ContentRiskScore);
        var confidence = HipConfidenceStage.Evaluate(request.Confidence, request.EvidenceFreshness);
        var evidenceContext = request.EvidenceContext ?? HipScoringEvidenceContext.Empty;

        var baselineHipScore = ComposeBaselineStage(
            domainTrust,
            pageTrust,
            contentRisk);
        var constraintResult = constraintPolicy.Apply(new HipScoreConstraintContext(
                domainTrust,
                pageTrust,
                contentRisk,
                ScoreValue.From(baselineHipScore),
                confidence,
                evidenceContext))
            ?? throw new InvalidOperationException("The HIP score constraint policy returned no result.");
        if (constraintResult.FinalHipScore > baselineHipScore)
        {
            throw new InvalidOperationException(
                "A HIP score constraint cannot increase the composed baseline score.");
        }

        var finalScore = HipFinalScoreStage.Evaluate(baselineHipScore, constraintResult.FinalHipScore);
        if (finalScore.Score != finalScore.BaselineScore &&
            (constraintResult.AdditionalReasons is null || constraintResult.AdditionalReasons.Count == 0))
        {
            throw new InvalidOperationException(
                "A HIP score constraint that changes the score must provide an explanation.");
        }

        var trustAssertionDisposition = EvaluateTrustAssertionDisposition(pageTrust, confidence);

        var reasons = NormalizeMessages(
            request.Reasons,
            constraintResult.AdditionalReasons,
            requireAtLeastOne: true,
            parameterName: nameof(request.Reasons));
        var warnings = NormalizeMessages(
            request.Warnings,
            BuildEvidenceWarnings(pageTrust, confidence),
            constraintResult.AdditionalWarnings,
            requireAtLeastOne: false,
            parameterName: nameof(request.Warnings));
        var reasonEntries = NormalizeReasonEntries(
            request.ReasonEntries,
            constraintResult.ReasonEntries,
            BuildEvidenceReasonEntries(pageTrust, confidence));

        return new HipScoringResult(
            domainTrust,
            pageTrust,
            contentRisk,
            finalScore,
            confidence,
            trustAssertionDisposition,
            reasons,
            warnings,
            evidenceContext,
            reasonEntries);
    }

    private static int ComposeBaselineStage(
        HipDomainTrustStage domainTrust,
        HipPageTrustStage pageTrust,
        HipContentRiskStage contentRisk)
    {
        var weightedTotal = (domainTrust.Score.Value * DomainWeight) +
                            (contentRisk.InverseSafetyScore.Value * ContentSafetyWeight);
        var activeWeight = DomainWeight + ContentSafetyWeight;
        if (pageTrust.Score is not null)
        {
            weightedTotal += pageTrust.Score.Value.Value * PageWeight;
            activeWeight += PageWeight;
        }

        return ScoreValue.From((int)Math.Round(
                weightedTotal / activeWeight,
                MidpointRounding.AwayFromZero))
            .Value;
    }

    private static void ValidateContext(HipScoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request.Reasons);
        ArgumentNullException.ThrowIfNull(request.Warnings);
    }

    private static HipTrustAssertionDisposition EvaluateTrustAssertionDisposition(
        HipPageTrustStage pageTrust,
        HipConfidenceStage confidence)
    {
        if (confidence.Level is HipScoreConfidence.Conflicted)
        {
            return HipTrustAssertionDisposition.WithheldConflictingEvidence;
        }

        if (pageTrust.Availability is HipPageTrustAvailability.Missing ||
            confidence.Level is HipScoreConfidence.Low ||
            confidence.EvidenceFreshness is HipEvidenceFreshness.Missing or
                HipEvidenceFreshness.Mixed or
                HipEvidenceFreshness.Stale)
        {
            return HipTrustAssertionDisposition.WithheldInsufficientEvidence;
        }

        return HipTrustAssertionDisposition.Allowed;
    }

    private static IReadOnlyCollection<string> BuildEvidenceWarnings(
        HipPageTrustStage pageTrust,
        HipConfidenceStage confidence)
    {
        var warnings = new List<string>();
        if (pageTrust.Availability is HipPageTrustAvailability.Missing)
        {
            warnings.Add(MissingPageWarning);
        }

        switch (confidence.EvidenceFreshness)
        {
            case HipEvidenceFreshness.Missing:
                warnings.Add("Required evidence is missing; HIP withheld a positive trust assertion.");
                break;
            case HipEvidenceFreshness.Mixed:
                warnings.Add("Evidence freshness is mixed; HIP withheld a positive trust assertion.");
                break;
            case HipEvidenceFreshness.Stale:
                warnings.Add("Evidence is stale; HIP withheld a positive trust assertion.");
                break;
        }

        if (confidence.Level is HipScoreConfidence.Low)
        {
            warnings.Add("Evidence confidence is low; HIP withheld a positive trust assertion.");
        }
        else if (confidence.Level is HipScoreConfidence.Conflicted)
        {
            warnings.Add("Evidence conflicts; HIP withheld a positive trust assertion pending review.");
        }

        return warnings;
    }

    private static IReadOnlyCollection<HipScoringReasonEntry> BuildEvidenceReasonEntries(
        HipPageTrustStage pageTrust,
        HipConfidenceStage confidence)
    {
        var entries = new List<HipScoringReasonEntry>();
        if (pageTrust.Availability is HipPageTrustAvailability.Missing)
        {
            entries.Add(HipScoringReasonCatalog.MissingPageEvidence());
        }

        switch (confidence.EvidenceFreshness)
        {
            case HipEvidenceFreshness.Missing:
                entries.Add(HipScoringReasonCatalog.MissingEvidenceFreshness());
                break;
            case HipEvidenceFreshness.Mixed:
                entries.Add(HipScoringReasonCatalog.MixedEvidenceFreshness());
                break;
            case HipEvidenceFreshness.Stale:
                entries.Add(HipScoringReasonCatalog.StaleEvidenceFreshness());
                break;
        }

        if (confidence.Level is HipScoreConfidence.Low)
        {
            entries.Add(HipScoringReasonCatalog.LowConfidence());
        }
        else if (confidence.Level is HipScoreConfidence.Conflicted)
        {
            entries.Add(HipScoringReasonCatalog.ConflictedConfidence());
        }

        return entries;
    }

    private static IReadOnlyCollection<HipScoringReasonEntry> NormalizeReasonEntries(
        IReadOnlyCollection<HipScoringReasonEntry>? requestEntries,
        IReadOnlyCollection<HipScoringReasonEntry>? constraintEntries,
        IReadOnlyCollection<HipScoringReasonEntry> evidenceEntries)
    {
        ArgumentNullException.ThrowIfNull(evidenceEntries);
        return (requestEntries ?? Array.Empty<HipScoringReasonEntry>())
            .Concat(constraintEntries ?? Array.Empty<HipScoringReasonEntry>())
            .Concat(evidenceEntries)
            .ToArray();
    }

    private static IReadOnlyCollection<string> NormalizeMessages(
        IReadOnlyCollection<string>? first,
        IReadOnlyCollection<string>? second,
        bool requireAtLeastOne,
        string parameterName) =>
        NormalizeMessages(first, second, [], requireAtLeastOne, parameterName);

    private static IReadOnlyCollection<string> NormalizeMessages(
        IReadOnlyCollection<string>? first,
        IReadOnlyCollection<string>? second,
        IReadOnlyCollection<string>? third,
        bool requireAtLeastOne,
        string parameterName)
    {
        if (first is null || second is null || third is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        var values = first.Concat(second).Concat(third).ToArray();
        if ((requireAtLeastOne && values.Length == 0) || values.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                requireAtLeastOne
                    ? "HIP scoring requires at least one non-blank explanation."
                    : "HIP scoring warnings cannot be blank.",
                parameterName);
        }

        return values
            .Select(value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}
