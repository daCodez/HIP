using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.SiteSafety;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>
/// Hashes a deterministic privacy-safe projection of authoritative Site Safety evidence.
/// Raw URLs, summaries, warning prose, provider values, and source references are intentionally excluded.
/// </summary>
public sealed class HipTrustReceiptEvidenceDigestService(ICanonicalJsonService canonicalJsonService)
    : IHipTrustReceiptEvidenceDigestService
{
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));

    public HipContentDigest Compute(
        SiteSafetyScanResult authoritativeEvaluation,
        IReadOnlyCollection<string> reasonCodes,
        IReadOnlyCollection<string> warningCodes,
        HipTrustReceiptPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(authoritativeEvaluation);
        ArgumentNullException.ThrowIfNull(reasonCodes);
        ArgumentNullException.ThrowIfNull(warningCodes);
        ArgumentNullException.ThrowIfNull(policy);

        var projection = new EvidenceProjection(
            authoritativeEvaluation.ScanId,
            authoritativeEvaluation.Domain,
            Sha256(authoritativeEvaluation.Url),
            authoritativeEvaluation.ScannedAtUtc,
            authoritativeEvaluation.MalwareRiskScore,
            authoritativeEvaluation.PhishingRiskScore,
            authoritativeEvaluation.RedirectRiskScore,
            authoritativeEvaluation.ScriptRiskScore,
            authoritativeEvaluation.DownloadRiskScore,
            authoritativeEvaluation.FormRiskScore,
            authoritativeEvaluation.ReputationRiskScore,
            authoritativeEvaluation.OverallSafetyRiskScore,
            authoritativeEvaluation.DomainTrustScore,
            authoritativeEvaluation.PageTrustScore,
            authoritativeEvaluation.ContentRiskScore,
            authoritativeEvaluation.FinalHipScore,
            authoritativeEvaluation.Status.ToString(),
            authoritativeEvaluation.ConfidenceLevel,
            authoritativeEvaluation.Scoring is null
                ? null
                : new FormalScoringProjection(
                    authoritativeEvaluation.Scoring.ModelVersion,
                    authoritativeEvaluation.Scoring.DomainTrustScore,
                    authoritativeEvaluation.Scoring.PageTrustScore,
                    authoritativeEvaluation.Scoring.ContentRiskScore,
                    authoritativeEvaluation.Scoring.FinalHipScore,
                    authoritativeEvaluation.Scoring.FinalStatus.ToString(),
                    authoritativeEvaluation.Scoring.PresentationStatus.ToString(),
                    authoritativeEvaluation.Scoring.Confidence.ToString(),
                    authoritativeEvaluation.Scoring.EvidenceFreshness.ToString(),
                    authoritativeEvaluation.Scoring.TrustAssertionDisposition.ToString(),
                    ProjectFormalEvidenceFacts(authoritativeEvaluation.Scoring)),
            reasonCodes.Order(StringComparer.Ordinal).ToArray(),
            warningCodes.Order(StringComparer.Ordinal).ToArray(),
            policy.PolicyVersion,
            policy.RuleSetVersion,
            authoritativeEvaluation.ProviderEvidence
                .Select(ToProjection)
                .OrderBy(projection => SortKey(projection), StringComparer.Ordinal)
                .ToArray(),
            (authoritativeEvaluation.MatchedRules ?? Array.Empty<SiteSafetyRuleResult>())
                .Select(ToProjection)
                .OrderBy(projection => SortKey(projection), StringComparer.Ordinal)
                .ToArray());
        var json = JsonSerializer.SerializeToUtf8Bytes(projection);
        var canonical = canonicalizer.Canonicalize(json);
        return new HipContentDigest(
            HipContentDigest.Sha256Algorithm,
            Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant());
    }

    private static ProviderEvidenceProjection ToProjection(SiteSafetyEvidence evidence) => new(
        evidence.ProviderName,
        evidence.ProviderType.ToString(),
        evidence.TargetType.ToString(),
        evidence.Domain,
        evidence.UrlHash,
        evidence.Confidence,
        evidence.CheckedAtUtc,
        evidence.ExpiresAtUtc,
        evidence.Errors.Count,
        evidence.IsAuthoritativeForRisk,
        evidence.IsAuthoritativeForTrust,
        evidence.EvidenceItems
            .Select(item => new ProviderEvidenceItemProjection(
                item.Category,
                item.EvidenceType,
                item.Status.ToString(),
                item.RiskImpact,
                item.TrustImpact,
                item.Confidence,
                item.Severity.ToString(),
                item.EvidenceQuality.ToString(),
                item.IsPositiveSignal,
                item.IsNegativeSignal,
                item.IsBlockingSignal))
            .OrderBy(projection => SortKey(projection), StringComparer.Ordinal)
            .ToArray());

    private static RuleEvidenceProjection ToProjection(SiteSafetyRuleResult rule) => new(
        rule.RuleId,
        rule.Source.ToString(),
        rule.CollectionType.ToString(),
        rule.RiskCategory.ToString(),
        rule.RiskImpact,
        rule.TrustImpact,
        rule.Severity.ToString(),
        rule.EvidenceQuality.ToString(),
        rule.StatusOverride?.ToString(),
        rule.ConfidencePenalty,
        rule.SendToAdminReview,
        rule.IsSimulationOnly);

    private static string Sha256(string value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()}";

    private static IReadOnlyCollection<FormalScoringEvidenceFactProjection>? ProjectFormalEvidenceFacts(
        HIP.Domain.Scoring.HipScoringResult scoring)
    {
        var facts = scoring.EvidenceContext.Facts
            .Select(fact => new FormalScoringEvidenceFactProjection(
                fact.Type.ToString(),
                fact.SourceCode))
            .OrderBy(fact => fact.Type, StringComparer.Ordinal)
            .ThenBy(fact => fact.SourceCode, StringComparer.Ordinal)
            .ToArray();
        return facts.Length == 0 ? null : facts;
    }

    private static string SortKey<TProjection>(TProjection projection) => JsonSerializer.Serialize(projection);

    private sealed record EvidenceProjection(
        string EvaluationId,
        string Domain,
        string UrlDigest,
        DateTimeOffset EvaluatedAtUtc,
        int MalwareRiskScore,
        int PhishingRiskScore,
        int RedirectRiskScore,
        int ScriptRiskScore,
        int DownloadRiskScore,
        int FormRiskScore,
        int ReputationRiskScore,
        int OverallSafetyRiskScore,
        int DomainTrustScore,
        int PageTrustScore,
        int ContentTrustScore,
        int FinalHipScore,
        string Status,
        string Confidence,
        FormalScoringProjection? FormalScoring,
        IReadOnlyCollection<string> ReasonCodes,
        IReadOnlyCollection<string> WarningCodes,
        string PolicyVersion,
        string RuleSetVersion,
        IReadOnlyCollection<ProviderEvidenceProjection> ProviderEvidence,
        IReadOnlyCollection<RuleEvidenceProjection> MatchedRules);

    private sealed record FormalScoringProjection(
        string ModelVersion,
        int DomainTrustScore,
        int? PageTrustScore,
        int ContentRiskScore,
        int FinalHipScore,
        string FinalStatus,
        string PresentationStatus,
        string Confidence,
        string EvidenceFreshness,
        string TrustAssertionDisposition,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        IReadOnlyCollection<FormalScoringEvidenceFactProjection>? EvidenceFacts);

    private sealed record FormalScoringEvidenceFactProjection(
        string Type,
        string SourceCode);

    private sealed record ProviderEvidenceProjection(
        string ProviderName,
        string ProviderType,
        string TargetType,
        string Domain,
        string? UrlHash,
        int Confidence,
        DateTimeOffset CheckedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        int ErrorCount,
        bool IsAuthoritativeForRisk,
        bool IsAuthoritativeForTrust,
        IReadOnlyCollection<ProviderEvidenceItemProjection> EvidenceItems);

    private sealed record ProviderEvidenceItemProjection(
        string Category,
        string EvidenceType,
        string Status,
        int RiskImpact,
        int TrustImpact,
        int Confidence,
        string Severity,
        string EvidenceQuality,
        bool IsPositiveSignal,
        bool IsNegativeSignal,
        bool IsBlockingSignal);

    private sealed record RuleEvidenceProjection(
        string RuleId,
        string Source,
        string CollectionType,
        string RiskCategory,
        int RiskImpact,
        int TrustImpact,
        string Severity,
        string EvidenceQuality,
        string? StatusOverride,
        int ConfidencePenalty,
        bool SendToAdminReview,
        bool IsSimulationOnly);
}
