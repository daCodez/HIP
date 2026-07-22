using System.Security.Cryptography;
using System.Text;
using HIP.Application.PublicLookup;
using HIP.Application.SiteSafety;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;
using HIP.Domain.Scoring;

namespace HIP.Application.Protocol;

/// <summary>
/// Issues immutable receipts from server-authoritative Site Safety results and verifies each signature before storage.
/// </summary>
public sealed class HipTrustReceiptIssuanceService(
    IManagedTrustReceiptSigner managedSigner,
    IHipTrustReceiptEvidenceDigestService evidenceDigestService,
    ICanonicalJsonService canonicalJsonService,
    IHipTrustReceiptVerificationService verificationService,
    IHipTrustReceiptRepository receiptRepository,
    HipTrustReceiptPolicy policy,
    HipTrustReceiptIssuerPolicy issuerPolicy,
    TimeProvider timeProvider) : IHipTrustReceiptIssuanceService
{
    private const string UnsignedPlaceholder = "unsigned-placeholder";
    private readonly IManagedTrustReceiptSigner signer =
        managedSigner ?? throw new ArgumentNullException(nameof(managedSigner));
    private readonly IHipTrustReceiptEvidenceDigestService evidenceDigests =
        evidenceDigestService ?? throw new ArgumentNullException(nameof(evidenceDigestService));
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));
    private readonly IHipTrustReceiptVerificationService verifier =
        verificationService ?? throw new ArgumentNullException(nameof(verificationService));
    private readonly IHipTrustReceiptRepository repository =
        receiptRepository ?? throw new ArgumentNullException(nameof(receiptRepository));
    private readonly HipTrustReceiptPolicy receiptPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
    private readonly HipTrustReceiptIssuerPolicy authorizedIssuers =
        issuerPolicy ?? throw new ArgumentNullException(nameof(issuerPolicy));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<HipTrustReceiptIssueResult> IssueAsync(
        SiteSafetyScanResult authoritativeEvaluation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (authoritativeEvaluation is null)
        {
            return Result(HipTrustReceiptIssueStatus.InvalidEvaluation);
        }

        PreparedEvaluation prepared;
        try
        {
            prepared = Prepare(authoritativeEvaluation, ProtocolTimestamp(clock.GetUtcNow()));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or NullReferenceException)
        {
            return Result(HipTrustReceiptIssueStatus.InvalidEvaluation);
        }

        HipStoredTrustReceipt? existing;
        try
        {
            existing = await repository.GetByRelatedEvaluationIdAsync(
                    prepared.RelatedEvaluationId,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.PersistenceUnavailable);
        }

        if (existing is not null)
        {
            return await ExistingResultAsync(existing, prepared.SourceEvaluationDigest, cancellationToken)
                .ConfigureAwait(false);
        }

        HipManagedTrustReceiptSigningKey signingKey;
        HipTrustReceipt unsignedReceipt;
        try
        {
            signingKey = await signer.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.SignerUnavailable);
        }

        if (!authorizedIssuers.IsAuthorized(signingKey.IssuerId, signingKey.KeyId))
        {
            return Result(HipTrustReceiptIssueStatus.SignerNotAuthorized);
        }

        HipTrustReceipt receipt;
        try
        {
            unsignedReceipt = CreateReceipt(prepared, signingKey, UnsignedPlaceholder);
            var canonicalPayload = canonicalizer.Canonicalize(HipTrustReceiptSigningPayload.Create(unsignedReceipt));
            var signingHash = Sha256(canonicalPayload);
            var signatureValue = await signer.SignHashAsync(signingKey, signingHash, cancellationToken)
                .ConfigureAwait(false);
            receipt = CreateReceipt(prepared, signingKey, signatureValue);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.SignerUnavailable);
        }

        string receiptJson;
        string receiptDigest;
        try
        {
            receiptJson = HipTrustReceiptJson.Serialize(receipt);
            var verification = await verifier.VerifyAsync(Encoding.UTF8.GetBytes(receiptJson), cancellationToken)
                .ConfigureAwait(false);
            if (!verification.IsVerified)
            {
                return Result(HipTrustReceiptIssueStatus.VerificationFailed);
            }

            receiptDigest = Sha256(canonicalizer.Canonicalize(Encoding.UTF8.GetBytes(receiptJson)));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.VerificationFailed);
        }

        var stored = new HipStoredTrustReceipt(
            receipt,
            receiptJson,
            receiptDigest,
            prepared.SourceEvaluationDigest);
        HipTrustReceiptRepositoryWriteResult writeResult;
        try
        {
            writeResult = await repository.TryCreateAsync(stored, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.PersistenceUnavailable);
        }

        if (writeResult.Status == HipTrustReceiptRepositoryWriteStatus.ExistingSame &&
            writeResult.StoredReceipt is not null)
        {
            return await ExistingResultAsync(
                    writeResult.StoredReceipt,
                    prepared.SourceEvaluationDigest,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return writeResult.Status switch
        {
            HipTrustReceiptRepositoryWriteStatus.Created =>
                new HipTrustReceiptIssueResult(HipTrustReceiptIssueStatus.Issued, receipt),
            HipTrustReceiptRepositoryWriteStatus.Conflict => Result(HipTrustReceiptIssueStatus.Conflict),
            _ => Result(HipTrustReceiptIssueStatus.PersistenceUnavailable)
        };
    }

    private PreparedEvaluation Prepare(SiteSafetyScanResult evaluation, DateTimeOffset issuedAtUtc)
    {
        var evaluatedAtUtc = ProtocolTimestamp(evaluation.ScannedAtUtc);
        if (evaluatedAtUtc > issuedAtUtc || issuedAtUtc - evaluatedAtUtc > receiptPolicy.MaximumEvaluationAge)
        {
            throw new ArgumentException("The authoritative evaluation is outside the receipt issuance window.");
        }

        var domain = DomainInputValidator.ValidateAndNormalize(evaluation.Domain);
        var relatedEvaluationId = RequiredEvaluationId(evaluation.ScanId);
        if (!Uri.TryCreate(evaluation.Url, UriKind.Absolute, out var evaluatedUri) ||
            !string.Equals(evaluatedUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(evaluatedUri.Host))
        {
            throw new ArgumentException("The authoritative evaluation must identify an absolute HTTPS target.");
        }

        var evaluatedUrlDomain = DomainInputValidator.ValidateAndNormalize(evaluatedUri.IdnHost);
        if (!string.Equals(evaluatedUrlDomain, domain, StringComparison.Ordinal))
        {
            throw new ArgumentException("The authoritative evaluation URL and domain do not match.");
        }

        ValidateRiskScores(evaluation);
        var confidence = evaluation.Scoring is null
            ? ParseLegacyConfidence(evaluation.ConfidenceLevel)
            : MapFormalConfidence(evaluation.Scoring.Confidence);
        var status = evaluation.Scoring is null
            ? MapStatus(evaluation.Status)
            : MostConservativeStatus(MapStatus(evaluation.Status), evaluation.Scoring.PresentationStatus);
        var reasonCodes = BuildReasonCodes(evaluation, status);
        var warningCodes = BuildWarningCodes(evaluation);
        var evidenceDigest = evidenceDigests.Compute(
            evaluation,
            reasonCodes,
            warningCodes,
            receiptPolicy);
        return new PreparedEvaluation(
            relatedEvaluationId,
            domain,
            evaluatedAtUtc,
            issuedAtUtc,
            issuedAtUtc + receiptPolicy.ValidityPeriod,
            new HipTrustReceiptScores(
                domainTrustScore: evaluation.Scoring?.DomainTrustScore ?? evaluation.DomainTrustScore,
                finalHipScore: evaluation.Scoring?.FinalHipScore ?? evaluation.FinalHipScore,
                pageTrustScore: evaluation.Scoring?.PageTrustScore ?? evaluation.PageTrustScore,
                contentRiskScore: evaluation.Scoring?.ContentRiskScore ?? evaluation.OverallSafetyRiskScore),
            status,
            confidence,
            reasonCodes,
            warningCodes,
            evidenceDigest,
            evidenceDigest.ToPrefixedString());
    }

    private HipTrustReceipt CreateReceipt(
        PreparedEvaluation evaluation,
        HipManagedTrustReceiptSigningKey signingKey,
        string signatureValue) => new(
        HipTrustReceipt.TrustReceiptDocumentType,
        HipProtocolVersion.Current,
        ReceiptId(signingKey.IssuerId, evaluation),
        evaluation.RelatedEvaluationId,
        new HipProtocolSubject(IdentitySubjectType.Website, evaluation.Domain),
        evaluation.EvaluatedAtUtc,
        evaluation.IssuedAtUtc,
        evaluation.ExpiresAtUtc,
        evaluation.Scores,
        evaluation.Status,
        evaluation.Confidence,
        evaluation.ReasonCodes,
        evaluation.WarningCodes,
        receiptPolicy.PolicyVersion,
        receiptPolicy.RuleSetVersion,
        evaluation.EvidenceDigest,
        new HipProtocolIssuer(signingKey.IssuerId),
        new HipProtocolSignature(
            HipProtocolSignature.OriginAndIntegrityScope,
            signingKey.KeyId,
            signingKey.Algorithm,
            signingKey.AlgorithmFamily,
            HipProtocolSignature.Rfc8785Canonicalization,
            signatureValue));

    private async Task<HipTrustReceiptIssueResult> ExistingResultAsync(
        HipStoredTrustReceipt existing,
        string sourceEvaluationDigest,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(existing.SourceEvaluationDigest, sourceEvaluationDigest, StringComparison.Ordinal) ||
            !string.Equals(existing.Receipt.PolicyVersion, receiptPolicy.PolicyVersion, StringComparison.Ordinal) ||
            !string.Equals(existing.Receipt.RuleSetVersion, receiptPolicy.RuleSetVersion, StringComparison.Ordinal))
        {
            return Result(HipTrustReceiptIssueStatus.Conflict);
        }

        try
        {
            var verification = await verifier.VerifyAsync(
                    Encoding.UTF8.GetBytes(existing.ReceiptJson),
                    cancellationToken)
                .ConfigureAwait(false);
            return verification is { IsVerified: true, Receipt: not null }
                ? new HipTrustReceiptIssueResult(HipTrustReceiptIssueStatus.Existing, verification.Receipt)
                : Result(HipTrustReceiptIssueStatus.VerificationFailed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result(HipTrustReceiptIssueStatus.VerificationFailed);
        }
    }

    private static IReadOnlyCollection<string> BuildReasonCodes(
        SiteSafetyScanResult evaluation,
        RiskStatus receiptStatus)
    {
        var projectedStatus = evaluation.Scoring is null
            ? evaluation.Status.ToString()
            : receiptStatus.ToString();
        var codes = new HashSet<string>(StringComparer.Ordinal)
        {
            $"status:{projectedStatus.ToLowerInvariant()}"
        };
        foreach (var entry in (evaluation.Scoring?.ReasonEntries ?? Array.Empty<HipScoringReasonEntry>())
                     .OrderBy(entry => entry.Code, StringComparer.Ordinal))
        {
            codes.Add(entry.Code);
            if (codes.Count == HipTrustReceipt.MaximumCodesPerCollection)
            {
                return codes.Order(StringComparer.Ordinal).ToArray();
            }
        }

        foreach (var rule in (evaluation.MatchedRules ?? Array.Empty<SiteSafetyRuleResult>())
                     .Where(rule => !rule.IsSimulationOnly)
                     .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
                     .Take(HipTrustReceipt.MaximumCodesPerCollection - codes.Count))
        {
            codes.Add(CanonicalCode("rule", rule.RuleId));
        }

        return codes.Order(StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyCollection<string> BuildWarningCodes(SiteSafetyScanResult evaluation)
    {
        var codes = new HashSet<string>(StringComparer.Ordinal);
        AddFormalEvidenceWarningCodes(codes, evaluation.Scoring);
        foreach (var warningCode in (evaluation.Scoring?.ReasonEntries ?? Array.Empty<HipScoringReasonEntry>())
                     .Select(entry => entry.WarningCode)
                     .Where(code => code is not null)
                     .Cast<string>()
                     .Order(StringComparer.Ordinal))
        {
            codes.Add(warningCode);
            if (codes.Count == HipTrustReceipt.MaximumCodesPerCollection)
            {
                return codes.Order(StringComparer.Ordinal).ToArray();
            }
        }

        AddRiskCode(codes, evaluation.MalwareRiskScore, "risk:malware");
        AddRiskCode(codes, evaluation.PhishingRiskScore, "risk:phishing");
        AddRiskCode(codes, evaluation.RedirectRiskScore, "risk:redirect");
        AddRiskCode(codes, evaluation.ScriptRiskScore, "risk:script");
        AddRiskCode(codes, evaluation.DownloadRiskScore, "risk:download");
        AddRiskCode(codes, evaluation.FormRiskScore, "risk:form");
        AddRiskCode(codes, evaluation.ReputationRiskScore, "risk:reputation");
        if (codes.Count >= HipTrustReceipt.MaximumCodesPerCollection)
        {
            return codes.Order(StringComparer.Ordinal).ToArray();
        }

        foreach (var rule in (evaluation.MatchedRules ?? Array.Empty<SiteSafetyRuleResult>())
                     .Where(rule => !rule.IsSimulationOnly && !string.IsNullOrWhiteSpace(rule.Warning))
                     .OrderBy(rule => rule.RuleId, StringComparer.Ordinal))
        {
            codes.Add(CanonicalCode("rule-warning", rule.RuleId));
            if (codes.Count == HipTrustReceipt.MaximumCodesPerCollection)
            {
                break;
            }
        }

        return codes.Order(StringComparer.Ordinal).ToArray();
    }

    private static void AddFormalEvidenceWarningCodes(
        ISet<string> codes,
        HipScoringResult? scoring)
    {
        if (scoring is null)
        {
            return;
        }

        if (scoring.Confidence is HipScoreConfidence.Conflicted)
        {
            codes.Add("confidence:conflicted");
        }

        switch (scoring.EvidenceFreshness)
        {
            case HipEvidenceFreshness.Missing:
                codes.Add("evidence-freshness:missing");
                break;
            case HipEvidenceFreshness.Mixed:
                codes.Add("evidence-freshness:mixed");
                break;
            case HipEvidenceFreshness.Stale:
                codes.Add("evidence-freshness:stale");
                break;
        }

        switch (scoring.TrustAssertionDisposition)
        {
            case HipTrustAssertionDisposition.WithheldConflictingEvidence:
                codes.Add("trust-assertion:withheld-conflicting-evidence");
                break;
            case HipTrustAssertionDisposition.WithheldInsufficientEvidence:
                codes.Add("trust-assertion:withheld-insufficient-evidence");
                break;
        }
    }

    private static void AddRiskCode(ISet<string> codes, int score, string code)
    {
        if (score >= 30 && codes.Count < HipTrustReceipt.MaximumCodesPerCollection)
        {
            codes.Add(code);
        }
    }

    private static string CanonicalCode(string prefix, string value)
    {
        var slug = new string(value
            .ToLowerInvariant()
            .Select(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.'
                    ? character
                    : '-')
            .ToArray()).Trim('-', '.', '_');
        if (slug.Length == 0)
        {
            slug = "unknown";
        }

        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant()[..8];
        var maximumSlugLength = HipTrustReceipt.MaximumCodeLength - prefix.Length - suffix.Length - 2;
        if (slug.Length > maximumSlugLength)
        {
            slug = slug[..maximumSlugLength];
        }

        return $"{prefix}:{slug}:{suffix}";
    }

    private static void ValidateRiskScores(SiteSafetyScanResult evaluation)
    {
        int[] scores =
        [
            evaluation.MalwareRiskScore,
            evaluation.PhishingRiskScore,
            evaluation.RedirectRiskScore,
            evaluation.ScriptRiskScore,
            evaluation.DownloadRiskScore,
            evaluation.FormRiskScore,
            evaluation.ReputationRiskScore,
            evaluation.OverallSafetyRiskScore,
            evaluation.DomainTrustScore,
            evaluation.PageTrustScore,
            evaluation.ContentRiskScore,
            evaluation.FinalHipScore
        ];
        if (scores.Any(score => score is < 0 or > 100))
        {
            throw new ArgumentOutOfRangeException(nameof(evaluation), "Authoritative evaluation scores must be between 0 and 100.");
        }
    }

    private static string RequiredEvaluationId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > HipTrustReceipt.MaximumRelatedReferenceIdLength ||
            value.Any(character =>
                character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':')))
        {
            throw new ArgumentException(
                "The authoritative evaluation ID must be a bounded HIP protocol token.",
                nameof(value));
        }

        return value;
    }

    private static RiskStatus MapStatus(SiteSafetyScanStatus status) => status switch
    {
        SiteSafetyScanStatus.Clean => RiskStatus.ProbablySafe,
        SiteSafetyScanStatus.LimitedData => RiskStatus.LimitedTrustData,
        SiteSafetyScanStatus.Unknown => RiskStatus.Unknown,
        SiteSafetyScanStatus.Suspicious => RiskStatus.Suspicious,
        SiteSafetyScanStatus.HighRisk => RiskStatus.HighRisk,
        SiteSafetyScanStatus.Dangerous => RiskStatus.Dangerous,
        SiteSafetyScanStatus.ScanFailed => RiskStatus.Unknown,
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Site Safety status is unsupported.")
    };

    private static HipTrustConfidence ParseLegacyConfidence(string value)
    {
        if (!Enum.TryParse<HipTrustConfidence>(value, ignoreCase: true, out var confidence) ||
            !Enum.IsDefined(confidence))
        {
            throw new ArgumentException("The authoritative evaluation confidence is unsupported.");
        }

        return confidence;
    }

    private static HipTrustConfidence MapFormalConfidence(HipScoreConfidence confidence) => confidence switch
    {
        HipScoreConfidence.Low => HipTrustConfidence.Low,
        HipScoreConfidence.Medium => HipTrustConfidence.Medium,
        HipScoreConfidence.High => HipTrustConfidence.High,
        HipScoreConfidence.Conflicted => HipTrustConfidence.Low,
        _ => throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "HIP scoring confidence is unsupported.")
    };

    private static RiskStatus MostConservativeStatus(RiskStatus first, RiskStatus second) =>
        StatusSeverity(first) <= StatusSeverity(second) ? first : second;

    private static int StatusSeverity(RiskStatus status) => status switch
    {
        RiskStatus.Critical => 0,
        RiskStatus.Dangerous => 1,
        RiskStatus.HighRisk => 2,
        RiskStatus.Suspicious => 3,
        RiskStatus.Caution => 4,
        RiskStatus.Unknown => 5,
        RiskStatus.LimitedTrustData => 6,
        RiskStatus.ProbablySafe => 7,
        RiskStatus.MostlyTrusted => 7,
        RiskStatus.Trusted => 8,
        _ => 5
    };

    private static DateTimeOffset ProtocolTimestamp(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return utc.AddTicks(-(utc.Ticks % TimeSpan.TicksPerMillisecond));
    }

    private static string ReceiptId(string issuerId, PreparedEvaluation evaluation)
    {
        var material = string.Join(
            '\n',
            issuerId,
            evaluation.RelatedEvaluationId,
            evaluation.SourceEvaluationDigest);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        return $"receipt:{digest}";
    }

    private static string Sha256(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    private static HipTrustReceiptIssueResult Result(HipTrustReceiptIssueStatus status) => new(status);

    private sealed record PreparedEvaluation(
        string RelatedEvaluationId,
        string Domain,
        DateTimeOffset EvaluatedAtUtc,
        DateTimeOffset IssuedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        HipTrustReceiptScores Scores,
        RiskStatus Status,
        HipTrustConfidence Confidence,
        IReadOnlyCollection<string> ReasonCodes,
        IReadOnlyCollection<string> WarningCodes,
        HipContentDigest EvidenceDigest,
        string SourceEvaluationDigest);
}
