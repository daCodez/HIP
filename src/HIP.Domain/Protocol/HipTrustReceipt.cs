using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using HIP.Domain.Risk;

namespace HIP.Domain.Protocol;

/// <summary>Raised when signed JSON uses another protocol document type in the trust-receipt verifier.</summary>
public sealed class HipTrustReceiptDocumentTypeException(string? documentType)
    : NotSupportedException($"HIP document type '{documentType}' is not a trust receipt.");

/// <summary>Bounded confidence labels carried by signed HIP trust receipts.</summary>
public enum HipTrustConfidence
{
    Low = 1,
    Medium,
    High
}

/// <summary>
/// Layered scores captured at evaluation time. Trust scores increase with trust, while content risk increases with risk.
/// </summary>
public sealed record HipTrustReceiptScores
{
    [JsonConstructor]
    public HipTrustReceiptScores(
        int domainTrustScore,
        int finalHipScore,
        int? pageTrustScore = null,
        int? contentRiskScore = null)
    {
        DomainTrustScore = RequiredScore(domainTrustScore, nameof(domainTrustScore));
        PageTrustScore = OptionalScore(pageTrustScore, nameof(pageTrustScore));
        ContentRiskScore = OptionalScore(contentRiskScore, nameof(contentRiskScore));
        FinalHipScore = RequiredScore(finalHipScore, nameof(finalHipScore));
    }

    [JsonPropertyName("domainTrustScore")]
    [JsonPropertyOrder(0)]
    public int DomainTrustScore { get; }

    [JsonPropertyName("pageTrustScore")]
    [JsonPropertyOrder(1)]
    public int? PageTrustScore { get; }

    /// <summary>Gets a 0-100 score where larger values mean greater content risk.</summary>
    [JsonPropertyName("contentRiskScore")]
    [JsonPropertyOrder(2)]
    public int? ContentRiskScore { get; }

    [JsonPropertyName("finalHipScore")]
    [JsonPropertyOrder(3)]
    public int FinalHipScore { get; }

    [JsonIgnore]
    public bool ContentRiskScoreHigherMeansMoreRisk => true;

    private static int RequiredScore(int value, string parameterName)
    {
        if (value is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "HIP receipt scores must be between 0 and 100.");
        }

        return value;
    }

    private static int? OptionalScore(int? value, string parameterName) =>
        value is null ? null : RequiredScore(value.Value, parameterName);
}

/// <summary>
/// Immutable, privacy-safe statement of what HIP evaluated. The signature proves origin and integrity only;
/// the receipt's bounded evidence and score fields carry the separate trust decision.
/// </summary>
public sealed record HipTrustReceipt
{
    public const string TrustReceiptDocumentType = "hip-trust-receipt";
    public const int MaximumReceiptIdLength = 128;
    public const int MaximumRelatedReferenceIdLength = 256;
    public const int MaximumVersionTokenLength = 128;
    public const int MaximumCodeLength = 128;
    public const int MaximumCodesPerCollection = 32;

    [JsonConstructor]
    public HipTrustReceipt(
        string documentType,
        HipProtocolVersion version,
        string receiptId,
        string relatedEvaluationId,
        HipProtocolSubject subject,
        DateTimeOffset evaluatedAtUtc,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        HipTrustReceiptScores scores,
        RiskStatus status,
        HipTrustConfidence confidence,
        IReadOnlyCollection<string> reasonCodes,
        IReadOnlyCollection<string> warningCodes,
        string policyVersion,
        string ruleSetVersion,
        HipContentDigest evidenceDigest,
        HipProtocolIssuer issuer,
        HipProtocolSignature signature)
    {
        if (!string.Equals(documentType, TrustReceiptDocumentType, StringComparison.Ordinal))
        {
            throw new HipTrustReceiptDocumentTypeException(documentType);
        }

        if (!version.IsSupported)
        {
            throw new NotSupportedException($"HIP protocol version '{version}' is unsupported.");
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "HIP trust receipt status is unsupported.");
        }

        if (!Enum.IsDefined(confidence))
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "HIP trust receipt confidence is unsupported.");
        }

        DocumentType = documentType;
        Version = version;
        ReceiptId = HipProtocolValidation.RequiredToken(receiptId, nameof(receiptId), MaximumReceiptIdLength);
        RelatedEvaluationId = HipProtocolValidation.RequiredToken(
            relatedEvaluationId,
            nameof(relatedEvaluationId),
            MaximumRelatedReferenceIdLength);
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        EvaluatedAtUtc = HipProtocolValidation.RequiredUtcTimestamp(evaluatedAtUtc, nameof(evaluatedAtUtc));
        IssuedAtUtc = HipProtocolValidation.RequiredUtcTimestamp(issuedAtUtc, nameof(issuedAtUtc));
        ExpiresAtUtc = HipProtocolValidation.RequiredUtcTimestamp(expiresAtUtc, nameof(expiresAtUtc));
        if (EvaluatedAtUtc > IssuedAtUtc)
        {
            throw new ArgumentException("HIP receipt evaluation time cannot be later than issuance.", nameof(evaluatedAtUtc));
        }

        if (ExpiresAtUtc <= IssuedAtUtc)
        {
            throw new ArgumentException("HIP receipt expiry must be later than issuance.", nameof(expiresAtUtc));
        }

        Scores = scores ?? throw new ArgumentNullException(nameof(scores));
        Status = status;
        Confidence = confidence;
        ReasonCodes = NormalizeCodes(reasonCodes, nameof(reasonCodes), allowEmpty: false);
        WarningCodes = NormalizeCodes(warningCodes, nameof(warningCodes), allowEmpty: true);
        PolicyVersion = HipProtocolValidation.RequiredToken(
            policyVersion,
            nameof(policyVersion),
            MaximumVersionTokenLength);
        RuleSetVersion = HipProtocolValidation.RequiredToken(
            ruleSetVersion,
            nameof(ruleSetVersion),
            MaximumVersionTokenLength);
        EvidenceDigest = evidenceDigest ?? throw new ArgumentNullException(nameof(evidenceDigest));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
    }

    [JsonPropertyName("documentType")]
    [JsonPropertyOrder(0)]
    public string DocumentType { get; }

    [JsonPropertyName("version")]
    [JsonPropertyOrder(1)]
    public HipProtocolVersion Version { get; }

    [JsonPropertyName("receiptId")]
    [JsonPropertyOrder(2)]
    public string ReceiptId { get; }

    [JsonPropertyName("relatedEvaluationId")]
    [JsonPropertyOrder(3)]
    public string RelatedEvaluationId { get; }

    [JsonPropertyName("subject")]
    [JsonPropertyOrder(4)]
    public HipProtocolSubject Subject { get; }

    [JsonPropertyName("evaluatedAtUtc")]
    [JsonPropertyOrder(5)]
    public DateTimeOffset EvaluatedAtUtc { get; }

    [JsonPropertyName("issuedAtUtc")]
    [JsonPropertyOrder(6)]
    public DateTimeOffset IssuedAtUtc { get; }

    [JsonPropertyName("expiresAtUtc")]
    [JsonPropertyOrder(7)]
    public DateTimeOffset ExpiresAtUtc { get; }

    [JsonPropertyName("scores")]
    [JsonPropertyOrder(8)]
    public HipTrustReceiptScores Scores { get; }

    [JsonPropertyName("status")]
    [JsonPropertyOrder(9)]
    public RiskStatus Status { get; }

    [JsonPropertyName("confidence")]
    [JsonPropertyOrder(10)]
    public HipTrustConfidence Confidence { get; }

    [JsonPropertyName("reasonCodes")]
    [JsonPropertyOrder(11)]
    public IReadOnlyCollection<string> ReasonCodes { get; }

    [JsonPropertyName("warningCodes")]
    [JsonPropertyOrder(12)]
    public IReadOnlyCollection<string> WarningCodes { get; }

    [JsonPropertyName("policyVersion")]
    [JsonPropertyOrder(13)]
    public string PolicyVersion { get; }

    [JsonPropertyName("ruleSetVersion")]
    [JsonPropertyOrder(14)]
    public string RuleSetVersion { get; }

    [JsonPropertyName("evidenceDigest")]
    [JsonPropertyOrder(15)]
    public HipContentDigest EvidenceDigest { get; }

    [JsonPropertyName("issuer")]
    [JsonPropertyOrder(16)]
    public HipProtocolIssuer Issuer { get; }

    [JsonPropertyName("signature")]
    [JsonPropertyOrder(17)]
    public HipProtocolSignature Signature { get; }

    [JsonIgnore]
    public bool EstablishesSafetyOrReputationBySignatureAlone => false;

    private static ReadOnlyCollection<string> NormalizeCodes(
        IReadOnlyCollection<string> codes,
        string parameterName,
        bool allowEmpty)
    {
        ArgumentNullException.ThrowIfNull(codes, parameterName);
        if ((!allowEmpty && codes.Count == 0) || codes.Count > MaximumCodesPerCollection)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"HIP receipt code collections must contain between {(allowEmpty ? 0 : 1)} and {MaximumCodesPerCollection} values.");
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in codes)
        {
            var code = HipProtocolValidation.RequiredToken(value, parameterName, MaximumCodeLength);
            if (!string.Equals(code, code.ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new ArgumentException("HIP receipt codes must use canonical lowercase tokens.", parameterName);
            }

            if (!unique.Add(code))
            {
                throw new ArgumentException("HIP receipt code collections cannot contain duplicates.", parameterName);
            }
        }

        return Array.AsReadOnly(unique.Order(StringComparer.Ordinal).ToArray());
    }
}
