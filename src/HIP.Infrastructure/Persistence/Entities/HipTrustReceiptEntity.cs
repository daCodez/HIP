namespace HIP.Infrastructure.Persistence.Entities;

/// <summary>Insert-only indexed projection of one exact signed HIP trust receipt.</summary>
public sealed class HipTrustReceiptEntity
{
    public required string ReceiptId { get; set; }

    public required string RelatedEvaluationId { get; set; }

    public required string ReceiptJson { get; set; }

    public required string ReceiptDigest { get; set; }

    public required string SourceEvaluationDigest { get; set; }

    public required string DocumentType { get; set; }

    public required string ProtocolVersion { get; set; }

    public required string SubjectType { get; set; }

    public required string SubjectId { get; set; }

    public DateTimeOffset EvaluatedAtUtc { get; set; }

    public DateTimeOffset IssuedAtUtc { get; set; }

    public DateTimeOffset ExpiresAtUtc { get; set; }

    public required string PolicyVersion { get; set; }

    public required string RuleSetVersion { get; set; }

    public required string EvidenceDigest { get; set; }

    public required string IssuerId { get; set; }

    public required string KeyId { get; set; }

    public required string Algorithm { get; set; }
}
