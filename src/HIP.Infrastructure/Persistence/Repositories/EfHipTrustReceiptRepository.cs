using System.Security.Cryptography;
using System.Text;
using HIP.Application.Protocol;
using HIP.Domain.Protocol;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>EF-backed insert-only trust receipt repository with unique evaluation idempotency.</summary>
public sealed class EfHipTrustReceiptRepository(
    HipDbContext dbContext,
    ICanonicalJsonService canonicalJsonService) : IHipTrustReceiptRepository
{
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));

    public async Task<HipStoredTrustReceipt?> GetByIdAsync(
        string receiptId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(receiptId);
        var entity = await dbContext.TrustReceipts.AsNoTracking()
            .SingleOrDefaultAsync(receipt => receipt.ReceiptId == receiptId, cancellationToken);
        return entity is null ? null : FromEntity(entity);
    }

    public async Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
        string relatedEvaluationId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relatedEvaluationId);
        var entity = await dbContext.TrustReceipts.AsNoTracking()
            .SingleOrDefaultAsync(
                receipt => receipt.RelatedEvaluationId == relatedEvaluationId,
                cancellationToken);
        return entity is null ? null : FromEntity(entity);
    }

    public async Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
        HipStoredTrustReceipt receipt,
        CancellationToken cancellationToken)
    {
        ValidateStoredReceipt(receipt);
        var existing = await FindCollisionAsync(receipt, cancellationToken);
        if (existing is not null)
        {
            return CollisionResult(existing, receipt);
        }

        dbContext.TrustReceipts.Add(ToEntity(receipt));
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new HipTrustReceiptRepositoryWriteResult(
                HipTrustReceiptRepositoryWriteStatus.Created,
                receipt);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            existing = await FindCollisionAsync(receipt, cancellationToken);
            if (existing is null)
            {
                throw;
            }

            return CollisionResult(existing, receipt);
        }
    }

    private async Task<HipStoredTrustReceipt?> FindCollisionAsync(
        HipStoredTrustReceipt receipt,
        CancellationToken cancellationToken)
    {
        var receiptId = receipt.Receipt.ReceiptId;
        var evaluationId = receipt.Receipt.RelatedEvaluationId;
        var entity = await dbContext.TrustReceipts.AsNoTracking()
            .SingleOrDefaultAsync(
                stored => stored.ReceiptId == receiptId || stored.RelatedEvaluationId == evaluationId,
                cancellationToken);
        return entity is null ? null : FromEntity(entity);
    }

    private static HipTrustReceiptRepositoryWriteResult CollisionResult(
        HipStoredTrustReceipt existing,
        HipStoredTrustReceipt candidate) => new(
        HasSameIssuanceIdentity(existing, candidate)
            ? HipTrustReceiptRepositoryWriteStatus.ExistingSame
            : HipTrustReceiptRepositoryWriteStatus.Conflict,
        existing);

    private HipStoredTrustReceipt FromEntity(HipTrustReceiptEntity entity)
    {
        var receipt = HipTrustReceiptJson.Deserialize(entity.ReceiptJson);
        var stored = new HipStoredTrustReceipt(
            receipt,
            entity.ReceiptJson,
            entity.ReceiptDigest,
            entity.SourceEvaluationDigest);
        ValidateStoredReceipt(stored);
        if (!string.Equals(entity.ReceiptId, receipt.ReceiptId, StringComparison.Ordinal) ||
            !string.Equals(entity.RelatedEvaluationId, receipt.RelatedEvaluationId, StringComparison.Ordinal) ||
            !string.Equals(entity.DocumentType, receipt.DocumentType, StringComparison.Ordinal) ||
            !string.Equals(entity.ProtocolVersion, receipt.Version.Value, StringComparison.Ordinal) ||
            !string.Equals(entity.SubjectType, receipt.Subject.Type.ToString(), StringComparison.Ordinal) ||
            !string.Equals(entity.SubjectId, receipt.Subject.Id, StringComparison.Ordinal) ||
            entity.EvaluatedAtUtc != receipt.EvaluatedAtUtc ||
            entity.IssuedAtUtc != receipt.IssuedAtUtc ||
            entity.ExpiresAtUtc != receipt.ExpiresAtUtc ||
            !string.Equals(entity.PolicyVersion, receipt.PolicyVersion, StringComparison.Ordinal) ||
            !string.Equals(entity.RuleSetVersion, receipt.RuleSetVersion, StringComparison.Ordinal) ||
            !string.Equals(entity.EvidenceDigest, receipt.EvidenceDigest.ToPrefixedString(), StringComparison.Ordinal) ||
            !string.Equals(entity.IssuerId, receipt.Issuer.Id, StringComparison.Ordinal) ||
            !string.Equals(entity.KeyId, receipt.Signature.KeyId, StringComparison.Ordinal) ||
            !string.Equals(entity.Algorithm, receipt.Signature.Algorithm, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Stored HIP trust receipt indexes do not match the signed receipt.");
        }

        return stored;
    }

    private static HipTrustReceiptEntity ToEntity(HipStoredTrustReceipt stored) => new()
    {
        ReceiptId = stored.Receipt.ReceiptId,
        RelatedEvaluationId = stored.Receipt.RelatedEvaluationId,
        ReceiptJson = stored.ReceiptJson,
        ReceiptDigest = stored.ReceiptDigest,
        SourceEvaluationDigest = stored.SourceEvaluationDigest,
        DocumentType = stored.Receipt.DocumentType,
        ProtocolVersion = stored.Receipt.Version.Value,
        SubjectType = stored.Receipt.Subject.Type.ToString(),
        SubjectId = stored.Receipt.Subject.Id,
        EvaluatedAtUtc = stored.Receipt.EvaluatedAtUtc,
        IssuedAtUtc = stored.Receipt.IssuedAtUtc,
        ExpiresAtUtc = stored.Receipt.ExpiresAtUtc,
        PolicyVersion = stored.Receipt.PolicyVersion,
        RuleSetVersion = stored.Receipt.RuleSetVersion,
        EvidenceDigest = stored.Receipt.EvidenceDigest.ToPrefixedString(),
        IssuerId = stored.Receipt.Issuer.Id,
        KeyId = stored.Receipt.Signature.KeyId,
        Algorithm = stored.Receipt.Signature.Algorithm
    };

    private void ValidateStoredReceipt(HipStoredTrustReceipt stored)
    {
        ArgumentNullException.ThrowIfNull(stored);
        ArgumentNullException.ThrowIfNull(stored.Receipt);
        var expectedJson = HipTrustReceiptJson.Serialize(stored.Receipt);
        if (!string.Equals(stored.ReceiptJson, expectedJson, StringComparison.Ordinal))
        {
            throw new ArgumentException("Stored HIP receipt JSON must be the exact validated wire representation.", nameof(stored));
        }

        var expectedDigest = Sha256(canonicalizer.Canonicalize(Encoding.UTF8.GetBytes(stored.ReceiptJson)));
        if (!string.Equals(stored.ReceiptDigest, expectedDigest, StringComparison.Ordinal))
        {
            throw new ArgumentException("Stored HIP receipt digest does not match the signed receipt JSON.", nameof(stored));
        }

        if (!string.Equals(
                stored.SourceEvaluationDigest,
                stored.Receipt.EvidenceDigest.ToPrefixedString(),
                StringComparison.Ordinal))
        {
            throw new ArgumentException("Stored HIP source evaluation digest does not match the receipt evidence digest.", nameof(stored));
        }
    }

    private static bool HasSameIssuanceIdentity(HipStoredTrustReceipt existing, HipStoredTrustReceipt candidate) =>
        string.Equals(existing.Receipt.ReceiptId, candidate.Receipt.ReceiptId, StringComparison.Ordinal) &&
        string.Equals(
            existing.Receipt.RelatedEvaluationId,
            candidate.Receipt.RelatedEvaluationId,
            StringComparison.Ordinal) &&
        string.Equals(existing.SourceEvaluationDigest, candidate.SourceEvaluationDigest, StringComparison.Ordinal) &&
        string.Equals(existing.Receipt.PolicyVersion, candidate.Receipt.PolicyVersion, StringComparison.Ordinal) &&
        string.Equals(existing.Receipt.RuleSetVersion, candidate.Receipt.RuleSetVersion, StringComparison.Ordinal) &&
        string.Equals(existing.Receipt.Issuer.Id, candidate.Receipt.Issuer.Id, StringComparison.Ordinal) &&
        string.Equals(existing.ReceiptJson, candidate.ReceiptJson, StringComparison.Ordinal) &&
        string.Equals(existing.ReceiptDigest, candidate.ReceiptDigest, StringComparison.Ordinal);

    private static string Sha256(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";
}
