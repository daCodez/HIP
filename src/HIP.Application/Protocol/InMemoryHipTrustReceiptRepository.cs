using System.Security.Cryptography;
using System.Text;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>Thread-safe insert-only receipt repository for focused tests and explicit in-memory hosts.</summary>
public sealed class InMemoryHipTrustReceiptRepository : IHipTrustReceiptRepository
{
    private readonly object gate = new();
    private readonly Dictionary<string, HipStoredTrustReceipt> receiptsById = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HipStoredTrustReceipt> receiptsByEvaluationId = new(StringComparer.Ordinal);
    private readonly ICanonicalJsonService canonicalizer;

    public InMemoryHipTrustReceiptRepository(ICanonicalJsonService? canonicalJsonService = null)
    {
        canonicalizer = canonicalJsonService ?? new Rfc8785CanonicalJsonService();
    }

    public Task<HipStoredTrustReceipt?> GetByIdAsync(
        string receiptId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(receiptId);
        lock (gate)
        {
            return Task.FromResult(receiptsById.GetValueOrDefault(receiptId));
        }
    }

    public Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
        string relatedEvaluationId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(relatedEvaluationId);
        lock (gate)
        {
            return Task.FromResult(receiptsByEvaluationId.GetValueOrDefault(relatedEvaluationId));
        }
    }

    public Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
        HipStoredTrustReceipt receipt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateStoredReceipt(receipt);
        lock (gate)
        {
            receiptsById.TryGetValue(receipt.Receipt.ReceiptId, out var receiptCollision);
            receiptsByEvaluationId.TryGetValue(receipt.Receipt.RelatedEvaluationId, out var evaluationCollision);
            var existing = receiptCollision ?? evaluationCollision;
            if (existing is not null)
            {
                var same = ReferenceEquals(receiptCollision, evaluationCollision) &&
                    HasSameIssuanceIdentity(existing, receipt);
                return Task.FromResult(new HipTrustReceiptRepositoryWriteResult(
                    same
                        ? HipTrustReceiptRepositoryWriteStatus.ExistingSame
                        : HipTrustReceiptRepositoryWriteStatus.Conflict,
                    existing));
            }

            receiptsById.Add(receipt.Receipt.ReceiptId, receipt);
            receiptsByEvaluationId.Add(receipt.Receipt.RelatedEvaluationId, receipt);
            return Task.FromResult(new HipTrustReceiptRepositoryWriteResult(
                HipTrustReceiptRepositoryWriteStatus.Created,
                receipt));
        }
    }

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
