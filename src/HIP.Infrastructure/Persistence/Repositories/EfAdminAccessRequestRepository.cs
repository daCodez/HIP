using System.Security.Cryptography;
using System.Text;
using HIP.Application.Administration;
using HIP.Domain.Audit;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Stores privacy-minimized access requests encrypted with append-only audit entries.</summary>
public sealed class EfAdminAccessRequestRepository(HipRecordStore store) : IAdminAccessRequestRepository
{
    private const string Partition = "admin-access-request";
    private const string AuditPartition = "audit-log";

    public async Task<AdminAccessRequestRecord?> GetForActorAsync(string actorId, CancellationToken cancellationToken)
    {
        var stored = await store.GetVersionedAsync<AdminAccessRequestRecord>(
            Partition, RecordId(actorId), cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        Validate(stored.Value.Record);
        if (stored.Value.AggregateVersion != stored.Value.Record.Version ||
            !string.Equals(stored.Value.Record.ActorId, actorId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Administrator access request identity or version is inconsistent.");
        }

        return stored.Value.Record;
    }

    public async Task<IReadOnlyCollection<AdminAccessRequestRecord>> ListAsync(CancellationToken cancellationToken)
    {
        var requests = await store.ListAsync<AdminAccessRequestRecord>(Partition, cancellationToken).ConfigureAwait(false);
        foreach (var request in requests)
        {
            Validate(request);
        }

        return requests;
    }

    public Task<bool> TrySaveAsync(
        AdminAccessRequestRecord request,
        long expectedVersion,
        AuditLogEntry auditEntry,
        CancellationToken cancellationToken)
    {
        Validate(request);
        ArgumentNullException.ThrowIfNull(auditEntry);
        if (request.Version != expectedVersion + 1)
        {
            throw new ArgumentException("Administrator access request versions must advance by exactly one.", nameof(request));
        }

        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            RecordId(request.ActorId),
            request,
            expectedVersion,
            request.Version,
            [(HipRelatedRecordWrite)new HipRelatedRecordWrite<AuditLogEntry>(
                AuditPartition, auditEntry.AuditLogId, auditEntry)],
            cancellationToken);
    }

    private static string RecordId(string actorId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(actorId))).ToLowerInvariant();

    private static void Validate(AdminAccessRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.RequestId) ||
            request.RequestId.Length != 32 || !request.RequestId.All(char.IsAsciiHexDigit) ||
            string.IsNullOrWhiteSpace(request.ActorId) || request.ActorId.Length > 160 ||
            !request.ActorId.All(character => char.IsAsciiLetterOrDigit(character) || character is ':' or '.' or '_' or '-') ||
            string.IsNullOrWhiteSpace(request.DisplayLabel) ||
            request.DisplayLabel.Trim().Length is < 2 or > 80 || request.DisplayLabel.Contains('@') ||
            string.IsNullOrWhiteSpace(request.Reason) ||
            request.Reason.Trim().Length is < 5 or > 500 ||
            request.DisplayLabel.Any(char.IsControl) || request.Reason.Any(char.IsControl) ||
            !Enum.IsDefined(request.Status) || request.Version < 1 ||
            request.CreatedAtUtc == default || request.UpdatedAtUtc < request.CreatedAtUtc)
        {
            throw new ArgumentException("Administrator access request state is invalid.", nameof(request));
        }
    }
}
