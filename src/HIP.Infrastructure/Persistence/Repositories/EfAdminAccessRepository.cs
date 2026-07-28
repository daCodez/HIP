using HIP.Application.Administration;
using HIP.Domain.Audit;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Stores the bounded administrator directory encrypted with its append-only audit entry.</summary>
public sealed class EfAdminAccessRepository(HipRecordStore store) : IAdminAccessRepository
{
    private const string Partition = "admin-access-directory";
    private const string DirectoryId = "global";
    private const string AuditPartition = "audit-log";

    public async Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken)
    {
        var stored = await store.GetVersionedAsync<AdminAccessDirectory>(Partition, DirectoryId, cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        if (stored.Value.AggregateVersion != stored.Value.Record.Version)
        {
            throw new InvalidOperationException("Administrator directory version is inconsistent.");
        }

        Validate(stored.Value.Record);
        return stored.Value.Record;
    }

    public Task<bool> TrySaveAsync(
        AdminAccessDirectory directory,
        long expectedVersion,
        AuditLogEntry auditEntry,
        CancellationToken cancellationToken)
    {
        Validate(directory);
        ArgumentNullException.ThrowIfNull(auditEntry);
        if (directory.Version != expectedVersion + 1)
        {
            throw new ArgumentException("Administrator directory versions must advance by exactly one.", nameof(directory));
        }

        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            DirectoryId,
            directory,
            expectedVersion,
            directory.Version,
            [(HipRelatedRecordWrite)new HipRelatedRecordWrite<AuditLogEntry>(
                AuditPartition, auditEntry.AuditLogId, auditEntry)],
            cancellationToken);
    }

    private static void Validate(AdminAccessDirectory directory)
    {
        ArgumentNullException.ThrowIfNull(directory);
        if (directory.Version < 1 || directory.Assignments.Count is < 1 or > 500 ||
            directory.UpdatedAtUtc == default ||
            directory.Assignments.Select(item => item.ActorId).Distinct(StringComparer.Ordinal).Count() != directory.Assignments.Count)
        {
            throw new ArgumentException("Administrator directory state is invalid.", nameof(directory));
        }

        if (!directory.Assignments.Any(item =>
                item.Status == AdminAccessStatus.Active &&
                string.Equals(item.Role, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase)) ||
            directory.Assignments.Any(item =>
                string.IsNullOrWhiteSpace(item.ActorId) || item.ActorId.Length > 160 ||
                !item.ActorId.All(character => char.IsAsciiLetterOrDigit(character) || character is ':' or '.' or '_' or '-') ||
                item.DisplayLabel.Trim().Length is < 2 or > 80 || item.DisplayLabel.Contains('@') ||
                !AdminAccessRoleNames.All.Contains(item.Role) || !Enum.IsDefined(item.Status) ||
                item.CreatedAtUtc == default || item.UpdatedAtUtc < item.CreatedAtUtc))
        {
            throw new ArgumentException("Administrator assignments are invalid or contain no active Owner.", nameof(directory));
        }
    }
}