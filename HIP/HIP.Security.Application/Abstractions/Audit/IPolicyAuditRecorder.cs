using HIP.Security.Domain.Audit;

namespace HIP.Security.Application.Abstractions.Audit;

public interface IPolicyAuditRecorder
{
    Task RecordAsync(PolicyAuditEvent auditEvent, CancellationToken cancellationToken = default);
}
