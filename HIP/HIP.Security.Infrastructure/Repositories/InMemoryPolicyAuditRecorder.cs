using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Domain.Audit;

namespace HIP.Security.Infrastructure.Repositories;

public sealed class InMemoryPolicyAuditRecorder : IPolicyAuditRecorder
{
    private readonly List<PolicyAuditEvent> _events = [];

    public Task RecordAsync(PolicyAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        _events.Add(auditEvent with
        {
            Metadata = new Dictionary<string, string>(auditEvent.Metadata)
        });

        return Task.CompletedTask;
    }

    public IReadOnlyList<PolicyAuditEvent> Snapshot() => _events.AsReadOnly();
}
