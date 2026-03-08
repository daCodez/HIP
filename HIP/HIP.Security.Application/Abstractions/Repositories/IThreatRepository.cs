using HIP.Security.Domain.Threats;

namespace HIP.Security.Application.Abstractions.Repositories;

public interface IThreatRepository
{
    Task<IReadOnlyList<ThreatModel>> ListAsync(CancellationToken cancellationToken = default);
    Task AddAsync(ThreatModel threat, CancellationToken cancellationToken = default);
}
