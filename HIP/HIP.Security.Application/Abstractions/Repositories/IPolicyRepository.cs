using HIP.Security.Domain.Policies;

namespace HIP.Security.Application.Abstractions.Repositories;

public interface IPolicyRepository
{
    Task<IReadOnlyList<SecurityPolicy>> ListAsync(CancellationToken cancellationToken = default);
    Task<SecurityPolicy?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task AddAsync(SecurityPolicy policy, CancellationToken cancellationToken = default);
    Task UpdateAsync(SecurityPolicy policy, CancellationToken cancellationToken = default);
}
