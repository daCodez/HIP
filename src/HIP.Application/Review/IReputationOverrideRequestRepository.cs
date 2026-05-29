using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReputationOverrideRequestRepository
{
    Task SaveAsync(ReputationOverrideRequest request, CancellationToken cancellationToken);

    Task<ReputationOverrideRequest?> GetAsync(string overrideRequestId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ReputationOverrideRequest>> ListAsync(CancellationToken cancellationToken);
}
