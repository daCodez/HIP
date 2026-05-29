using HIP.Application.Review;
using HIP.Domain.Review;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfReputationOverrideRequestRepository(HipRecordStore store) : IReputationOverrideRequestRepository
{
    private const string Partition = "reputation-override";

    public Task SaveAsync(ReputationOverrideRequest request, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, request.OverrideRequestId, request, cancellationToken);

    public Task<ReputationOverrideRequest?> GetAsync(string overrideRequestId, CancellationToken cancellationToken) =>
        store.GetAsync<ReputationOverrideRequest>(Partition, overrideRequestId, cancellationToken);

    public Task<IReadOnlyCollection<ReputationOverrideRequest>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<ReputationOverrideRequest>(Partition, cancellationToken);
}
