using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReputationOverrideRequestRepository
{
    Task SaveAsync(ReputationOverrideRequest request, CancellationToken cancellationToken);

    Task<ReputationOverrideRequest?> GetAsync(string overrideRequestId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ReputationOverrideRequest>> ListAsync(CancellationToken cancellationToken);
}

public sealed class InMemoryReputationOverrideRequestRepository : IReputationOverrideRequestRepository
{
    private readonly Dictionary<string, ReputationOverrideRequest> requests = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    public Task SaveAsync(ReputationOverrideRequest request, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            requests[request.OverrideRequestId] = request;
        }

        return Task.CompletedTask;
    }

    public Task<ReputationOverrideRequest?> GetAsync(string overrideRequestId, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult(requests.GetValueOrDefault(overrideRequestId));
        }
    }

    public Task<IReadOnlyCollection<ReputationOverrideRequest>> ListAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<ReputationOverrideRequest>>(requests.Values.ToArray());
        }
    }
}
