using HIP.ApiService.Application.Abstractions;
using HIP.Reputation.Domain;

namespace HIP.ApiService.Infrastructure.Reputation;

public sealed class InMemoryReputationService(ILogger<InMemoryReputationService> logger) : IReputationService
{
    public Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId); // validation
        logger.LogDebug("Reputation lookup requested for {IdentityId}", identityId); // logging/security awareness

        var score = ReputationConstants.BaseScore; // TODO(HIP): replace with full scoring pipeline
        return Task.FromResult(score); // performance awareness: constant-time response
    }
}
