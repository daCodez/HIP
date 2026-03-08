using HIP.Security.Application.Abstractions.Execution;

namespace HIP.Security.Simulator.Execution;

public sealed class ReplayService : IReplayService
{
    public Task<string> ReplayAsync(Guid campaignId, CancellationToken cancellationToken = default) =>
        Task.FromResult($"Replay requested for campaign {campaignId}. (Placeholder)");
}
