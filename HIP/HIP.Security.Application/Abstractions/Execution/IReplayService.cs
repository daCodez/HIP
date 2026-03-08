namespace HIP.Security.Application.Abstractions.Execution;

public interface IReplayService
{
    Task<string> ReplayAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
