using HIP.Security.Domain.Common;

namespace HIP.Security.Application.Abstractions.Execution;

public interface ICampaignRunner
{
    Task<CampaignRunResult> RunAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
