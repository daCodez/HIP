using HIP.Security.Application.Abstractions.Execution;
using MediatR;

namespace HIP.Security.Application.Campaigns.ReplayCampaign;

public sealed record ReplayCampaignCommand(Guid CampaignId) : IRequest<string>;

public sealed class ReplayCampaignCommandHandler(IReplayService replayService) : IRequestHandler<ReplayCampaignCommand, string>
{
    public Task<string> Handle(ReplayCampaignCommand request, CancellationToken cancellationToken) =>
        replayService.ReplayAsync(request.CampaignId, cancellationToken);
}
