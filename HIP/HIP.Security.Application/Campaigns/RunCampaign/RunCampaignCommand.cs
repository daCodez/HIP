using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Domain.Common;
using MediatR;

namespace HIP.Security.Application.Campaigns.RunCampaign;

public sealed record RunCampaignCommand(Guid CampaignId) : IRequest<CampaignRunResult>;

public sealed class RunCampaignCommandHandler(ICampaignRunner campaignRunner) : IRequestHandler<RunCampaignCommand, CampaignRunResult>
{
    public Task<CampaignRunResult> Handle(RunCampaignCommand request, CancellationToken cancellationToken) =>
        campaignRunner.RunAsync(request.CampaignId, cancellationToken);
}
