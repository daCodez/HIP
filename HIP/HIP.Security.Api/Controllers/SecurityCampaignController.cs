using HIP.Security.Application.Campaigns.ReplayCampaign;
using HIP.Security.Application.Campaigns.RunCampaign;
using HIP.Security.Application.Coverage.EvaluateCoverage;
using HIP.Security.Application.Suggestions.GeneratePolicySuggestions;
using HIP.Security.Application.Suggestions.GenerateScenarioSuggestions;
using HIP.Security.Application.Suggestions.GenerateTelemetrySuggestions;
using HIP.Security.Api.Contracts;
using HIP.Security.Api.Security;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace HIP.Security.Api.Controllers;

[ApiController]
[Route("api/security/campaign")]
[Authorize]
public sealed class SecurityCampaignController(IMediator mediator) : ControllerBase
{
    [HttpPost("run/{campaignId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.CampaignExecute)]
    [EnableRateLimiting("campaign-sensitive")]
    public async Task<IActionResult> RunCampaign(Guid campaignId, CancellationToken cancellationToken)
    {
        var result = await mediator.Send(new RunCampaignCommand(campaignId), cancellationToken);
        return Ok(result);
    }

    [HttpGet("coverage/{campaignId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyRead)]
    public async Task<IActionResult> EvaluateCoverage(Guid campaignId, CancellationToken cancellationToken)
    {
        var result = await mediator.Send(new EvaluateCoverageQuery(campaignId), cancellationToken);
        return Ok(result);
    }

    [HttpGet("suggestions/policies/{campaignId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyRead)]
    [EnableRateLimiting("campaign-sensitive")]
    public async Task<IActionResult> PolicySuggestions(Guid campaignId, CancellationToken cancellationToken)
    {
        var result = await mediator.Send(new GeneratePolicySuggestionsQuery(campaignId), cancellationToken);
        return Ok(result);
    }

    [HttpGet("suggestions/telemetry/{campaignId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyRead)]
    [EnableRateLimiting("campaign-sensitive")]
    public async Task<IActionResult> TelemetrySuggestions(Guid campaignId, CancellationToken cancellationToken)
    {
        var result = await mediator.Send(new GenerateTelemetrySuggestionsQuery(campaignId), cancellationToken);
        return Ok(result);
    }

    [HttpGet("suggestions/scenarios/{campaignId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyRead)]
    [EnableRateLimiting("campaign-sensitive")]
    public async Task<IActionResult> ScenarioSuggestions(Guid campaignId, CancellationToken cancellationToken)
    {
        var result = await mediator.Send(new GenerateScenarioSuggestionsQuery(campaignId), cancellationToken);
        return Ok(result);
    }

    [HttpPost("replay")]
    [Authorize(Policy = SecurityAuthorizationPolicies.CampaignExecute)]
    [EnableRateLimiting("campaign-sensitive")]
    public async Task<IActionResult> ReplayCampaign([FromBody] ReplayCampaignRequest request, CancellationToken cancellationToken)
    {
        for (var i = 0; i < request.ReplayCount; i++)
        {
            await mediator.Send(new ReplayCampaignCommand(request.CampaignId), cancellationToken);
        }

        return Ok(new { message = "Replay completed.", request.ReplayCount });
    }
}
