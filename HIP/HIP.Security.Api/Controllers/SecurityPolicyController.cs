using HIP.Security.Api.Contracts;
using HIP.Security.Api.Mappings;
using HIP.Security.Api.Security;
using HIP.Security.Application.Policies.ActivatePolicy;
using HIP.Security.Application.Policies.CreatePolicyDraft;
using HIP.Security.Application.Policies.Internal;
using HIP.Security.Application.Policies.RollbackPolicy;
using HIP.Security.Application.Policies.SimulatePolicy;
using HIP.Security.Domain.Approvals;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace HIP.Security.Api.Controllers;

[ApiController]
[Route("api/security/policies")]
[Authorize]
public sealed class SecurityPolicyController(IMediator mediator, IPolicyDtoMapper policyDtoMapper) : ControllerBase
{
    [HttpPost("draft")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyWrite)]
    [EnableRateLimiting("policy-write")]
    public async Task<IActionResult> CreateDraft([FromBody] CreatePolicyDraftRequest request, CancellationToken cancellationToken)
    {
        var policy = await mediator.Send(
            new CreatePolicyDraftCommand(request.Name, request.Description, policyDtoMapper.ToDomainRules(request)),
            cancellationToken);

        return Ok(policyDtoMapper.ToDto(policy));
    }

    [HttpPost("simulate/{policyId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyPromote)]
    [EnableRateLimiting("policy-promote")]
    public async Task<IActionResult> Simulate(Guid policyId, CancellationToken cancellationToken)
    {
        try
        {
            var policy = await mediator.Send(new SimulatePolicyCommand(policyId), cancellationToken);
            return Ok(policyDtoMapper.ToDto(policy));
        }
        catch (PolicyTransitionRejectedException ex)
        {
            return UnprocessableEntity(new { error = ex.Message, reasonCode = ex.ReasonCode.ToString() });
        }
    }

    [HttpPost("activate/{policyId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyPromote)]
    [EnableRateLimiting("policy-promote")]
    public async Task<IActionResult> Activate(Guid policyId, [FromBody] ActivatePolicyRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var policy = await mediator.Send(
                new ActivatePolicyCommand(
                    policyId,
                    new PolicyApprovalMetadata(
                        request.AuthorId,
                        request.ReviewerId,
                        request.ApproverId,
                        request.ChangeTicket,
                        DateTimeOffset.UtcNow)),
                cancellationToken);

            return Ok(policyDtoMapper.ToDto(policy));
        }
        catch (PolicyTransitionRejectedException ex)
        {
            return UnprocessableEntity(new { error = ex.Message, reasonCode = ex.ReasonCode.ToString() });
        }
    }

    [HttpPost("rollback/{policyId:guid}")]
    [Authorize(Policy = SecurityAuthorizationPolicies.PolicyPromote)]
    [EnableRateLimiting("policy-promote")]
    public async Task<IActionResult> Rollback(Guid policyId, [FromBody] RollbackPolicyRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await mediator.Send(new RollbackPolicyCommand(policyId, request.RequestedBy), cancellationToken);
            return Ok();
        }
        catch (PolicyTransitionRejectedException ex)
        {
            return UnprocessableEntity(new { error = ex.Message, reasonCode = ex.ReasonCode.ToString() });
        }
    }
}
