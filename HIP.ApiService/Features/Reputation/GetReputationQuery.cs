using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Reputation;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="IdentityId">The IdentityId value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record GetReputationQuery(string IdentityId) : IRequest<ReputationDto>;
