using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Application.Reputation.Queries;

/// <summary>
/// Query contract for loading reputation data for a specific identity.
/// </summary>
/// <param name="IdentityId">Identity identifier whose reputation should be returned.</param>
public sealed record GetReputationByIdentityQuery(string IdentityId) : IRequest<ReputationDto>;
