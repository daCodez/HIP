using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Application.Reputation.Queries;

public sealed record GetReputationByIdentityQuery(string IdentityId) : IRequest<ReputationDto>;
