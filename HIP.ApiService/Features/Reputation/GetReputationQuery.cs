using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Reputation;

public sealed record GetReputationQuery(string IdentityId) : IRequest<ReputationDto>;
