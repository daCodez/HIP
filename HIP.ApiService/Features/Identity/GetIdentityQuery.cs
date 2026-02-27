using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Identity;

public sealed record GetIdentityQuery(string Id) : IRequest<IdentityDto?>;
