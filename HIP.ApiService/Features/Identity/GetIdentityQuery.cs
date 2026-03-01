using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Identity;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="Id">The Id value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record GetIdentityQuery(string Id) : IRequest<IdentityDto?>;
