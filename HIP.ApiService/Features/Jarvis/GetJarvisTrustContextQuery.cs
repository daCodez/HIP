using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="IdentityId">The IdentityId value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record GetJarvisTrustContextQuery(string IdentityId) : IRequest<JarvisTrustContextDto>;