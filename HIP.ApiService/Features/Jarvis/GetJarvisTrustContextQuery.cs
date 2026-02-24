using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Jarvis;

public sealed record GetJarvisTrustContextQuery(string IdentityId) : IRequest<JarvisTrustContextDto>;