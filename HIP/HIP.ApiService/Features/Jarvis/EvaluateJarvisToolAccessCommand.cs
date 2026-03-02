using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="Request">The Request value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record EvaluateJarvisToolAccessCommand(JarvisToolAccessRequestDto Request) : IRequest<JarvisToolAccessResultDto>;