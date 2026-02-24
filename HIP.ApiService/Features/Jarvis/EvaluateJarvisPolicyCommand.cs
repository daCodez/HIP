using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Jarvis;

public sealed record EvaluateJarvisPolicyCommand(JarvisPolicyEvaluationRequestDto Request) : IRequest<JarvisPolicyEvaluationResultDto>;