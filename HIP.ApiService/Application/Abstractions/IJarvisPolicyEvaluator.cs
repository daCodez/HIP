using HIP.ApiService.Application.Contracts;

namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Evaluates Jarvis policy decisions for a given request.
/// </summary>
public interface IJarvisPolicyEvaluator
{
    /// <summary>
    /// Evaluates policy and returns a structured allow/review/block response.
    /// </summary>
    Task<JarvisPolicyEvaluationResultDto> EvaluateAsync(JarvisPolicyEvaluationRequestDto request, CancellationToken cancellationToken);
}
