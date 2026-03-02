using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Application.Contracts;
using MediatR;
using System.Diagnostics;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <returns>The operation result.</returns>
public sealed class EvaluateJarvisPolicyHandler(
    IJarvisPolicyEvaluator policyEvaluator,
    IAuditTrail auditTrail) : IRequestHandler<EvaluateJarvisPolicyCommand, JarvisPolicyEvaluationResultDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="command">The command value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<JarvisPolicyEvaluationResultDto> Handle(EvaluateJarvisPolicyCommand command, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var request = command.Request;

        var result = await policyEvaluator.EvaluateAsync(request, cancellationToken);

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "jarvis.policy.evaluate",
            Subject: request.IdentityId,
            Source: "api",
            Detail: $"decision={result.Decision};risk={result.Risk};policyVersion={result.PolicyVersion};identityExists={result.DecisionTrace.IdentityExists};reputationScore={result.DecisionTrace.ReputationScore}",
            Category: "policy",
            Outcome: result.Decision,
            ReasonCode: result.PolicyCode,
            CorrelationId: Activity.Current?.TraceId.ToString(),
            LatencyMs: sw.Elapsed.TotalMilliseconds), cancellationToken);

        return result;
    }
}
