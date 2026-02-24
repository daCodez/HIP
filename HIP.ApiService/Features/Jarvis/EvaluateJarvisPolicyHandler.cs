using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Audit;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;
using System.Diagnostics;

namespace HIP.ApiService.Features.Jarvis;

public sealed class EvaluateJarvisPolicyHandler(
    IIdentityService identityService,
    IReputationService reputationService,
    IAuditTrail auditTrail,
    ISecurityEventCounter securityCounter,
    ILogger<EvaluateJarvisPolicyHandler> logger) : IRequestHandler<EvaluateJarvisPolicyCommand, JarvisPolicyEvaluationResultDto>
{
    private static readonly string[] HighRiskMarkers =
    [
        "ignore previous instructions",
        "ignore all previous instructions",
        "developer mode",
        "print your system prompt",
        "reveal environment variables",
        "api key",
        "token",
        "password",
        "sudo",
        "chmod 777",
        "chown -r",
        "curl | bash",
        "bypass",
        "don't tell",
        "do not tell"
    ];

    public async Task<JarvisPolicyEvaluationResultDto> Handle(EvaluateJarvisPolicyCommand command, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var request = command.Request;

        var lowered = request.UserText.ToLowerInvariant();
        var reasons = new List<string>();
        var risk = "low";
        var decision = "allow";

        var matched = HighRiskMarkers.Where(lowered.Contains).Distinct().ToList();
        if (matched.Count > 0)
        {
            risk = "high";
            decision = "block";
            reasons.Add("Detected prompt-injection or secret-exfiltration patterns.");
        }

        var sanitizedLines = request.UserText
            .Split('\n')
            .Where(line => !HighRiskMarkers.Any(m => line.Contains(m, StringComparison.OrdinalIgnoreCase)))
            .Select(line => line.TrimEnd())
            .ToList();

        var sanitizedText = decision == "block"
            ? string.Empty
            : string.Join('\n', sanitizedLines).Trim();

        if (decision != "block" && string.IsNullOrWhiteSpace(sanitizedText))
        {
            decision = "review";
            risk = "medium";
            reasons.Add("Sanitization removed all actionable text.");
        }

        var identity = await identityService.GetByIdAsync(request.IdentityId, cancellationToken);
        var score = await reputationService.GetScoreAsync(request.IdentityId, cancellationToken);

        var requiredScore = request.RiskLevel switch
        {
            "low" => 20,
            "medium" => 50,
            "high" => 80,
            _ => 101
        };

        var toolAccessAllowed = decision != "block" && identity is not null && score >= requiredScore;
        var toolAccessReason = decision == "block"
            ? "policy_blocked"
            : identity is null
                ? "identity_not_found"
                : toolAccessAllowed ? "allowed" : "insufficient_reputation";

        var policyCode = decision == "block"
            ? "policy.promptInjectionDetected"
            : identity is null
                ? "policy.adminDenied"
                : toolAccessAllowed ? "policy.allowed" : "policy.lowReputation";

        if (!toolAccessAllowed && decision == "allow")
        {
            decision = "review";
            risk = risk == "low" ? "medium" : risk;
            reasons.Add("Tool access requires higher trust level.");
        }

        if (decision == "block")
        {
            securityCounter.IncrementPolicyBlocked();
            await reputationService.RecordSecurityEventAsync(request.IdentityId, "policy_blocked", cancellationToken);
        }

        if (reasons.Count == 0)
        {
            reasons.Add("No injection markers detected.");
        }

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "jarvis.policy.evaluate",
            Subject: request.IdentityId,
            Source: "api",
            Detail: $"decision={decision};risk={risk};markers={matched.Count}"), cancellationToken);

        sw.Stop();
        HipTelemetry.Record("jarvis.policy.evaluate", decision, sw.Elapsed.TotalMilliseconds);
        logger.LogInformation("Jarvis policy evaluated for {IdentityId}: decision={Decision}, risk={Risk}, toolAccess={ToolAccessReason}",
            request.IdentityId, decision, risk, toolAccessReason);

        return new JarvisPolicyEvaluationResultDto(
            decision,
            risk,
            reasons,
            sanitizedText,
            toolAccessAllowed,
            toolAccessReason,
            policyCode);
    }
}
