using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Messages;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <returns>The operation result.</returns>
public sealed class SignMessageHandler(
    IMessageSignatureService signatureService,
    IAuditTrail auditTrail,
    ILogger<SignMessageHandler> logger) : IRequestHandler<SignMessageCommand, SignMessageResultDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<SignMessageResultDto> Handle(SignMessageCommand request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        var keyId = string.IsNullOrWhiteSpace(request.Request.KeyId) ? request.Request.From : request.Request.KeyId.Trim();
        using var _ = logger.BeginScope(new Dictionary<string, object>
        {
            ["eventType"] = "message.sign",
            ["identityId"] = request.Request.From,
            ["keyId"] = keyId
        });

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation("Handling message sign request from {From} to {To} using keyId {KeyId}", request.Request.From, request.Request.To, keyId);

        var result = await signatureService.SignAsync(request.Request, cancellationToken);

        await auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "message.sign",
                Subject: request.Request.From,
                Source: "api",
                Detail: result.Reason,
                Category: "security",
                Outcome: result.Success ? "success" : "fail",
                ReasonCode: result.Reason,
                CorrelationId: Activity.Current?.TraceId.ToString(),
                LatencyMs: stopwatch.Elapsed.TotalMilliseconds),
            cancellationToken); // security awareness: audit metadata only

        stopwatch.Stop();
        HipTelemetry.Record("message.sign", result.Reason, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
