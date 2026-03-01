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
public sealed class VerifySignedMessageHandler(
    IMessageSignatureService signatureService,
    IAuditTrail auditTrail,
    ILogger<VerifySignedMessageHandler> logger) : IRequestHandler<VerifySignedMessageCommand, VerifyMessageResultDto>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<VerifyMessageResultDto> Handle(VerifySignedMessageCommand request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        var keyId = string.IsNullOrWhiteSpace(request.Message.KeyId) ? request.Message.From : request.Message.KeyId.Trim();
        using var _ = logger.BeginScope(new Dictionary<string, object>
        {
            ["eventType"] = "message.verify",
            ["identityId"] = request.Message.From,
            ["keyId"] = keyId
        });

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation("Handling signed message verification request from {From} to {To} using keyId {KeyId}", request.Message.From, request.Message.To, keyId);

        var result = await signatureService.VerifyAsync(request.Message, cancellationToken); // performance awareness: single verify operation

        await auditTrail.AppendAsync(
            new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "message.verify",
                Subject: request.Message.From,
                Source: "api",
                Detail: result.Reason,
                Category: "security",
                Outcome: result.IsValid ? "success" : "fail",
                ReasonCode: result.Reason,
                CorrelationId: Activity.Current?.TraceId.ToString(),
                LatencyMs: stopwatch.Elapsed.TotalMilliseconds),
            cancellationToken); // security awareness: audit metadata only

        stopwatch.Stop();
        HipTelemetry.Record("message.verify", result.Reason, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
