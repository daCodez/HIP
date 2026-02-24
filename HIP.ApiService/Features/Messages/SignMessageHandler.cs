using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Audit;
using System.Diagnostics;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Observability;
using MediatR;

namespace HIP.ApiService.Features.Messages;

public sealed class SignMessageHandler(
    IMessageSignatureService signatureService,
    IAuditTrail auditTrail,
    ILogger<SignMessageHandler> logger) : IRequestHandler<SignMessageCommand, SignMessageResultDto>
{
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
                Detail: result.Reason),
            cancellationToken); // security awareness: audit metadata only

        stopwatch.Stop();
        HipTelemetry.Record("message.sign", result.Reason, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }
}
