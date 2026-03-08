using System.Text.Json;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Services;
using HIP.Protocol.Transport.Http.Mapping;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HIP.Protocol.Transport.Http.Middleware;

public sealed class HipProtocolMiddleware(
    RequestDelegate next,
    IHipHttpEnvelopeMapper mapper,
    HipEnvelopeSecurityService verifier,
    HipReceiptSecurityService receiptService,
    ILogger<HipProtocolMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var envelope = mapper.TryReadEnvelope(context);
        if (envelope is null)
        {
            await next(context);
            return;
        }

        var keyId = envelope.SenderHipId;
        var result = await verifier.VerifyAsync(envelope, keyId, context.RequestAborted);
        if (!result.Success)
        {
            logger.LogWarning("HIP verification failed: {Code} correlation={CorrelationId}", result.Error?.Code, envelope.CorrelationId);
            var error = result.Error ?? new HipError(HipErrorCode.InvalidEnvelope, "HIP verification failed.", envelope.CorrelationId);
            context.Response.StatusCode = MapStatus(error.Code);
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(error));
            return;
        }

        await next(context);

        if (context.Response.HasStarted || context.Response.StatusCode >= StatusCodes.Status500InternalServerError)
        {
            return;
        }

        try
        {
            var verifierKeyId = envelope.ReceiverHipId ?? "hip-http-verifier";
            var unsignedReceipt = new HipTrustReceipt(
                ReceiptId: Guid.NewGuid().ToString("N"),
                HipVersion: envelope.HipVersion,
                InteractionType: envelope.MessageType,
                SenderHipId: envelope.SenderHipId,
                ReceiverHipId: envelope.ReceiverHipId,
                TimestampUtc: DateTimeOffset.UtcNow,
                MessageHash: envelope.PayloadHash,
                DeviceId: envelope.DeviceId,
                Checks: ["signature", "nonce", "timestamp"],
                Decision: HipDecision.Allow,
                AppliedPolicyIds: [],
                ReputationSnapshot: null,
                ReceiptSignature: string.Empty);

            var issued = receiptService.Issue(unsignedReceipt, verifierKeyId);
            mapper.WriteReceipt(context, issued);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "HIP receipt issuance skipped for correlation={CorrelationId}", envelope.CorrelationId);
        }
    }

    private static int MapStatus(HipErrorCode code)
        => code switch
        {
            HipErrorCode.InvalidEnvelope => StatusCodes.Status400BadRequest,
            HipErrorCode.UnsupportedVersion => StatusCodes.Status400BadRequest,
            HipErrorCode.ReplayDetected => StatusCodes.Status409Conflict,
            HipErrorCode.KeyRevoked => StatusCodes.Status403Forbidden,
            HipErrorCode.PolicyViolation => StatusCodes.Status403Forbidden,
            HipErrorCode.InvalidSignature or HipErrorCode.UnknownIdentity or HipErrorCode.TimestampExpired => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status401Unauthorized
        };
}

public static class HipProtocolMiddlewareExtensions
{
    public static IApplicationBuilder UseHipProtocol(this IApplicationBuilder app)
        => app.UseMiddleware<HipProtocolMiddleware>();
}
