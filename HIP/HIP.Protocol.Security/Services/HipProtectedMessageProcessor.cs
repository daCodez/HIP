using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Flows;
using HIP.Protocol.Security.Abstractions;

namespace HIP.Protocol.Security.Services;

public sealed class HipProtectedMessageProcessor(
    HipEnvelopeSecurityService envelopeVerifier,
    HipReceiptSecurityService receiptService,
    IHipPayloadHasher hasher)
{
    public async Task<HipProtectedMessageResult> ProcessAsync(
        HipProtectedMessage message,
        string senderKeyId,
        string verifierKeyId,
        Func<HipMessageEnvelope, HipPolicyDecision>? policyEvaluator = null,
        CancellationToken ct = default)
    {
        var computedHash = hasher.ComputePayloadHash(message.Payload ?? string.Empty);
        if (!string.Equals(computedHash, message.Envelope.PayloadHash, StringComparison.OrdinalIgnoreCase))
        {
            var error = new HipError(HipErrorCode.InvalidEnvelope, "Payload hash mismatch.", message.Envelope.CorrelationId);
            var decision = new HipPolicyDecision(HipDecision.Block, "Payload hash mismatch", [], DateTimeOffset.UtcNow);
            return new HipProtectedMessageResult(false, decision, null, error);
        }

        var verify = await envelopeVerifier.VerifyAsync(message.Envelope, senderKeyId, ct);
        if (!verify.Success)
        {
            var decision = new HipPolicyDecision(HipDecision.Block, verify.Error?.Message ?? "Verification failed", [], DateTimeOffset.UtcNow);
            return new HipProtectedMessageResult(false, decision, null, verify.Error);
        }

        var decisionOut = policyEvaluator?.Invoke(message.Envelope)
            ?? new HipPolicyDecision(HipDecision.Allow, "Verified by HIP protocol", [], DateTimeOffset.UtcNow);

        var receipt = receiptService.Issue(new HipTrustReceipt(
            ReceiptId: Guid.NewGuid().ToString("N"),
            HipVersion: message.Envelope.HipVersion,
            InteractionType: message.Envelope.MessageType,
            SenderHipId: message.Envelope.SenderHipId,
            ReceiverHipId: message.Envelope.ReceiverHipId,
            TimestampUtc: DateTimeOffset.UtcNow,
            MessageHash: message.Envelope.PayloadHash,
            DeviceId: message.Envelope.DeviceId,
            Checks: ["signature", "nonce", "timestamp", "payloadhash"],
            Decision: decisionOut.Decision,
            AppliedPolicyIds: decisionOut.AppliedPolicyIds,
            ReputationSnapshot: null,
            ReceiptSignature: string.Empty), verifierKeyId);

        return new HipProtectedMessageResult(decisionOut.Decision is not HipDecision.Block and not HipDecision.Quarantine, decisionOut, receipt);
    }
}
