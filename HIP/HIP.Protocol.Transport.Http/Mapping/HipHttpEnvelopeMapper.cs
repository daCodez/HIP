using HIP.Protocol.Contracts;
using HIP.Protocol.Transport.Http.Headers;
using Microsoft.AspNetCore.Http;

namespace HIP.Protocol.Transport.Http.Mapping;

public interface IHipHttpEnvelopeMapper
{
    HipMessageEnvelope? TryReadEnvelope(HttpContext context);
    void WriteReceipt(HttpContext context, HipTrustReceipt receipt);
}

public sealed class HipHttpEnvelopeMapper : IHipHttpEnvelopeMapper
{
    public HipMessageEnvelope? TryReadEnvelope(HttpContext context)
    {
        var h = context.Request.Headers;
        if (!h.TryGetValue(HipHttpHeaders.Version, out var v)) return null;

        var tsRaw = h[HipHttpHeaders.Timestamp].ToString();
        if (!DateTimeOffset.TryParse(tsRaw, out var timestamp)) return null;

        return new HipMessageEnvelope(
            HipVersion: v.ToString(),
            MessageType: h[HipHttpHeaders.MessageType].ToString(),
            SenderHipId: h[HipHttpHeaders.Sender].ToString(),
            ReceiverHipId: h.TryGetValue(HipHttpHeaders.Receiver, out var r) ? r.ToString() : null,
            TimestampUtc: timestamp.ToUniversalTime(),
            Nonce: h[HipHttpHeaders.Nonce].ToString(),
            PayloadHash: h[HipHttpHeaders.PayloadHash].ToString(),
            Signature: h[HipHttpHeaders.Signature].ToString(),
            CorrelationId: h[HipHttpHeaders.CorrelationId].ToString(),
            DeviceId: h.TryGetValue(HipHttpHeaders.Device, out var d) ? d.ToString() : null);
    }

    public void WriteReceipt(HttpContext context, HipTrustReceipt receipt)
    {
        context.Response.Headers[HipHttpHeaders.ReceiptId] = receipt.ReceiptId;
        context.Response.Headers[HipHttpHeaders.ReceiptSignature] = receipt.ReceiptSignature;
    }
}
