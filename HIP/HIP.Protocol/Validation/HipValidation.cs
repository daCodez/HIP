using HIP.Protocol.Contracts;

namespace HIP.Protocol.Validation;

public sealed record HipValidationError(string Field, string Message);

public sealed class HipValidationResult
{
    public bool IsValid => Errors.Count == 0;
    public List<HipValidationError> Errors { get; } = [];

    public static HipValidationResult Success() => new();

    public static HipValidationResult Fail(params HipValidationError[] errors)
    {
        var result = new HipValidationResult();
        result.Errors.AddRange(errors);
        return result;
    }

    public void Add(string field, string message) => Errors.Add(new HipValidationError(field, message));
}

public interface IHipEnvelopeValidator
{
    HipValidationResult Validate(HipMessageEnvelope envelope);
}

public interface IHipReceiptValidator
{
    HipValidationResult Validate(HipTrustReceipt receipt, bool requireSignature = true);
}

public sealed class HipEnvelopeValidator : IHipEnvelopeValidator
{
    public HipValidationResult Validate(HipMessageEnvelope envelope)
    {
        var r = HipValidationResult.Success();

        if (string.IsNullOrWhiteSpace(envelope.HipVersion)) r.Add(nameof(envelope.HipVersion), "HipVersion is required.");
        if (string.IsNullOrWhiteSpace(envelope.MessageType)) r.Add(nameof(envelope.MessageType), "MessageType is required.");
        if (string.IsNullOrWhiteSpace(envelope.SenderHipId)) r.Add(nameof(envelope.SenderHipId), "SenderHipId is required.");
        if (string.IsNullOrWhiteSpace(envelope.Nonce)) r.Add(nameof(envelope.Nonce), "Nonce is required.");
        if (string.IsNullOrWhiteSpace(envelope.PayloadHash)) r.Add(nameof(envelope.PayloadHash), "PayloadHash is required.");
        if (string.IsNullOrWhiteSpace(envelope.Signature)) r.Add(nameof(envelope.Signature), "Signature is required.");
        if (string.IsNullOrWhiteSpace(envelope.CorrelationId)) r.Add(nameof(envelope.CorrelationId), "CorrelationId is required.");
        if (envelope.TimestampUtc.Offset != TimeSpan.Zero) r.Add(nameof(envelope.TimestampUtc), "TimestampUtc must be UTC.");

        return r;
    }
}

public sealed class HipReceiptValidator : IHipReceiptValidator
{
    public HipValidationResult Validate(HipTrustReceipt receipt, bool requireSignature = true)
    {
        var r = HipValidationResult.Success();

        if (string.IsNullOrWhiteSpace(receipt.ReceiptId)) r.Add(nameof(receipt.ReceiptId), "ReceiptId is required.");
        if (string.IsNullOrWhiteSpace(receipt.HipVersion)) r.Add(nameof(receipt.HipVersion), "HipVersion is required.");
        if (string.IsNullOrWhiteSpace(receipt.InteractionType)) r.Add(nameof(receipt.InteractionType), "InteractionType is required.");
        if (string.IsNullOrWhiteSpace(receipt.SenderHipId)) r.Add(nameof(receipt.SenderHipId), "SenderHipId is required.");
        if (string.IsNullOrWhiteSpace(receipt.MessageHash)) r.Add(nameof(receipt.MessageHash), "MessageHash is required.");
        if (requireSignature && string.IsNullOrWhiteSpace(receipt.ReceiptSignature)) r.Add(nameof(receipt.ReceiptSignature), "ReceiptSignature is required.");
        if (receipt.TimestampUtc.Offset != TimeSpan.Zero) r.Add(nameof(receipt.TimestampUtc), "TimestampUtc must be UTC.");

        return r;
    }
}
