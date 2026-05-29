namespace HIP.Domain.Identity;

public sealed record HipSignedContent(
    string ContentId,
    HipContentType ContentType,
    string ContentHash,
    HipSignature Signature,
    VerificationResult VerificationResult);
