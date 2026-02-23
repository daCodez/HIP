namespace HIP.Communication.Domain;

public sealed record SignedMessage(
    Guid Id,
    string From,
    string To,
    string Body,
    string SignaturePlaceholder);
