namespace HIP.ApiService.Application.Contracts;

public sealed record SignedMessageDto(
    string Id,
    string From,
    string To,
    string Body,
    string SignatureBase64,
    string? KeyId = null);
