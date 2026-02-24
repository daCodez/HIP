namespace HIP.ApiService.Application.Contracts;

public sealed record SignMessageRequestDto(
    string From,
    string To,
    string Body,
    string? Id = null,
    string? KeyId = null);
