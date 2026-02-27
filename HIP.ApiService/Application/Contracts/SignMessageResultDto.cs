namespace HIP.ApiService.Application.Contracts;

public sealed record SignMessageResultDto(bool Success, string Reason, SignedMessageDto? Message);
