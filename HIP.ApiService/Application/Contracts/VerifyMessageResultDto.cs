namespace HIP.ApiService.Application.Contracts;

public sealed record VerifyMessageResultDto(bool IsValid, string Reason);
