namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Result payload for message-verification operations.
/// </summary>
/// <param name="IsValid">Whether signature and policy verification succeeded.</param>
/// <param name="Reason">Reason for validation outcome.</param>
public sealed record VerifyMessageResultDto(bool IsValid, string Reason);
