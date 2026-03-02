namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Result payload for message-sign operations.
/// </summary>
/// <param name="Success">Whether signing succeeded.</param>
/// <param name="Reason">Reason for success/failure outcome.</param>
/// <param name="Message">Signed message payload when successful.</param>
public sealed record SignMessageResultDto(bool Success, string Reason, SignedMessageDto? Message);
