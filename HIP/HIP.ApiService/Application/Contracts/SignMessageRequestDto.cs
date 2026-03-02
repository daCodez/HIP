namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for signing a message via HIP.
/// </summary>
/// <param name="From">Sender identity identifier.</param>
/// <param name="To">Recipient identity identifier.</param>
/// <param name="Body">Message body to sign.</param>
/// <param name="Id">Optional caller-provided message id/nonce.</param>
/// <param name="KeyId">Optional key id override for signing.</param>
public sealed record SignMessageRequestDto(
    string From,
    string To,
    string Body,
    string? Id = null,
    string? KeyId = null);
