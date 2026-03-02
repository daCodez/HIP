namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Signed message contract used for verification and transport.
/// </summary>
/// <param name="Id">Message id/nonce.</param>
/// <param name="From">Sender identity identifier.</param>
/// <param name="To">Recipient identity identifier.</param>
/// <param name="Body">Message body that was signed.</param>
/// <param name="SignatureBase64">Detached signature encoded as base64.</param>
/// <param name="KeyId">Optional key id used for signing.</param>
/// <param name="CreatedAtUtc">Optional UTC creation timestamp.</param>
public sealed record SignedMessageDto(
    string Id,
    string From,
    string To,
    string Body,
    string SignatureBase64,
    string? KeyId = null,
    DateTimeOffset? CreatedAtUtc = null);
