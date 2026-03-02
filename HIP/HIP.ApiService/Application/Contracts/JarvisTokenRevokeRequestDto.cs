namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for revoking Jarvis tokens.
/// </summary>
/// <param name="AccessToken">Optional access token to revoke.</param>
/// <param name="RefreshToken">Optional refresh token to revoke.</param>
/// <param name="IdentityId">Optional identity id for broader revoke operations.</param>
public sealed record JarvisTokenRevokeRequestDto(string? AccessToken, string? RefreshToken, string? IdentityId);
