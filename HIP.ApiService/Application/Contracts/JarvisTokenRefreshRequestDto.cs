namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for refreshing a Jarvis token set.
/// </summary>
/// <param name="RefreshToken">Refresh token presented by the client.</param>
public sealed record JarvisTokenRefreshRequestDto(string RefreshToken);
