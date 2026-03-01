namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for validating a Jarvis access token.
/// </summary>
/// <param name="AccessToken">Access token to validate.</param>
/// <param name="Audience">Optional expected audience constraint.</param>
/// <param name="DeviceId">Optional expected device binding.</param>
public sealed record JarvisTokenValidateRequestDto(string AccessToken, string? Audience = null, string? DeviceId = null);
