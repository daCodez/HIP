namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisTokenValidateRequestDto(string AccessToken, string? Audience = null, string? DeviceId = null);