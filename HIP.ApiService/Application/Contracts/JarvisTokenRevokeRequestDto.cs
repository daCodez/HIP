namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisTokenRevokeRequestDto(string? AccessToken, string? RefreshToken, string? IdentityId);