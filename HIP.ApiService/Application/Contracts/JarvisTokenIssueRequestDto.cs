namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisTokenIssueRequestDto(string IdentityId, string Audience, string? DeviceId = null);