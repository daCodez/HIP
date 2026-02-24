namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisProofTokenIssueRequestDto(string IdentityId, string Audience, string? DeviceId, string Action, int? TtlSeconds = null);