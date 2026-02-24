namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisToolAccessRequestDto(
    string IdentityId,
    string ToolName,
    string RiskLevel);
