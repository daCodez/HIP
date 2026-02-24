namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisToolAccessResultDto(
    bool Allowed,
    string Reason,
    int CurrentScore,
    int RequiredScore,
    string RiskLevel);
