namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Result payload for Jarvis tool-access evaluation.
/// </summary>
/// <param name="Allowed">Whether the tool action is allowed.</param>
/// <param name="Reason">Reason explaining the allow/deny decision.</param>
/// <param name="CurrentScore">Current identity reputation score.</param>
/// <param name="RequiredScore">Minimum score required for access.</param>
/// <param name="RiskLevel">Risk level used for evaluation.</param>
public sealed record JarvisToolAccessResultDto(
    bool Allowed,
    string Reason,
    int CurrentScore,
    int RequiredScore,
    string RiskLevel);
