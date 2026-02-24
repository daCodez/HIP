namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisPolicyEvaluationRequestDto(
    string IdentityId,
    string UserText,
    string? ContextNote,
    string? ToolName,
    string RiskLevel = "low");
