namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for Jarvis policy evaluation.
/// </summary>
/// <param name="IdentityId">Identity requesting policy evaluation.</param>
/// <param name="UserText">User text to classify and sanitize.</param>
/// <param name="ContextNote">Optional context hint to improve policy reasoning.</param>
/// <param name="ToolName">Optional tool name associated with the request.</param>
/// <param name="RiskLevel">Requested risk level classification (default: low).</param>
public sealed record JarvisPolicyEvaluationRequestDto(
    string IdentityId,
    string UserText,
    string? ContextNote,
    string? ToolName,
    string RiskLevel = "low");
