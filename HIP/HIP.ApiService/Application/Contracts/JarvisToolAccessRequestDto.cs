namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for Jarvis tool-access evaluation.
/// </summary>
/// <param name="IdentityId">Identity requesting tool use.</param>
/// <param name="ToolName">Target tool name.</param>
/// <param name="RiskLevel">Requested risk level for the tool action.</param>
public sealed record JarvisToolAccessRequestDto(
    string IdentityId,
    string ToolName,
    string RiskLevel);
