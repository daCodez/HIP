namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Result payload returned by Jarvis policy evaluation.
/// </summary>
/// <param name="Decision">Policy decision (allow/deny/review, etc.).</param>
/// <param name="Risk">Computed risk classification.</param>
/// <param name="Reasons">Machine/human-readable reasons supporting the decision.</param>
/// <param name="SanitizedText">Sanitized user text after policy processing.</param>
/// <param name="ToolAccessAllowed">Whether requested tool usage is allowed.</param>
/// <param name="ToolAccessReason">Reason for tool allow/deny outcome.</param>
/// <param name="PolicyCode">Stable policy code associated with the evaluation.</param>
/// <param name="PolicyVersion">Policy-pack version used to produce this decision.</param>
/// <param name="DecisionTrace">Cross-pillar trace snapshot for this decision.</param>
public sealed record JarvisPolicyEvaluationResultDto(
    string Decision,
    string Risk,
    List<string> Reasons,
    string SanitizedText,
    bool ToolAccessAllowed,
    string ToolAccessReason,
    string PolicyCode,
    string PolicyVersion,
    JarvisPolicyDecisionTraceDto DecisionTrace);
