namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisPolicyEvaluationResultDto(
    string Decision,
    string Risk,
    List<string> Reasons,
    string SanitizedText,
    bool ToolAccessAllowed,
    string ToolAccessReason,
    string PolicyCode);
