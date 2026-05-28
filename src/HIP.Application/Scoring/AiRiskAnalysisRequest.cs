namespace HIP.Application.Scoring;

public sealed record AiRiskAnalysisRequest(
    string Subject,
    IReadOnlyDictionary<string, object?> PrivacySafeFacts);
