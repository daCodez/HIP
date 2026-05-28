namespace HIP.Application.Scoring;

public sealed record AiRiskAnalysisResult(
    bool AnalysisPerformed,
    string Explanation,
    IReadOnlyCollection<string> SuggestedReasons);
