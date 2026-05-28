namespace HIP.Application.Scoring;

public sealed class NoOpAiRiskAnalysisService : IAiRiskAnalysisService
{
    public Task<AiRiskAnalysisResult> AnalyzeAsync(AiRiskAnalysisRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new AiRiskAnalysisResult(false, "AI-assisted analysis is reserved for a later HIP milestone.", []));
    }
}
