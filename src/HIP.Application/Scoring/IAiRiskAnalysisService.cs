namespace HIP.Application.Scoring;

public interface IAiRiskAnalysisService
{
    Task<AiRiskAnalysisResult> AnalyzeAsync(AiRiskAnalysisRequest request, CancellationToken cancellationToken);
}
