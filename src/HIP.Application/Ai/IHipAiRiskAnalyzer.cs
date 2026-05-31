namespace HIP.Application.Ai;

public interface IHipAiRiskAnalyzer
{
    Task<HipAiRiskAnalysisResult> AnalyzeUrlRiskAsync(
        HipAiUrlRiskAnalysisRequest request,
        CancellationToken cancellationToken);

    Task<HipAiRiskAnalysisResult> AnalyzeContentRiskAsync(
        HipAiContentRiskAnalysisRequest request,
        CancellationToken cancellationToken);

    Task<HipAiRuleSuggestionResult> SuggestRuleAsync(
        HipAiRuleSuggestionRequest request,
        CancellationToken cancellationToken);
}
