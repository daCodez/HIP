namespace HIP.Application.Ai;

/// <summary>
/// Defines AI-assisted risk analysis operations used as supporting HIP evidence.
/// </summary>
public interface IHipAiRiskAnalyzer
{
    /// <summary>
    /// Analyzes URL-level risk from privacy-safe URL and rule signals.
    /// </summary>
    /// <param name="request">The URL risk request that avoids raw private content.</param>
    /// <param name="cancellationToken">Token used to cancel the analysis.</param>
    /// <returns>A supporting risk analysis result for scoring, review, or rule suggestion workflows.</returns>
    Task<HipAiRiskAnalysisResult> AnalyzeUrlRiskAsync(
        HipAiUrlRiskAnalysisRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Analyzes content-level risk from privacy-safe summaries and structured signals.
    /// </summary>
    /// <param name="request">The content risk request, limited to safe summaries and allow-listed signals.</param>
    /// <param name="cancellationToken">Token used to cancel the analysis.</param>
    /// <returns>A supporting content risk analysis result.</returns>
    Task<HipAiRiskAnalysisResult> AnalyzeContentRiskAsync(
        HipAiContentRiskAnalysisRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Suggests a structured HIP rule from an analysis result without executing raw code.
    /// </summary>
    /// <param name="request">The rule suggestion request built from a prior analysis result.</param>
    /// <param name="cancellationToken">Token used to cancel rule suggestion.</param>
    /// <returns>A proposed rule and the required simulation or approval controls.</returns>
    Task<HipAiRuleSuggestionResult> SuggestRuleAsync(
        HipAiRuleSuggestionRequest request,
        CancellationToken cancellationToken);
}
