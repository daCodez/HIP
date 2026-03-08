namespace HIP.Security.Domain.Coverage;

public sealed record CoverageReport(
    Guid CampaignId,
    int TotalScenarios,
    int CoveredScenarios,
    IReadOnlyList<string> Gaps,
    DateTimeOffset EvaluatedAtUtc)
{
    public decimal CoveragePercent => TotalScenarios == 0 ? 0 : Math.Round((decimal)CoveredScenarios / TotalScenarios * 100m, 2);
}
