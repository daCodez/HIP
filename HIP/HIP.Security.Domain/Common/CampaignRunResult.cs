namespace HIP.Security.Domain.Common;

public sealed record CampaignRunResult(
    Guid CampaignId,
    int ScenarioCount,
    int ExecutedCount,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    string Status,
    IReadOnlyList<string> Notes);
