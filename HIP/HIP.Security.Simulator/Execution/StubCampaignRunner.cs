using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Domain.Common;

namespace HIP.Security.Simulator.Execution;

public sealed class StubCampaignRunner : ICampaignRunner
{
    public Task<CampaignRunResult> RunAsync(Guid campaignId, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        return Task.FromResult(new CampaignRunResult(
            campaignId,
            ScenarioCount: 0,
            ExecutedCount: 0,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            Status: "Stubbed",
            Notes: ["Phase 1 scaffold: no scenarios executed."]));
    }
}
