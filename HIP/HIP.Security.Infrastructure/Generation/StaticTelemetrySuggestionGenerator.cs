using HIP.Security.Application.Abstractions.Generation;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticTelemetrySuggestionGenerator : ITelemetrySuggestionGenerator
{
    public Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>(["Capture policy decision latency p95 for campaign correlation."]);
}
