using HIP.Security.Application.Abstractions.Generation;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticPolicySuggestionGenerator : IPolicySuggestionGenerator
{
    public Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>(["Consider enabling adaptive rate limits for campaign anomalies."]);
}
