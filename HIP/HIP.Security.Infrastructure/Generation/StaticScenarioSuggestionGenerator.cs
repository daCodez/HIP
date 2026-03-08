using HIP.Security.Application.Abstractions.Generation;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticScenarioSuggestionGenerator : IScenarioSuggestionGenerator
{
    public Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>(["Add token replay attempts against expired nonce windows."]);
}
