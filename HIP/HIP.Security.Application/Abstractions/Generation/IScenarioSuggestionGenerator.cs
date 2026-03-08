namespace HIP.Security.Application.Abstractions.Generation;

public interface IScenarioSuggestionGenerator
{
    Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
