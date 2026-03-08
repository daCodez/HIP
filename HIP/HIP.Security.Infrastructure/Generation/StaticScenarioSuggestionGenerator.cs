using HIP.Security.Application.Abstractions.Generation;
using HIP.Security.Application.Abstractions.Repositories;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticScenarioSuggestionGenerator(IScenarioRepository scenarioRepository) : IScenarioSuggestionGenerator
{
    public async Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default)
    {
        var scenarios = await scenarioRepository.ListAsync(cancellationToken);

        if (scenarios.Count == 0)
        {
            return
            [
                $"[Campaign {campaignId:N}] Add baseline scenario: expired token replay with nonce mismatch.",
                $"[Campaign {campaignId:N}] Add baseline scenario: impossible-travel login challenge path."
            ];
        }

        return scenarios
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .Select(x => $"[Campaign {campaignId:N}] Add mutation wave for scenario '{x.Name}' ({x.Id:N}).")
            .ToArray();
    }
}
