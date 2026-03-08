using HIP.Security.Application.Abstractions.Generation;
using MediatR;

namespace HIP.Security.Application.Suggestions.GenerateScenarioSuggestions;

public sealed record GenerateScenarioSuggestionsQuery(Guid CampaignId) : IRequest<IReadOnlyList<string>>;

public sealed class GenerateScenarioSuggestionsQueryHandler(IScenarioSuggestionGenerator generator) : IRequestHandler<GenerateScenarioSuggestionsQuery, IReadOnlyList<string>>
{
    public Task<IReadOnlyList<string>> Handle(GenerateScenarioSuggestionsQuery request, CancellationToken cancellationToken) =>
        generator.GenerateAsync(request.CampaignId, cancellationToken);
}
