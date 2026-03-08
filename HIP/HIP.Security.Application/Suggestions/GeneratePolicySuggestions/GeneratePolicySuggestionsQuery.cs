using HIP.Security.Application.Abstractions.Generation;
using MediatR;

namespace HIP.Security.Application.Suggestions.GeneratePolicySuggestions;

public sealed record GeneratePolicySuggestionsQuery(Guid CampaignId) : IRequest<IReadOnlyList<string>>;

public sealed class GeneratePolicySuggestionsQueryHandler(IPolicySuggestionGenerator generator) : IRequestHandler<GeneratePolicySuggestionsQuery, IReadOnlyList<string>>
{
    public Task<IReadOnlyList<string>> Handle(GeneratePolicySuggestionsQuery request, CancellationToken cancellationToken) =>
        generator.GenerateAsync(request.CampaignId, cancellationToken);
}
