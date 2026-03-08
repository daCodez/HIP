using HIP.Security.Application.Abstractions.Generation;
using MediatR;

namespace HIP.Security.Application.Suggestions.GenerateTelemetrySuggestions;

public sealed record GenerateTelemetrySuggestionsQuery(Guid CampaignId) : IRequest<IReadOnlyList<string>>;

public sealed class GenerateTelemetrySuggestionsQueryHandler(ITelemetrySuggestionGenerator generator) : IRequestHandler<GenerateTelemetrySuggestionsQuery, IReadOnlyList<string>>
{
    public Task<IReadOnlyList<string>> Handle(GenerateTelemetrySuggestionsQuery request, CancellationToken cancellationToken) =>
        generator.GenerateAsync(request.CampaignId, cancellationToken);
}
