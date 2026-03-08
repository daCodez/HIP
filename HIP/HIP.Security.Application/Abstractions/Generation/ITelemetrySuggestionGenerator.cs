namespace HIP.Security.Application.Abstractions.Generation;

public interface ITelemetrySuggestionGenerator
{
    Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
