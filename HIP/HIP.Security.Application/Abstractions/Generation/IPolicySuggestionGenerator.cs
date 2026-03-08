namespace HIP.Security.Application.Abstractions.Generation;

public interface IPolicySuggestionGenerator
{
    Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
