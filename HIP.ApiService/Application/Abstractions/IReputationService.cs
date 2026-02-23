namespace HIP.ApiService.Application.Abstractions;

public interface IReputationService
{
    Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken);
}
