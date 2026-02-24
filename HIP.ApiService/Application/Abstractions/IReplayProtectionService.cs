namespace HIP.ApiService.Application.Abstractions;

public interface IReplayProtectionService
{
    Task<bool> TryConsumeAsync(string messageId, string identityId, CancellationToken cancellationToken);
}
