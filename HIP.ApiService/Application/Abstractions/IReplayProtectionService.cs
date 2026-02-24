namespace HIP.ApiService.Application.Abstractions;

public interface IReplayProtectionService
{
    bool TryConsume(string messageId);
}
