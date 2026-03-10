namespace HIP.Agent.Worker;

public interface IAgentCredentialStore
{
    Task<AgentCredential?> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(AgentCredential credential, CancellationToken cancellationToken);
}
