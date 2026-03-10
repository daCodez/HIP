namespace HIP.Agent.Worker;

public sealed record AgentCredential(
    string DeviceId,
    string AssignedIdentity,
    string BootstrapToken,
    DateTimeOffset IssuedAtUtc);
