using HIP.Security.Domain.Scenarios;

namespace HIP.Security.Application.Abstractions.Execution;

public interface IMutationEngine
{
    Task<IReadOnlyList<ThreatScenario>> MutateAsync(ThreatScenario scenario, CancellationToken cancellationToken = default);
}
