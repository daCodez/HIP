using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Domain.Scenarios;

namespace HIP.Security.PolicyEngine.Execution;

public sealed class PassThroughMutationEngine : IMutationEngine
{
    public Task<IReadOnlyList<ThreatScenario>> MutateAsync(ThreatScenario scenario, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ThreatScenario>>([scenario]);
}
