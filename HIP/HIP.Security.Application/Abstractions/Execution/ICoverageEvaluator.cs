using HIP.Security.Domain.Coverage;

namespace HIP.Security.Application.Abstractions.Execution;

public interface ICoverageEvaluator
{
    Task<CoverageReport> EvaluateAsync(Guid campaignId, CancellationToken cancellationToken = default);
}
