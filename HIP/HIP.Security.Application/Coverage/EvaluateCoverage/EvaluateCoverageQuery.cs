using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Domain.Coverage;
using MediatR;

namespace HIP.Security.Application.Coverage.EvaluateCoverage;

public sealed record EvaluateCoverageQuery(Guid CampaignId) : IRequest<CoverageReport>;

public sealed class EvaluateCoverageQueryHandler(ICoverageEvaluator coverageEvaluator) : IRequestHandler<EvaluateCoverageQuery, CoverageReport>
{
    public Task<CoverageReport> Handle(EvaluateCoverageQuery request, CancellationToken cancellationToken) =>
        coverageEvaluator.EvaluateAsync(request.CampaignId, cancellationToken);
}
