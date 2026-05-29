using HIP.Domain.Risk;

namespace HIP.Application.Reporting;

public sealed record RiskFindingIngestionResponse(
    bool Accepted,
    string? ReportId,
    string? NormalizedDomain,
    RiskStatus RiskLevel,
    bool ReviewCreated,
    string Message);
