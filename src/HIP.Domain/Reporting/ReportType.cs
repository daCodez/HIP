namespace HIP.Domain.Reporting;

public enum ReportType
{
    RiskyUrl = 0,
    SuspiciousSender = 1,
    FalsePositive = 2,
    ReportAsSafe = 3,
    ReportAsDangerous = 4,
    SuspiciousDomain = 5,
    SuspiciousContentPattern = 6
}
