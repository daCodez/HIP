using System.Globalization;

namespace HIP.Admin.Models;

public static class AdminUiSemantics
{
    public static SeverityLevel ParseSeverity(string? severity, string? result = null)
    {
        if (string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase))
        {
            return SeverityLevel.Critical;
        }

        if (string.Equals(severity, "high", StringComparison.OrdinalIgnoreCase))
        {
            return SeverityLevel.High;
        }

        if (string.Equals(severity, "warning", StringComparison.OrdinalIgnoreCase)
            || string.Equals(severity, "medium", StringComparison.OrdinalIgnoreCase))
        {
            return SeverityLevel.Medium;
        }

        if (string.Equals(severity, "info", StringComparison.OrdinalIgnoreCase)
            || string.Equals(result, "success", StringComparison.OrdinalIgnoreCase))
        {
            return SeverityLevel.Info;
        }

        return string.Equals(result, "Denied", StringComparison.OrdinalIgnoreCase)
            ? SeverityLevel.High
            : SeverityLevel.Low;
    }

    public static bool MatchesSeverity(SeverityLevel severity, string? filter)
        => string.IsNullOrWhiteSpace(filter)
           || string.Equals(filter, "all", StringComparison.OrdinalIgnoreCase)
           || string.Equals(filter, severity.ToString(), StringComparison.OrdinalIgnoreCase);

    public static bool MatchesStatus(WorkflowStatus status, string? filter)
        => string.IsNullOrWhiteSpace(filter)
           || string.Equals(filter, "all", StringComparison.OrdinalIgnoreCase)
           || string.Equals(filter, ToFilterValue(status), StringComparison.OrdinalIgnoreCase);

    public static string ToFilterValue(WorkflowStatus status)
        => status switch
        {
            WorkflowStatus.InProgress => "inprogress",
            WorkflowStatus.FalsePositive => "falsepositive",
            _ => status.ToString().ToLowerInvariant()
        };

    public static string ToDisplayStatus(WorkflowStatus status)
        => status switch
        {
            WorkflowStatus.InProgress => "In Progress",
            WorkflowStatus.FalsePositive => "False Positive",
            _ => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(status.ToString().ToLowerInvariant())
        };
}
