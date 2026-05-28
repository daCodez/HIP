using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed class PatternDetectionService : IPatternDetectionService
{
    public IReadOnlyCollection<PatternCluster> DetectPatterns(IReadOnlyCollection<SuspiciousFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return findings
            .Where(finding => !string.IsNullOrWhiteSpace(finding.Domain))
            .GroupBy(finding => new PatternKey(
                finding.FindingType,
                finding.Domain.Trim().ToLowerInvariant(),
                finding.Platform.Trim().ToLowerInvariant(),
                finding.RiskLevel))
            .Where(group => group.Count() >= 2)
            .Select(CreateCluster)
            .OrderByDescending(cluster => cluster.FindingCount)
            .ThenBy(cluster => cluster.PatternType)
            .ToArray();
    }

    private static PatternCluster CreateCluster(IGrouping<PatternKey, SuspiciousFinding> group)
    {
        var findings = group.OrderBy(finding => finding.DetectedAtUtc).ToArray();
        var averageRisk = MapAverageRisk(findings);
        var domain = findings[0].Domain.Trim().ToLowerInvariant();
        var platform = findings[0].Platform.Trim();
        var confidenceHint = Math.Clamp(Math.Round((findings.Length / 10m) + ReporterTrustBoost(findings), 2), 0m, 1m);
        var patternType = findings[0].FindingType;
        var clusterId = $"cluster-{Slug(patternType.ToString())}-{Slug(domain)}-{Slug(platform)}-{Slug(averageRisk.ToString())}";

        return new PatternCluster(
            clusterId,
            patternType,
            findings,
            $"{findings.Length} {patternType} findings for {domain} on {platform}.",
            findings.First().DetectedAtUtc,
            findings.Last().DetectedAtUtc,
            findings.Length,
            averageRisk,
            confidenceHint);
    }

    private static RiskStatus MapAverageRisk(IReadOnlyCollection<SuspiciousFinding> findings)
    {
        var average = findings.Average(finding => RiskWeight(finding.RiskLevel));

        return average switch
        {
            >= 6 => RiskStatus.Critical,
            >= 5 => RiskStatus.Dangerous,
            >= 4 => RiskStatus.HighRisk,
            >= 3 => RiskStatus.Caution,
            >= 2 => RiskStatus.ProbablySafe,
            >= 1 => RiskStatus.Trusted,
            _ => RiskStatus.Unknown
        };
    }

    private static int RiskWeight(RiskStatus status) => status switch
    {
        RiskStatus.Trusted => 1,
        RiskStatus.ProbablySafe => 2,
        RiskStatus.Caution => 3,
        RiskStatus.HighRisk => 4,
        RiskStatus.Dangerous => 5,
        RiskStatus.Critical => 6,
        _ => 0
    };

    private static decimal ReporterTrustBoost(IEnumerable<SuspiciousFinding> findings) =>
        findings.Average(finding => finding.ReporterTrustLevel switch
        {
            ReporterTrustLevel.Trusted => 0.25m,
            ReporterTrustLevel.High => 0.2m,
            ReporterTrustLevel.Medium => 0.1m,
            ReporterTrustLevel.Low => 0.03m,
            _ => 0m
        });

    private static string Slug(string value) =>
        string.Join("-", value.Split(Path.GetInvalidFileNameChars().Concat([' ', '.', '_']).ToArray(), StringSplitOptions.RemoveEmptyEntries)).ToLowerInvariant();

    private sealed record PatternKey(FindingType FindingType, string Domain, string Platform, RiskStatus RiskLevel);
}
