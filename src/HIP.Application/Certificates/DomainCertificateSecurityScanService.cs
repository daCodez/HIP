using System.Text;
using HIP.Application.Browser;
using HIP.Application.SiteSafety;
using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

public sealed record DomainCertificateSecurityScanRequest(
    string Domain,
    DomainCertificateLevel RequestedLevel,
    bool AccountContactVerified,
    DateTimeOffset? DomainControlVerifiedAtUtc,
    DateTimeOffset? DnsVerifiedAtUtc,
    DateTimeOffset? WebsiteVerifiedAtUtc,
    bool IdentityInformationCompleted,
    bool ContinuousMonitoringEnabled = false,
    bool CertificateActive = false);

public enum DomainCertificateSecurityScanStatus
{
    Evaluated,
    ScanUnavailable,
    PersistenceUnavailable
}

public sealed record DomainCertificateSecurityScanResult(
    DomainCertificateSecurityScanStatus Status,
    SiteSafetyScanResult? Scan = null,
    DomainCertificatePolicyEvaluationResult? Evaluation = null,
    DomainCertificatePublicRiskClassification PublicRiskClassification =
        DomainCertificatePublicRiskClassification.Unknown,
    IReadOnlyCollection<string>? PublicFindingCodes = null);

public interface IDomainCertificateSecurityScanService
{
    Task<DomainCertificateSecurityScanResult> ScanAsync(
        DomainCertificateSecurityScanRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Runs a HIP-owned scan of the fixed HTTPS origin, writes an authoritative dashboard projection,
/// and evaluates only normalized evidence under the versioned certificate policy.
/// </summary>
public sealed class DomainCertificateSecurityScanService(
    ISiteSafetyScanner siteSafetyScanner,
    IBrowserScanResultWriteService scanResultWriter,
    IDomainCertificatePolicyEvaluator policyEvaluator,
    ExternalSiteEvidenceOptions externalEvidenceOptions,
    TimeProvider timeProvider) : IDomainCertificateSecurityScanService
{
    public async Task<DomainCertificateSecurityScanResult> ScanAsync(
        DomainCertificateSecurityScanRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var domain = PublicLookup.DomainInputValidator.ValidateAndNormalize(request.Domain);
        if (!string.Equals(domain, request.Domain, StringComparison.Ordinal))
        {
            throw new ArgumentException("Certificate security scans require a canonical domain.", nameof(request));
        }

        var origin = $"https://{domain}/";
        SiteSafetyScanResult scan;
        try
        {
            var scanOptions = externalEvidenceOptions.GetEffectiveOptions().Clone();
            scanOptions.RunExternalProvidersOnRequestPath = true;
            using var providerScope = externalEvidenceOptions.UseScopedOverride(scanOptions);
            scan = await siteSafetyScanner.ScanAsync(
                    new SiteSafetyScanRequest(origin),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateSecurityScanResult(
                DomainCertificateSecurityScanStatus.ScanUnavailable);
        }

        var publicFindingCodes = PublicFindingCodes(scan);
        var criticalFindings = CriticalFindingCount(scan);
        var risk = RiskClassification(scan);
        try
        {
            await scanResultWriter.SaveAsync(
                    AuthoritativeProjection(scan, origin, risk),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateSecurityScanResult(
                DomainCertificateSecurityScanStatus.PersistenceUnavailable,
                scan,
                PublicRiskClassification: risk,
                PublicFindingCodes: publicFindingCodes);
        }

        var evaluatedAt = timeProvider.GetUtcNow().ToUniversalTime();
        var scanCompleted = scan.Status != SiteSafetyScanStatus.ScanFailed;
        var tlsValid = HasAuthoritativeTlsEvidence(scan, evaluatedAt);
        var requiredPoliciesPassed =
            scanCompleted &&
            scan.Status is not SiteSafetyScanStatus.Unknown
                and not SiteSafetyScanStatus.Suspicious
                and not SiteSafetyScanStatus.HighRisk
                and not SiteSafetyScanStatus.Dangerous &&
            criticalFindings == 0;
        var evaluation = policyEvaluator.Evaluate(new DomainCertificatePolicyEvaluationRequest(
            domain,
            request.RequestedLevel,
            new DomainCertificateEvidenceSnapshot(
                request.AccountContactVerified,
                request.DomainControlVerifiedAtUtc,
                request.DnsVerifiedAtUtc,
                request.WebsiteVerifiedAtUtc,
                scanCompleted,
                criticalFindings,
                request.IdentityInformationCompleted,
                HttpsAvailable: request.WebsiteVerifiedAtUtc is not null,
                TlsCertificateValid: tlsValid,
                RequiredPoliciesPassed: requiredPoliciesPassed,
                CurrentTrustScore: scan.FinalHipScore,
                ContinuousMonitoringEnabled: request.ContinuousMonitoringEnabled,
                CertificateActive: request.CertificateActive,
                LastMonitoringAtUtc: request.RequestedLevel == DomainCertificateLevel.Monitored
                    ? evaluatedAt
                    : null),
            new DomainCertificateReviewSignals(
                LowScanConfidence: string.Equals(scan.ConfidenceLevel, "Low", StringComparison.OrdinalIgnoreCase),
                UnresolvedHighRiskFindings: HasHighRiskFinding(scan)),
            evaluatedAt));
        return new DomainCertificateSecurityScanResult(
            DomainCertificateSecurityScanStatus.Evaluated,
            scan,
            evaluation,
            risk,
            publicFindingCodes);
    }

    private static BrowserScanResultSaveRequest AuthoritativeProjection(
        SiteSafetyScanResult scan,
        string origin,
        DomainCertificatePublicRiskClassification risk)
    {
        var metadata = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["scanPurpose"] = "DomainCertificateSecurityReview",
            ["siteSafetyScanId"] = scan.ScanId,
            ["evidenceConfidence"] = scan.ConfidenceLevel,
            ["domainTrustScore"] = scan.DomainTrustScore.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["pageTrustScore"] = scan.PageTrustScore.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["contentRiskScore"] = scan.ContentRiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["finalHipScore"] = scan.FinalHipScore.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var items = scan.ProviderEvidence.SelectMany(item => item.EvidenceItems).ToArray();
        return new BrowserScanResultSaveRequest(
            scan.Domain,
            PageUrl: null,
            scan.FinalHipScore,
            risk.ToString(),
            scan.Status.ToString(),
            scan.Reasons,
            LinksScanned: 0,
            RiskyLinksFound: items.Count(item => item.IsNegativeSignal),
            SuspiciousLinksFound: items.Count(item =>
                item.Status is SiteSafetyEvidenceStatus.Suspicious or SiteSafetyEvidenceStatus.HighRisk),
            DangerousLinksFound: items.Count(item => item.Status == SiteSafetyEvidenceStatus.Dangerous),
            RecommendedAction: scan.Status is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous
                ? "RouteToSafetyPage"
                : scan.Status is SiteSafetyScanStatus.Unknown or SiteSafetyScanStatus.Suspicious or SiteSafetyScanStatus.ScanFailed
                    ? "Review"
                    : "Allow",
            metadata,
            scan.ScannedAtUtc,
            $"sha256:{SiteSafetyEvidenceHashing.HashUrl(origin)}",
            PluginVersion: null);
    }

    private static bool HasAuthoritativeTlsEvidence(
        SiteSafetyScanResult scan,
        DateTimeOffset evaluatedAtUtc) =>
        scan.ProviderEvidence.Any(evidence =>
            evidence.ProviderType == SiteSafetyEvidenceProviderType.TlsScanner &&
            evidence.IsAuthoritativeForTrust &&
            evidence.ResultStatus is SiteSafetyProviderResultStatus.Succeeded or SiteSafetyProviderResultStatus.Partial &&
            evidence.ExpiresAtUtc > evaluatedAtUtc &&
            evidence.EvidenceItems.Any(item =>
                item.EvidenceType == "TlsGrade" &&
                item.IsPositiveSignal &&
                item.Status is SiteSafetyEvidenceStatus.Clean or SiteSafetyEvidenceStatus.Positive));

    private static int CriticalFindingCount(SiteSafetyScanResult scan)
    {
        var count = scan.ProviderEvidence
            .SelectMany(item => item.EvidenceItems)
            .Count(item =>
                item.Severity == SiteSafetyEvidenceSeverity.Critical &&
                (item.IsNegativeSignal || item.IsBlockingSignal ||
                 item.Status is SiteSafetyEvidenceStatus.HighRisk or SiteSafetyEvidenceStatus.Dangerous));
        return scan.Status is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous
            ? Math.Max(1, count)
            : count;
    }

    private static bool HasHighRiskFinding(SiteSafetyScanResult scan) =>
        scan.Status is SiteSafetyScanStatus.Suspicious or SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous ||
        scan.ProviderEvidence.SelectMany(item => item.EvidenceItems).Any(item =>
            item.Status is SiteSafetyEvidenceStatus.Suspicious
                or SiteSafetyEvidenceStatus.HighRisk
                or SiteSafetyEvidenceStatus.Dangerous);

    private static DomainCertificatePublicRiskClassification RiskClassification(SiteSafetyScanResult scan) =>
        scan.Status switch
        {
            SiteSafetyScanStatus.Dangerous => DomainCertificatePublicRiskClassification.Critical,
            SiteSafetyScanStatus.HighRisk => DomainCertificatePublicRiskClassification.High,
            SiteSafetyScanStatus.Suspicious => DomainCertificatePublicRiskClassification.Medium,
            SiteSafetyScanStatus.Clean or SiteSafetyScanStatus.LimitedData =>
                DomainCertificatePublicRiskClassification.Low,
            _ => DomainCertificatePublicRiskClassification.Unknown
        };

    private static IReadOnlyCollection<string> PublicFindingCodes(SiteSafetyScanResult scan) =>
        scan.ProviderEvidence
            .SelectMany(evidence => evidence.EvidenceItems)
            .Where(item => item.IsNegativeSignal || item.IsBlockingSignal)
            .Select(item => Token(item.Category))
            .Where(item => item.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .Take(20)
            .ToArray();

    private static string Token(string value)
    {
        var builder = new StringBuilder(Math.Min(value.Length, 80));
        foreach (var character in value.ToLowerInvariant())
        {
            if (character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.')
            {
                builder.Append(character);
            }
            else if (builder.Length > 0 && builder[^1] != '-')
            {
                builder.Append('-');
            }
            if (builder.Length == 80)
            {
                break;
            }
        }
        return builder.ToString().Trim('-');
    }
}
