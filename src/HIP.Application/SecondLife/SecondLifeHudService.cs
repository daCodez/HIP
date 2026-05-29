using System.Security.Cryptography;
using System.Text;
using HIP.Application.Reporting;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SecondLife;

public sealed class SecondLifeHudService(IRiskFindingIngestionService ingestionService) : ISecondLifeHudService
{
    private const string ValidDevelopmentSetupCode = "HIP-DEV-SETUP";

    public SecondLifeHudActivationResponse Activate(SecondLifeHudActivationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.SetupCode) || string.IsNullOrWhiteSpace(request.HudDeviceId))
        {
            return Inactive("Setup code and HUD device ID are required.");
        }

        if (!string.Equals(request.SetupCode.Trim(), ValidDevelopmentSetupCode, StringComparison.Ordinal))
        {
            return Inactive("Setup code was not accepted.");
        }

        return new SecondLifeHudActivationResponse(
            true,
            "DevelopmentActive",
            "HIP SL HUD activated for development use.",
            DefaultConfig());
    }

    public async Task<SecondLifeHudFindingResponse> ReportFindingAsync(SecondLifeHudFindingReport report, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(report.Domain) && string.IsNullOrWhiteSpace(report.RiskyUrl))
        {
            return new SecondLifeHudFindingResponse(false, null, string.Empty, report.RiskLevel, false, string.Empty, "Domain or risky URL is required.");
        }

        var domain = NormalizeDomain(report.Domain, report.RiskyUrl);
        var urlHash = string.IsNullOrWhiteSpace(report.UrlHash) && !string.IsNullOrWhiteSpace(report.RiskyUrl)
            ? Sha256(report.RiskyUrl)
            : report.UrlHash;

        var riskReport = new RiskFindingReport(
            "",
            SourceClient.SecondLifeHud,
            ReportPlatform.SecondLife,
            TargetType.Url,
            domain,
            urlHash,
            report.RiskyUrl,
            report.SenderHash,
            report.RiskLevel,
            report.Reason,
            report.DetectedAtUtc == default ? DateTimeOffset.UtcNow : report.DetectedAtUtc,
            ReporterTrustLevel.Medium,
            new PrivacySafeEvidence(
                "second-life-link-risk",
                "Second Life HUD reported a risky link without full chat or IM logs.",
                new Dictionary<string, string>
                {
                    ["hudDeviceId"] = report.HudDeviceId,
                    ["avatarHashPresent"] = (!string.IsNullOrWhiteSpace(report.AvatarHash)).ToString(),
                    ["senderHashPresent"] = (!string.IsNullOrWhiteSpace(report.SenderHash)).ToString()
                }),
            string.IsNullOrWhiteSpace(report.HipSignature) ? "sl-hud-signature-placeholder" : report.HipSignature);

        var response = await ingestionService.IngestAsync(riskReport, cancellationToken);
        return SecondLifeHudFindingResponse.FromIngestion(response, SafetyPageUrl(report.RiskyUrl, domain, report.Reason));
    }

    private static SecondLifeHudActivationResponse Inactive(string message) =>
        new(false, "Inactive", message, DefaultConfig());

    private static SecondLifeHudClientConfig DefaultConfig() =>
        new("Normal", true, "/safety", "/api/v1/public/sl-hud/report-finding");

    private static string SafetyPageUrl(string? riskyUrl, string domain, string reason)
    {
        var value = string.IsNullOrWhiteSpace(riskyUrl) ? $"https://{domain}/" : riskyUrl;
        return $"/safety?url={Uri.EscapeDataString(value)}&risk={Uri.EscapeDataString(reason)}";
    }

    private static string NormalizeDomain(string domain, string? riskyUrl)
    {
        if (!string.IsNullOrWhiteSpace(domain))
        {
            return domain.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        if (!string.IsNullOrWhiteSpace(riskyUrl) && Uri.TryCreate(riskyUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return string.Empty;
    }

    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }
}
