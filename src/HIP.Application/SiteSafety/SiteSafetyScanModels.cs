using HIP.Domain.Scoring;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Describes the outcome label for HIP's page-level safety scan.
/// </summary>
public enum SiteSafetyScanStatus
{
    /// <summary>
    /// No obvious safety issue was found and enough trust context exists to call the scan clean.
    /// </summary>
    Clean,

    /// <summary>
    /// No obvious malware or phishing was found, but HIP lacks enough trust data for a stronger claim.
    /// </summary>
    LimitedData,

    /// <summary>
    /// HIP could not determine a meaningful safety state from the available signals.
    /// </summary>
    Unknown,

    /// <summary>
    /// HIP found suspicious page behavior that should lower trust.
    /// </summary>
    Suspicious,

    /// <summary>
    /// HIP found high-risk behavior such as phishing-style forms or executable downloads.
    /// </summary>
    HighRisk,

    /// <summary>
    /// HIP found strong malware, phishing, or abuse indicators.
    /// </summary>
    Dangerous,

    /// <summary>
    /// HIP could not complete the scan safely.
    /// </summary>
    ScanFailed
}

/// <summary>
/// Request sent to the Site Safety Scan service.
/// </summary>
/// <param name="Url">Absolute HTTP or HTTPS URL to scan.</param>
/// <param name="ObservedSignals">Optional privacy-safe observations collected by a HIP client.</param>
public sealed record SiteSafetyScanRequest(
    string Url,
    SiteSafetyObservedSignals? ObservedSignals = null);

/// <summary>
/// Privacy-safe client observations used by the scanner without sending full page text or form values.
/// </summary>
/// <param name="RedirectChain">Redirect URLs observed by the client or server, capped by the caller.</param>
/// <param name="ExternalScriptUrls">External script source URLs. Script contents are not sent.</param>
/// <param name="InlineScriptCount">Count of inline script blocks, not script content.</param>
/// <param name="SuspiciousScriptPatternCount">Count of locally detected suspicious JavaScript patterns.</param>
/// <param name="DownloadLinks">Download-like links observed on the page.</param>
/// <param name="HasLoginForm">Whether the page contains a login form.</param>
/// <param name="HasPasswordField">Whether the page contains a password field.</param>
/// <param name="HasPaymentField">Whether the page contains payment-related fields.</param>
/// <param name="ContainsScamWording">Whether a client found scam-like wording without sending full text.</param>
/// <param name="ContainsUrgencyWording">Whether a client found urgency wording without sending full text.</param>
/// <param name="ContainsImpersonationWording">Whether a client found impersonation wording without sending full text.</param>
/// <param name="KnownPhishingPattern">Whether a known phishing pattern matched.</param>
/// <param name="KnownMalwareIndicator">Whether a known malware indicator matched.</param>
/// <param name="KnownAbuseReports">Number of public-safe known abuse report signals.</param>
/// <param name="DomainReputationScore">Optional 0-100 domain reputation score where lower is riskier.</param>
/// <param name="PageReputationScore">Optional 0-100 page reputation score where lower is riskier.</param>
/// <param name="TrustDataAvailable">Whether HIP has enough non-safety trust data to make a stronger safety statement.</param>
/// <param name="ShortenedLinkCount">Count of locally detected shortened links. No page text is sent.</param>
/// <param name="ObfuscatedLinkCount">Count of locally detected obfuscated links. No private message text is sent.</param>
/// <param name="MatchedRiskTerms">Privacy-safe risk term labels, not raw page content.</param>
public sealed record SiteSafetyObservedSignals(
    IReadOnlyCollection<string>? RedirectChain = null,
    IReadOnlyCollection<string>? ExternalScriptUrls = null,
    int InlineScriptCount = 0,
    int SuspiciousScriptPatternCount = 0,
    IReadOnlyCollection<string>? DownloadLinks = null,
    bool HasLoginForm = false,
    bool HasPasswordField = false,
    bool HasPaymentField = false,
    bool ContainsScamWording = false,
    bool ContainsUrgencyWording = false,
    bool ContainsImpersonationWording = false,
    bool KnownPhishingPattern = false,
    bool KnownMalwareIndicator = false,
    int KnownAbuseReports = 0,
    int? DomainReputationScore = null,
    int? PageReputationScore = null,
    bool TrustDataAvailable = false,
    int ShortenedLinkCount = 0,
    int ObfuscatedLinkCount = 0,
    IReadOnlyCollection<string>? MatchedRiskTerms = null);

/// <summary>
/// Result produced by HIP's Site Safety Scan layer.
/// </summary>
/// <param name="ScanId">Unique scan identifier.</param>
/// <param name="Url">Sanitized URL that was scanned.</param>
/// <param name="Domain">Normalized domain for the scan.</param>
/// <param name="ScannedAtUtc">UTC timestamp for the scan.</param>
/// <param name="MalwareRiskScore">0-100 malware risk score.</param>
/// <param name="PhishingRiskScore">0-100 phishing risk score.</param>
/// <param name="RedirectRiskScore">0-100 redirect risk score.</param>
/// <param name="ScriptRiskScore">0-100 script risk score.</param>
/// <param name="DownloadRiskScore">0-100 download risk score.</param>
/// <param name="FormRiskScore">0-100 form risk score.</param>
/// <param name="ReputationRiskScore">0-100 reputation risk score.</param>
/// <param name="OverallSafetyRiskScore">0-100 combined page safety risk score.</param>
/// <param name="Status">Safety scan status.</param>
/// <param name="Summary">Plain-English summary.</param>
/// <param name="Reasons">Plain-English reasons.</param>
/// <param name="Warnings">Warnings that should be shown to users or admins.</param>
/// <param name="PositiveSignals">Positive safety signals found during the scan.</param>
/// <param name="NegativeSignals">Negative safety signals found during the scan.</param>
/// <param name="ConfidenceLevel">Low, Medium, or High confidence label.</param>
/// <param name="DomainTrustScore">Domain trust score after safety reputation impact.</param>
/// <param name="PageTrustScore">Page trust score after safety impact.</param>
/// <param name="ContentRiskScore">Layered content trust score derived from malware, script, download, and phishing signals; lower means riskier content.</param>
/// <param name="FinalHipScore">Safety-adjusted HIP score contribution.</param>
/// <param name="ProviderEvidence">Normalized provider evidence used by the scan. Raw private page content is not included.</param>
/// <param name="ScoreImpact">Detailed score impact for the larger HIP scoring model.</param>
/// <param name="MatchedRules">Built-in and admin rule results that contributed to the scan. Raw private evidence is not included.</param>
public sealed record SiteSafetyScanResult(
    string ScanId,
    string Url,
    string Domain,
    DateTimeOffset ScannedAtUtc,
    int MalwareRiskScore,
    int PhishingRiskScore,
    int RedirectRiskScore,
    int ScriptRiskScore,
    int DownloadRiskScore,
    int FormRiskScore,
    int ReputationRiskScore,
    int OverallSafetyRiskScore,
    SiteSafetyScanStatus Status,
    string Summary,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Warnings,
    IReadOnlyCollection<string> PositiveSignals,
    IReadOnlyCollection<string> NegativeSignals,
    string ConfidenceLevel,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    IReadOnlyCollection<SiteSafetyEvidence> ProviderEvidence,
    SiteSafetyScoreImpact ScoreImpact,
    IReadOnlyCollection<SiteSafetyRuleResult>? MatchedRules = null);

/// <summary>
/// Explains how the Site Safety Scan contributes to HIP's larger scoring categories.
/// </summary>
/// <param name="DomainTrustScore">DomainTrustScore contribution after reputation risk.</param>
/// <param name="PageTrustScore">PageTrustScore contribution after phishing, redirect, form, and reputation risk.</param>
/// <param name="ContentRiskScore">ContentRiskScore contribution where lower values indicate riskier content and higher values indicate safer content.</param>
/// <param name="FinalHipScore">Final safety-adjusted HIP score contribution.</param>
/// <param name="ScoreBreakdown">Standard HIP score breakdown components.</param>
public sealed record SiteSafetyScoreImpact(
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    IReadOnlyCollection<ScoreComponent> ScoreBreakdown);
