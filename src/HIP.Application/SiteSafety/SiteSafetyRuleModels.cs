namespace HIP.Application.SiteSafety;

/// <summary>
/// Severity for built-in and admin-managed Site Safety rules.
/// </summary>
public enum SiteSafetyRuleSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Evidence quality for a rule match.
/// </summary>
public enum SiteSafetyEvidenceQuality
{
    Weak,
    Medium,
    Strong,
    Confirmed
}

/// <summary>
/// Site Safety rule collection buckets used by built-in rule definitions.
/// </summary>
public enum SiteSafetyRuleCollectionType
{
    MalwareRiskRules,
    PhishingRiskRules,
    StatusRules,
    StatusLabelRules,
    OverrideRules,
    DownloadRiskRules,
    FormRiskRules,
    RedirectRiskRules,
    ScriptRiskRules,
    ReputationRiskRules,
    ExternalEvidenceRules,
    ConfidenceRules
}

/// <summary>
/// Identifies where a Site Safety rule came from.
/// </summary>
public enum SiteSafetyRuleSource
{
    BuiltIn,
    Admin
}

/// <summary>
/// Execution mode for strongly typed Site Safety rules.
/// </summary>
public enum SiteSafetyRuleMode
{
    Enforced,
    Simulation
}

/// <summary>
/// Risk score bucket affected by a Site Safety rule.
/// </summary>
public enum SiteSafetyRiskCategory
{
    Malware,
    Phishing,
    Redirect,
    Script,
    Download,
    Form,
    Reputation,
    Confidence
}

/// <summary>
/// Options used by built-in Site Safety rules.
/// </summary>
public sealed class SiteSafetyRuleOptions
{
    /// <summary>
    /// Gets or sets how long recent scan results are cached.
    /// </summary>
    public TimeSpan ScanCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the executable download risk impact.
    /// </summary>
    public int ExecutableDownloadRiskImpact { get; set; } = 45;

    /// <summary>
    /// Gets or sets the archive download risk impact.
    /// </summary>
    public int ArchiveDownloadRiskImpact { get; set; } = 18;

    /// <summary>
    /// Gets or sets the login form risk impact when trust data is limited.
    /// </summary>
    public int LoginFormLimitedDataRiskImpact { get; set; } = 45;

    /// <summary>
    /// Gets or sets the login form risk impact when trust data is available.
    /// </summary>
    public int LoginFormTrustedContextRiskImpact { get; set; } = 18;

    /// <summary>
    /// Gets or sets the payment form risk impact when trust data is limited.
    /// </summary>
    public int PaymentFormLimitedDataRiskImpact { get; set; } = 50;

    /// <summary>
    /// Gets or sets the payment form risk impact when trust data is available.
    /// </summary>
    public int PaymentFormTrustedContextRiskImpact { get; set; } = 20;

    /// <summary>
    /// Gets or sets the suspicious redirect risk impact.
    /// </summary>
    public int SuspiciousRedirectRiskImpact { get; set; } = 60;

    /// <summary>
    /// Gets or sets the long redirect chain risk impact.
    /// </summary>
    public int LongRedirectChainRiskImpact { get; set; } = 45;

    /// <summary>
    /// Gets or sets the known phishing pattern risk impact.
    /// </summary>
    public int KnownPhishingRiskImpact { get; set; } = 85;

    /// <summary>
    /// Gets or sets the known malware indicator risk impact.
    /// </summary>
    public int KnownMalwareRiskImpact { get; set; } = 95;

    /// <summary>
    /// Gets or sets the suspicious wording phishing risk impact.
    /// </summary>
    public int SuspiciousWordingRiskImpact { get; set; } = 55;

    /// <summary>
    /// Gets or sets the maximum positive trust boost external TLS evidence may provide.
    /// </summary>
    public int MaxExternalTrustBoost { get; set; } = 5;
}

/// <summary>
/// Code-based built-in Site Safety rule.
/// </summary>
public sealed class BuiltInSiteSafetyRule
{
    /// <summary>
    /// Initializes a built-in Site Safety rule.
    /// </summary>
    public BuiltInSiteSafetyRule(
        string ruleId,
        string name,
        string description,
        SiteSafetyRuleCollectionType collectionType,
        SiteSafetyRiskCategory riskCategory,
        Func<SiteSafetyRuleInput, bool> condition,
        int riskImpact,
        int trustImpact,
        string reason,
        string? warning,
        SiteSafetyRuleSeverity severity,
        SiteSafetyEvidenceQuality evidenceQuality,
        SiteSafetyScanStatus? statusOverride = null,
        int confidencePenalty = 0,
        bool sendToAdminReview = false)
    {
        RuleId = ruleId;
        Name = name;
        Description = description;
        Source = SiteSafetyRuleSource.BuiltIn;
        Mode = SiteSafetyRuleMode.Enforced;
        CollectionType = collectionType;
        RiskCategory = riskCategory;
        Condition = condition;
        RiskImpact = _ => riskImpact;
        TrustImpact = trustImpact;
        Reason = reason;
        Warning = warning;
        Severity = severity;
        EvidenceQuality = evidenceQuality;
        StatusOverride = statusOverride;
        ConfidencePenalty = confidencePenalty;
        SendToAdminReview = sendToAdminReview;
    }

    /// <summary>
    /// Initializes a built-in Site Safety rule with an input-dependent risk impact.
    /// </summary>
    public BuiltInSiteSafetyRule(
        string ruleId,
        string name,
        string description,
        SiteSafetyRuleCollectionType collectionType,
        SiteSafetyRiskCategory riskCategory,
        Func<SiteSafetyRuleInput, bool> condition,
        Func<SiteSafetyRuleInput, int> riskImpact,
        int trustImpact,
        string reason,
        string? warning,
        SiteSafetyRuleSeverity severity,
        SiteSafetyEvidenceQuality evidenceQuality,
        SiteSafetyScanStatus? statusOverride = null,
        int confidencePenalty = 0,
        bool sendToAdminReview = false)
    {
        RuleId = ruleId;
        Name = name;
        Description = description;
        Source = SiteSafetyRuleSource.BuiltIn;
        Mode = SiteSafetyRuleMode.Enforced;
        CollectionType = collectionType;
        RiskCategory = riskCategory;
        Condition = condition;
        RiskImpact = riskImpact;
        TrustImpact = trustImpact;
        Reason = reason;
        Warning = warning;
        Severity = severity;
        EvidenceQuality = evidenceQuality;
        StatusOverride = statusOverride;
        ConfidencePenalty = confidencePenalty;
        SendToAdminReview = sendToAdminReview;
    }

    /// <summary>Gets the stable rule ID.</summary>
    public string RuleId { get; }

    /// <summary>Gets the short human-readable rule name.</summary>
    public string Name { get; }

    /// <summary>Gets the rule description.</summary>
    public string Description { get; }

    /// <summary>Gets where the rule came from so built-in and admin rules can be explained separately.</summary>
    public SiteSafetyRuleSource Source { get; }

    /// <summary>Gets whether the rule enforces or only simulates its effect.</summary>
    public SiteSafetyRuleMode Mode { get; }

    /// <summary>Gets the rule collection bucket.</summary>
    public SiteSafetyRuleCollectionType CollectionType { get; }

    /// <summary>Gets the risk category affected by this rule.</summary>
    public SiteSafetyRiskCategory RiskCategory { get; }

    /// <summary>Gets the strongly typed condition used by built-in code rules.</summary>
    public Func<SiteSafetyRuleInput, bool> Condition { get; }

    /// <summary>Gets the risk impact.</summary>
    public Func<SiteSafetyRuleInput, int> RiskImpact { get; }

    /// <summary>Gets the trust impact.</summary>
    public int TrustImpact { get; }

    /// <summary>Gets the plain-English reason.</summary>
    public string Reason { get; }

    /// <summary>Gets the optional warning.</summary>
    public string? Warning { get; }

    /// <summary>Gets the severity.</summary>
    public SiteSafetyRuleSeverity Severity { get; }

    /// <summary>Gets the evidence quality.</summary>
    public SiteSafetyEvidenceQuality EvidenceQuality { get; }

    /// <summary>Gets an optional status override.</summary>
    public SiteSafetyScanStatus? StatusOverride { get; }

    /// <summary>Gets the confidence penalty.</summary>
    public int ConfidencePenalty { get; }

    /// <summary>Gets whether the result should be sent to admin review.</summary>
    public bool SendToAdminReview { get; }

    /// <summary>
    /// Evaluates this rule against a privacy-safe input model.
    /// </summary>
    /// <param name="input">Rule input.</param>
    /// <returns>Matched result when the condition is true.</returns>
    public SiteSafetyRuleResult? Evaluate(SiteSafetyRuleInput input) =>
        Condition(input)
            ? new SiteSafetyRuleResult(RuleId, Name, Description, Source, CollectionType, RiskCategory, RiskImpact(input), TrustImpact, Reason, Warning, Severity, EvidenceQuality, StatusOverride, ConfidencePenalty, SendToAdminReview, IsSimulationOnly: Mode == SiteSafetyRuleMode.Simulation)
            : null;
}

/// <summary>
/// Privacy-safe input available to built-in and admin Site Safety rules.
/// </summary>
public sealed record SiteSafetyRuleInput(
    Uri Url,
    string Domain,
    string Tld,
    bool HasHttps,
    int RedirectCount,
    int ShortenedLinkCount,
    int ObfuscatedLinkCount,
    bool HasSuspiciousQueryShape,
    int ExternalScriptCount,
    int InlineScriptCount,
    int SuspiciousScriptPatternCount,
    int ExecutableDownloadCount,
    int ArchiveDownloadCount,
    bool HasLoginForm,
    bool HasPasswordField,
    bool HasPaymentField,
    int KnownAbuseReports,
    int? DomainReputationScore,
    int? PageReputationScore,
    IReadOnlyCollection<string> MatchedRiskTerms,
    IReadOnlyCollection<SiteSafetyEvidence> ProviderEvidence,
    bool TrustDataAvailable);

/// <summary>
/// Result created when a Site Safety rule matches.
/// </summary>
public sealed record SiteSafetyRuleResult(
    string RuleId,
    string RuleName,
    string Description,
    SiteSafetyRuleSource Source,
    SiteSafetyRuleCollectionType CollectionType,
    SiteSafetyRiskCategory RiskCategory,
    int RiskImpact,
    int TrustImpact,
    string Reason,
    string? Warning,
    SiteSafetyRuleSeverity Severity,
    SiteSafetyEvidenceQuality EvidenceQuality,
    SiteSafetyScanStatus? StatusOverride,
    int ConfidencePenalty,
    bool SendToAdminReview,
    bool IsSimulationOnly,
    string? PositiveSignal = null,
    string? NegativeSignal = null);

/// <summary>
/// Privacy-safe context used by ordered status label rules after risk rules have been evaluated.
/// </summary>
public sealed record SiteSafetyRuleEvaluationContext(
    int MalwareRiskScore,
    int PhishingRiskScore,
    int RedirectRiskScore,
    int ScriptRiskScore,
    int DownloadRiskScore,
    int FormRiskScore,
    int ReputationRiskScore,
    int OverallSafetyRiskScore,
    bool TrustDataAvailable,
    bool HasAuthoritativeRiskHit,
    SiteSafetyScanStatus? StatusOverride);

/// <summary>
/// Ordered status label rule used to avoid hard-coded status if/else chains in the scanner.
/// </summary>
public sealed record SiteSafetyStatusRule(
    string RuleId,
    string Name,
    string Description,
    int Priority,
    Func<SiteSafetyRuleEvaluationContext, bool> Condition,
    Func<SiteSafetyRuleEvaluationContext, SiteSafetyScanStatus> StatusFactory,
    string Reason);

/// <summary>
/// Evaluates ordered Site Safety status label rules.
/// </summary>
public static class SiteSafetyRuleEvaluator
{
    /// <summary>
    /// Selects the first matching status label by priority.
    /// </summary>
    /// <param name="context">Aggregated risk context created from matched risk rules.</param>
    /// <param name="rules">Ordered or unordered status rules.</param>
    /// <returns>The selected status label.</returns>
    public static SiteSafetyScanStatus EvaluateStatus(SiteSafetyRuleEvaluationContext context, IReadOnlyCollection<SiteSafetyStatusRule> rules) =>
        rules.OrderBy(rule => rule.Priority)
            .FirstOrDefault(rule => rule.Condition(context))
            ?.StatusFactory(context) ?? SiteSafetyScanStatus.Unknown;
}

/// <summary>
/// Builds the HIP built-in Site Safety rule collections.
/// </summary>
public static class BuiltInSiteSafetyRules
{
    /// <summary>
    /// Creates all built-in rules from configurable options.
    /// </summary>
    /// <param name="options">Rule options.</param>
    /// <returns>Built-in rule collection.</returns>
    public static IReadOnlyCollection<BuiltInSiteSafetyRule> Create(SiteSafetyRuleOptions options) =>
    [
        new("malware-known-indicator", "Known malware indicator", "Known malware indicators force a dangerous status.", SiteSafetyRuleCollectionType.MalwareRiskRules, SiteSafetyRiskCategory.Malware, input => input.MatchedRiskTerms.Contains("KnownMalwareIndicator", StringComparer.OrdinalIgnoreCase), options.KnownMalwareRiskImpact, 0, "HIP found strong malware or phishing indicators. Avoid this page.", "HIP found a strong malware indicator.", SiteSafetyRuleSeverity.Critical, SiteSafetyEvidenceQuality.Confirmed, SiteSafetyScanStatus.Dangerous, sendToAdminReview: true),
        new("phishing-known-pattern", "Known phishing pattern", "Known phishing indicators force a dangerous status.", SiteSafetyRuleCollectionType.PhishingRiskRules, SiteSafetyRiskCategory.Phishing, input => input.MatchedRiskTerms.Contains("KnownPhishingPattern", StringComparer.OrdinalIgnoreCase), options.KnownPhishingRiskImpact, 0, "HIP found a known phishing pattern.", "HIP found a known phishing pattern.", SiteSafetyRuleSeverity.Critical, SiteSafetyEvidenceQuality.Confirmed, SiteSafetyScanStatus.Dangerous, sendToAdminReview: true),
        new("phishing-risk-terms", "Scam wording labels", "Scam, urgency, or impersonation terms increase phishing risk.", SiteSafetyRuleCollectionType.PhishingRiskRules, SiteSafetyRiskCategory.Phishing, input => input.MatchedRiskTerms.Any(term => term is "ScamWording" or "UrgencyWording" or "ImpersonationWording" or "CrackedSoftware" or "DisableAntivirus"), options.SuspiciousWordingRiskImpact, 0, "Risk wording labels were observed without sending page text.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("phishing-suspicious-query", "Suspicious URL query shape", "Suspicious query-string shape increases phishing risk without logging query values.", SiteSafetyRuleCollectionType.PhishingRiskRules, SiteSafetyRiskCategory.Phishing, input => input.HasSuspiciousQueryShape, 35, 0, "The URL contains unusual query parameters often seen in tracking or redirect abuse.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Weak),
        new("transport-https-present", "HTTPS present", "HTTPS is a small transport security signal, never proof of trust.", SiteSafetyRuleCollectionType.ConfidenceRules, SiteSafetyRiskCategory.Confidence, input => input.HasHttps, 0, 1, "HTTPS is present, which protects transport encryption but does not prove the site is trusted.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak),
        new("transport-https-missing", "Missing HTTPS", "Missing HTTPS slightly increases page phishing risk.", SiteSafetyRuleCollectionType.ConfidenceRules, SiteSafetyRiskCategory.Phishing, input => !input.HasHttps, 20, 0, "Missing HTTPS increases page trust risk.", "This page does not use HTTPS.", SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Medium),
        new("download-executable", "Executable download", "Executable download links increase content risk.", SiteSafetyRuleCollectionType.DownloadRiskRules, SiteSafetyRiskCategory.Download, input => input.ExecutableDownloadCount > 0, options.ExecutableDownloadRiskImpact, 0, "This page links to executable files that should be reviewed before downloading.", "This page links to executable files that should not be downloaded unless the source is trusted.", SiteSafetyRuleSeverity.High, SiteSafetyEvidenceQuality.Strong),
        new("download-archive", "Archive download", "Archive download links require review.", SiteSafetyRuleCollectionType.DownloadRiskRules, SiteSafetyRiskCategory.Download, input => input.ArchiveDownloadCount > 0, options.ArchiveDownloadRiskImpact, 0, "This page links to compressed files that should be reviewed before downloading.", "This page links to compressed or disk image files that need review.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("form-login-limited-data", "Login form on limited-data domain", "Login forms on limited-data sites increase risk.", SiteSafetyRuleCollectionType.FormRiskRules, SiteSafetyRiskCategory.Form, input => (input.HasLoginForm || input.HasPasswordField) && !input.TrustDataAvailable, options.LoginFormLimitedDataRiskImpact, 0, "This page contains login fields, but HIP has limited trust data for the domain.", "This page contains login fields; verify the domain before entering credentials.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("form-login-trusted-context", "Login form with trust data", "Login forms still require light review even with trust data.", SiteSafetyRuleCollectionType.FormRiskRules, SiteSafetyRiskCategory.Form, input => (input.HasLoginForm || input.HasPasswordField) && input.TrustDataAvailable, options.LoginFormTrustedContextRiskImpact, 0, "This page contains login fields.", "This page contains login fields; verify the domain before entering credentials.", SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Medium),
        new("form-payment-limited-data", "Payment field on limited-data domain", "Payment fields on limited-data sites increase risk.", SiteSafetyRuleCollectionType.FormRiskRules, SiteSafetyRiskCategory.Form, input => input.HasPaymentField && !input.TrustDataAvailable, options.PaymentFormLimitedDataRiskImpact, 0, "Payment fields require domain and identity review.", "This page contains payment fields; review the domain and identity before entering payment details.", SiteSafetyRuleSeverity.High, SiteSafetyEvidenceQuality.Medium),
        new("form-payment-trusted-context", "Payment field with trust data", "Payment fields still require review with trust data.", SiteSafetyRuleCollectionType.FormRiskRules, SiteSafetyRiskCategory.Form, input => input.HasPaymentField && input.TrustDataAvailable, options.PaymentFormTrustedContextRiskImpact, 0, "Payment fields require review.", "This page contains payment fields; review the domain and identity before entering payment details.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("redirect-long-chain", "Long redirect chain", "Long redirect chains increase redirect risk.", SiteSafetyRuleCollectionType.RedirectRiskRules, SiteSafetyRiskCategory.Redirect, input => input.RedirectCount > 3, options.LongRedirectChainRiskImpact, 0, "This page uses a long redirect chain.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("redirect-shortener", "Shortener redirect", "Shorteners can hide the destination.", SiteSafetyRuleCollectionType.RedirectRiskRules, SiteSafetyRiskCategory.Redirect, input => input.ShortenedLinkCount > 0, options.SuspiciousRedirectRiskImpact, 0, "Shortened or suspicious link patterns can hide the final destination.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("redirect-obfuscated", "Obfuscated link", "Obfuscated links increase redirect risk.", SiteSafetyRuleCollectionType.RedirectRiskRules, SiteSafetyRiskCategory.Redirect, input => input.ObfuscatedLinkCount > 0, options.SuspiciousRedirectRiskImpact, 0, "Obfuscated links were detected by a privacy-safe client scan.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("script-suspicious-patterns", "Suspicious script structure", "Suspicious script structure increases script risk.", SiteSafetyRuleCollectionType.ScriptRiskRules, SiteSafetyRiskCategory.Script, input => input.SuspiciousScriptPatternCount > 0, 25, 0, "HIP saw script signals that increase content risk without executing scripts.", "Script structure should be reviewed before trusting this page.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("script-high-volume", "High script volume", "Large script volume increases script risk.", SiteSafetyRuleCollectionType.ScriptRiskRules, SiteSafetyRiskCategory.Script, input => input.InlineScriptCount > 8 || input.ExternalScriptCount > 12, input => Math.Min(70, Math.Max(0, input.InlineScriptCount - 8) * 3 + Math.Max(0, input.ExternalScriptCount - 12) * 2), 0, "External or inline JavaScript volume increased script risk.", "Script structure should be reviewed before trusting this page.", SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak),
        new("reputation-risky-tld", "Risky TLD review", "Some TLDs require extra early review.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, input => SiteSafetyRuleHelpers.RiskyTlds.Contains(input.Tld), 25, 0, "The domain uses a TLD that can require extra review in early HIP scoring.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak),
        new("reputation-abuse-reports", "Known abuse reports", "Known abuse reports increase reputation risk.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, input => input.KnownAbuseReports > 0, input => Math.Min(85, 30 + input.KnownAbuseReports * 10), 0, "Known abuse reports are present for this page or domain.", null, SiteSafetyRuleSeverity.High, SiteSafetyEvidenceQuality.Strong),
        new("reputation-domain-score", "Weak domain reputation", "Weak domain reputation increases reputation risk.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, input => input.DomainReputationScore is < 50, 55, 0, "Domain reputation is weak.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("reputation-page-score", "Weak page reputation", "Weak page reputation increases reputation risk.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, input => input.PageReputationScore is < 50, 55, 0, "Page reputation is weak.", null, SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Medium),
        new("feedback-looks-safe", "Weighted safe feedback", "Weighted safe feedback gives only a small capped support signal.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasLooksSafeFeedback, 0, 2, "Trusted feedback suggests this warning may be too strong, but feedback alone does not prove safety.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak),
        new("feedback-suspicious", "Weighted suspicious feedback", "Weighted suspicious feedback increases reputation risk without directly creating malware or phishing findings.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasSuspiciousFeedback, SiteSafetyRuleHelpers.FeedbackRiskImpact, 0, "Some users have reported this site as suspicious, but HIP has not confirmed a threat.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak),
        new("feedback-conflict", "Conflicting feedback", "Conflicting feedback lowers confidence and recommends review.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Confidence, SiteSafetyRuleHelpers.HasConflictingFeedback, 0, 0, "Recent feedback is conflicting, so HIP lowered confidence and recommends review.", "Recent feedback is conflicting, so HIP recommends review before changing trust significantly.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Weak, confidencePenalty: 25, sendToAdminReview: true),
        new("feedback-review-signal", "Feedback review signal", "Feedback patterns can request admin review without directly controlling score.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Confidence, SiteSafetyRuleHelpers.HasFeedbackReviewSignal, 0, 0, "Feedback patterns recommend admin review before HIP changes trust significantly.", "Feedback patterns recommend admin review before HIP changes trust significantly.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Weak, confidencePenalty: 10, sendToAdminReview: true),
        new("admin-review-safe", "Admin safe review", "Admin safe or false-positive review gives only a small capped support signal.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasAdminSafeReview, 0, 3, "Admin review found privacy-safe evidence supporting a safer interpretation, but this alone does not make the site trusted.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Strong),
        new("admin-review-needs-more-data", "Admin needs more data", "Admin review needing more data lowers confidence.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Confidence, SiteSafetyRuleHelpers.HasAdminNeedsMoreDataReview, 0, 0, "Admin review needs more privacy-safe evidence before HIP makes a stronger decision.", "Admin review needs more privacy-safe evidence before HIP makes a stronger decision.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Weak, confidencePenalty: 20, sendToAdminReview: true),
        new("admin-review-suspicious", "Admin suspicious review", "Admin-confirmed suspicious review increases reputation risk.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasAdminSuspiciousReview, SiteSafetyRuleHelpers.AdminReviewRiskImpact, 0, "Admin review confirmed suspicious behavior from privacy-safe evidence.", "Admin review confirmed suspicious behavior.", SiteSafetyRuleSeverity.Medium, SiteSafetyEvidenceQuality.Strong),
        new("admin-review-high-risk", "Admin high-risk review", "Admin-confirmed high-risk review affects status transparently.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasAdminHighRiskReview, SiteSafetyRuleHelpers.AdminReviewRiskImpact, 0, "Admin review confirmed high-risk behavior from privacy-safe evidence.", "Admin review confirmed high-risk behavior.", SiteSafetyRuleSeverity.High, SiteSafetyEvidenceQuality.Strong, SiteSafetyScanStatus.HighRisk, sendToAdminReview: true),
        new("admin-review-dangerous", "Admin dangerous review", "Admin-confirmed dangerous review affects status transparently.", SiteSafetyRuleCollectionType.ReputationRiskRules, SiteSafetyRiskCategory.Reputation, SiteSafetyRuleHelpers.HasAdminDangerousReview, SiteSafetyRuleHelpers.AdminReviewRiskImpact, 0, "Admin review confirmed dangerous behavior from privacy-safe evidence.", "Admin review confirmed dangerous behavior.", SiteSafetyRuleSeverity.Critical, SiteSafetyEvidenceQuality.Strong, SiteSafetyScanStatus.Dangerous, sendToAdminReview: true),
        new("external-weak", "Weak external evidence", "Weak external evidence lowers confidence.", SiteSafetyRuleCollectionType.ExternalEvidenceRules, SiteSafetyRiskCategory.Confidence, input => input.ProviderEvidence.SelectMany(evidence => evidence.EvidenceItems).Any(item => item.Status == SiteSafetyEvidenceStatus.Weak), 0, 0, "External TLS or provider evidence is weak and lowers confidence.", "External TLS or provider evidence is weak and lowers confidence.", SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Weak, confidencePenalty: 20),
        new("external-conflict", "Conflicting external evidence", "Conflicting external evidence lowers confidence and creates review warning.", SiteSafetyRuleCollectionType.ExternalEvidenceRules, SiteSafetyRiskCategory.Confidence, SiteSafetyRuleHelpers.HasConflictingExternalEvidence, 0, 0, "External scanner evidence conflicts; HIP lowered confidence and recommends review.", "External scanner evidence conflicts; HIP lowered confidence and recommends review.", SiteSafetyRuleSeverity.High, SiteSafetyEvidenceQuality.Medium, confidencePenalty: 35, sendToAdminReview: true),
        new("external-threat-intel-phishing", "External phishing hit", "Authoritative phishing evidence raises phishing risk.", SiteSafetyRuleCollectionType.ExternalEvidenceRules, SiteSafetyRiskCategory.Phishing, input => SiteSafetyRuleHelpers.HasAuthoritativeExternalHit(input, "phishing"), 90, 0, "Threat-intel provider matched a phishing indicator.", null, SiteSafetyRuleSeverity.Critical, SiteSafetyEvidenceQuality.Confirmed, SiteSafetyScanStatus.HighRisk, sendToAdminReview: true),
        new("external-threat-intel-malware", "External malware hit", "Authoritative malware evidence raises malware risk.", SiteSafetyRuleCollectionType.ExternalEvidenceRules, SiteSafetyRiskCategory.Malware, input => SiteSafetyRuleHelpers.HasAuthoritativeExternalHit(input, "malware"), 95, 0, "Threat-intel provider matched a malware indicator.", null, SiteSafetyRuleSeverity.Critical, SiteSafetyEvidenceQuality.Confirmed, SiteSafetyScanStatus.Dangerous, sendToAdminReview: true),
        new("external-positive-tls", "Strong TLS evidence", "Strong TLS evidence gives a small trust boost only.", SiteSafetyRuleCollectionType.ExternalEvidenceRules, SiteSafetyRiskCategory.Reputation, input => SiteSafetyRuleHelpers.HasPositiveTlsEvidence(input), 0, options.MaxExternalTrustBoost, "TLS scanner reported strong TLS configuration.", null, SiteSafetyRuleSeverity.Low, SiteSafetyEvidenceQuality.Medium)
    ];

    /// <summary>
    /// Creates ordered status label rules. Overrides run first, and clean scans remain limited when trust data is missing.
    /// </summary>
    /// <returns>Ordered status label rules.</returns>
    public static IReadOnlyCollection<SiteSafetyStatusRule> CreateStatusRules() =>
    [
        new("status-override", "Status override", "Confirmed rule override wins before score thresholds.", 10, context => context.StatusOverride is not null, context => context.StatusOverride!.Value, "A matched rule set a status override."),
        new("status-dangerous-malware-phishing", "Dangerous malware or phishing", "Confirmed malware or phishing risk forces Dangerous.", 20, context => context.MalwareRiskScore >= 90 || context.PhishingRiskScore >= 85, _ => SiteSafetyScanStatus.Dangerous, "Malware or phishing risk reached the Dangerous threshold."),
        new("status-authoritative-risk", "Authoritative external risk", "Authoritative threat intelligence raises the status to at least HighRisk.", 30, context => context.HasAuthoritativeRiskHit, _ => SiteSafetyScanStatus.HighRisk, "Authoritative external evidence matched risk."),
        new("status-high-risk-score", "High overall risk", "Overall safety risk at or above 65 is HighRisk.", 40, context => context.OverallSafetyRiskScore >= 65, _ => SiteSafetyScanStatus.HighRisk, "Overall safety risk reached the HighRisk threshold."),
        new("status-suspicious-download", "Suspicious download risk", "Executable download risk is suspicious even if overall risk is moderate.", 50, context => context.DownloadRiskScore >= 45, _ => SiteSafetyScanStatus.Suspicious, "Download risk requires review."),
        new("status-suspicious-score", "Suspicious overall risk", "Overall safety risk at or above 30 is Suspicious.", 60, context => context.OverallSafetyRiskScore >= 30, _ => SiteSafetyScanStatus.Suspicious, "Overall safety risk reached the Suspicious threshold."),
        new("status-clean-with-trust", "Clean with trust data", "Clean means no major safety risk and separate trust data exists.", 70, context => context.TrustDataAvailable, _ => SiteSafetyScanStatus.Clean, "No major risk was found and HIP has trust data."),
        new("status-limited-data", "Limited trust data", "No major risk without trust data stays LimitedData.", 80, context => !context.TrustDataAvailable, _ => SiteSafetyScanStatus.LimitedData, "No major risk was found, but HIP has limited trust data.")
    ];
}

/// <summary>
/// Helper methods shared by built-in Site Safety rules.
/// </summary>
public static class SiteSafetyRuleHelpers
{
    /// <summary>
    /// Gets TLDs that require extra review during early HIP scoring.
    /// </summary>
    public static readonly HashSet<string> RiskyTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip",
        "mov",
        "top",
        "xyz",
        "ru",
        "tk"
    };

    /// <summary>
    /// Gets common shortener domains that can hide final destinations.
    /// </summary>
    public static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly",
        "rebrand.ly",
        "cutt.ly"
    };

    /// <summary>
    /// Detects conflicting external evidence.
    /// </summary>
    public static bool HasConflictingExternalEvidence(SiteSafetyRuleInput input) =>
        input.ProviderEvidence.Any(evidence => evidence.ProviderType is not SiteSafetyEvidenceProviderType.BrowserObserved &&
                                                evidence.EvidenceItems.Any(item => item.Status is SiteSafetyEvidenceStatus.Clean or SiteSafetyEvidenceStatus.Positive)) &&
        input.ProviderEvidence.Any(evidence => evidence.IsAuthoritativeForRisk &&
                                                evidence.EvidenceItems.Any(item => item.Status is SiteSafetyEvidenceStatus.HighRisk or SiteSafetyEvidenceStatus.Dangerous));

    /// <summary>
    /// Detects authoritative external malware or phishing hits.
    /// </summary>
    public static bool HasAuthoritativeExternalHit(SiteSafetyRuleInput input, string category) =>
        input.ProviderEvidence.Any(evidence => evidence.IsAuthoritativeForRisk &&
                                                evidence.EvidenceItems.Any(item => item.Category.Contains(category, StringComparison.OrdinalIgnoreCase) &&
                                                                                   item.Status is SiteSafetyEvidenceStatus.HighRisk or SiteSafetyEvidenceStatus.Dangerous));

    /// <summary>
    /// Detects positive TLS evidence that can provide only a small security boost.
    /// </summary>
    public static bool HasPositiveTlsEvidence(SiteSafetyRuleInput input) =>
        input.ProviderEvidence.Any(evidence => evidence.ProviderType == SiteSafetyEvidenceProviderType.TlsScanner &&
                                                evidence.IsAuthoritativeForTrust &&
                                                evidence.EvidenceItems.Any(item => item.Status is SiteSafetyEvidenceStatus.Clean or SiteSafetyEvidenceStatus.Positive));

    /// <summary>
    /// Detects weighted LooksSafe feedback.
    /// </summary>
    public static bool HasLooksSafeFeedback(SiteSafetyRuleInput input) =>
        UserFeedbackItems(input).Any(item => item.Category.Equals("LooksSafe", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects weighted suspicious or report-issue feedback.
    /// </summary>
    public static bool HasSuspiciousFeedback(SiteSafetyRuleInput input) =>
        UserFeedbackItems(input).Any(item => item.Category.Equals("LooksSuspicious", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects conflicting feedback that should lower confidence.
    /// </summary>
    public static bool HasConflictingFeedback(SiteSafetyRuleInput input) =>
        UserFeedbackItems(input).Any(item => item.Category.Equals("ConflictingFeedback", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects feedback patterns that should create an admin-review signal.
    /// </summary>
    public static bool HasFeedbackReviewSignal(SiteSafetyRuleInput input) =>
        UserFeedbackItems(input).Any(item => item.Category.Equals("AdminReviewSignal", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Calculates the conservative reputation-risk impact from weighted feedback evidence.
    /// </summary>
    public static int FeedbackRiskImpact(SiteSafetyRuleInput input) =>
        Math.Clamp(UserFeedbackItems(input)
            .Where(item => item.Category.Equals("LooksSuspicious", StringComparison.OrdinalIgnoreCase))
            .Select(item => item.RiskImpact)
            .DefaultIfEmpty(0)
            .Max(), 0, 35);

    /// <summary>
    /// Detects admin-confirmed safe or false-positive decisions.
    /// </summary>
    public static bool HasAdminSafeReview(SiteSafetyRuleInput input) =>
        AdminReviewItems(input).Any(item => item.Category is "AdminConfirmSafe" or "AdminFalsePositive");

    /// <summary>
    /// Detects admin decisions that need more evidence and should lower confidence.
    /// </summary>
    public static bool HasAdminNeedsMoreDataReview(SiteSafetyRuleInput input) =>
        AdminReviewItems(input).Any(item => item.Category.Equals("AdminNeedsMoreData", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects admin-confirmed suspicious decisions.
    /// </summary>
    public static bool HasAdminSuspiciousReview(SiteSafetyRuleInput input) =>
        AdminReviewItems(input).Any(item => item.Category.Equals("AdminConfirmSuspicious", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects admin-confirmed high-risk decisions.
    /// </summary>
    public static bool HasAdminHighRiskReview(SiteSafetyRuleInput input) =>
        AdminReviewItems(input).Any(item => item.Category.Equals("AdminConfirmHighRisk", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Detects admin-confirmed dangerous decisions.
    /// </summary>
    public static bool HasAdminDangerousReview(SiteSafetyRuleInput input) =>
        AdminReviewItems(input).Any(item => item.Category.Equals("AdminConfirmDangerous", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Calculates the strongest admin-review risk impact while preserving rule transparency.
    /// </summary>
    public static int AdminReviewRiskImpact(SiteSafetyRuleInput input) =>
        Math.Clamp(AdminReviewItems(input)
            .Where(item => item.Category.StartsWith("AdminConfirm", StringComparison.OrdinalIgnoreCase))
            .Select(item => item.RiskImpact)
            .DefaultIfEmpty(0)
            .Max(), 0, 95);

    /// <summary>
    /// Enumerates user feedback evidence items only.
    /// </summary>
    private static IEnumerable<SiteSafetyEvidenceItem> UserFeedbackItems(SiteSafetyRuleInput input) =>
        input.ProviderEvidence
            .Where(evidence => evidence.ProviderType == SiteSafetyEvidenceProviderType.UserFeedback)
            .SelectMany(evidence => evidence.EvidenceItems);

    /// <summary>
    /// Enumerates approved admin review evidence items only.
    /// </summary>
    private static IEnumerable<SiteSafetyEvidenceItem> AdminReviewItems(SiteSafetyRuleInput input) =>
        input.ProviderEvidence
            .Where(evidence => evidence.ProviderType == SiteSafetyEvidenceProviderType.AdminReview)
            .SelectMany(evidence => evidence.EvidenceItems);
}
