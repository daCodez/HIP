using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.Identity;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using HIP.Domain.Audit;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Dashboard;

/// <summary>
/// Aggregates privacy-safe HIP dashboard metrics from stored browser scans and administrative workflow services.
/// </summary>
/// <param name="browserScanResultRepository">Repository containing stored browser plugin scan summaries.</param>
/// <param name="dashboardScanAggregateStore">Pre-aggregated scan counter store for dashboard hot-path reads.</param>
/// <param name="riskFindingRepository">Repository containing privacy-safe risk finding reports.</param>
/// <param name="reviewQueueRepository">Review queue repository used for bounded dashboard read projections.</param>
/// <param name="appealRepository">Appeal repository used for bounded dashboard read projections.</param>
/// <param name="reputationOverrideRepository">Reputation override repository used for bounded dashboard read projections.</param>
/// <param name="auditLogRepository">Audit log repository used for bounded dashboard read projections.</param>
/// <param name="ruleRepository">Rule repository.</param>
/// <param name="generatedRuleCandidateRepository">Generated rule candidate repository.</param>
/// <param name="adminReviewQueueRepository">Generated admin review signal repository.</param>
/// <param name="weightedFeedbackRepository">Weighted feedback repository.</param>
/// <param name="adminSiteSafetyRuleRepository">Admin-managed Site Safety rule repository.</param>
/// <param name="websiteIdentityRepository">Registered website identity repository.</param>
public sealed class AdminDashboardService(
    IBrowserScanResultRepository browserScanResultRepository,
    IDashboardScanAggregateStore dashboardScanAggregateStore,
    IRiskFindingReportRepository riskFindingRepository,
    IReviewQueueRepository reviewQueueRepository,
    IAppealRepository appealRepository,
    IReputationOverrideRequestRepository reputationOverrideRepository,
    IAuditLogRepository auditLogRepository,
    IRuleRepository ruleRepository,
    IGeneratedRuleCandidateRepository generatedRuleCandidateRepository,
    IAdminReviewQueueRepository adminReviewQueueRepository,
    IWeightedFeedbackRepository weightedFeedbackRepository,
    IAdminSiteSafetyRuleRepository adminSiteSafetyRuleRepository,
    IWebsiteIdentityRepository websiteIdentityRepository,
    IDomainCertificateAdminQuery? domainCertificateAdminQuery = null) : IAdminDashboardService
{
    private static readonly TimeSpan LegacyReadBudget = TimeSpan.FromMilliseconds(750);

    /// <summary>
    /// Builds a privacy-safe dashboard summary using stored browser scan results as the primary real scan source.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel repository reads.</param>
    /// <returns>Admin dashboard summary.</returns>
    public async Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken)
    {
        // The legacy aggregate predates scan provenance and can contain anonymous client
        // observations. Keep the injected store for contract compatibility, but derive all
        // authoritative metrics from records whose server-owned provenance can be verified.
        _ = dashboardScanAggregateStore;
        var browserScans = await browserScanResultRepository.ListRecentAsync(100, cancellationToken);
        var clientTelemetryRead = await ReadOptionalAsync(browserScanResultRepository.ListAsync, cancellationToken);
        // Keep the dashboard render on the hot path. Some MVP sources still use broad
        // encrypted-record scans, so each optional source gets a small read budget. These
        // reads intentionally stay sequential because the current EF-backed stores share a
        // scoped DbContext, and EF Core contexts cannot safely run concurrent operations.
        var findingsRead = await ReadOptionalAsync(riskFindingRepository.ListAsync, cancellationToken);
        var rulesRead = await ReadOptionalAsync(ruleRepository.ListAsync, cancellationToken);
        var candidatesRead = await ReadOptionalAsync(generatedRuleCandidateRepository.ListAsync, cancellationToken);
        var generatedReviewsRead = await ReadOptionalAsync(adminReviewQueueRepository.ListAsync, cancellationToken);
        var feedbackRead = await ReadOptionalAsync(weightedFeedbackRepository.ListAsync, cancellationToken);
        var adminSiteSafetyRulesRead = await ReadOptionalAsync(adminSiteSafetyRuleRepository.ListAsync, cancellationToken);
        var reviewsRead = await ReadOptionalAsync(reviewQueueRepository.ListAsync, cancellationToken);
        var appealsRead = await ReadOptionalAsync(appealRepository.ListAsync, cancellationToken);
        var overridesRead = await ReadOptionalAsync(reputationOverrideRepository.ListAsync, cancellationToken);
        var auditLogsRead = await ReadOptionalAsync(auditLogRepository.ListAsync, cancellationToken);
        var websiteIdentitiesRead = await ReadOptionalAsync(websiteIdentityRepository.ListAsync, cancellationToken);
        var domainCertificatesRead = domainCertificateAdminQuery is null
            ? new OptionalReadResult<AdminDomainCertificateSummary>([], false)
            : await ReadOptionalAsync(
                token => ListDomainCertificatesAsync(domainCertificateAdminQuery, token),
                cancellationToken);

        var findings = findingsRead.Items;
        var rules = rulesRead.Items;
        var candidates = candidatesRead.Items;
        var generatedReviews = generatedReviewsRead.Items;
        var feedback = feedbackRead.Items;
        var adminSiteSafetyRules = adminSiteSafetyRulesRead.Items;
        var reviews = reviewsRead.Items;
        var appeals = appealsRead.Items;
        var overrides = overridesRead.Items;
        var auditLogs = auditLogsRead.Items;
        var websiteIdentities = websiteIdentitiesRead.Items;
        var domainCertificates = domainCertificatesRead.Items;
        var scanHistory = clientTelemetryRead.IsAvailable ? clientTelemetryRead.Items : browserScans;
        var authoritativeScans = scanHistory
            .Where(BrowserScanResultProvenance.IsServerAuthoritative)
            .OrderByDescending(scan => scan.LastCheckedUtc)
            .ToArray();
        var clientTelemetry = clientTelemetryRead.Items
            .Where(scan => !BrowserScanResultProvenance.IsServerAuthoritative(scan))
            .OrderByDescending(scan => scan.LastCheckedUtc)
            .ToArray();

        var now = DateTimeOffset.UtcNow;
        var issuedCertificates = domainCertificates
            .Where(item => item.CertificateId is not null && item.CertificateStatus is not null && item.BadgeLevel is not null)
            .ToArray();
        var certificateTotal = issuedCertificates.Length;
        var certificateActive = issuedCertificates.Count(item => EffectiveCertificateStatus(item, now) == DomainCertificateStatus.Active);
        var certificateSuspended = issuedCertificates.Count(item => EffectiveCertificateStatus(item, now) == DomainCertificateStatus.Suspended);
        var certificateRevoked = issuedCertificates.Count(item => EffectiveCertificateStatus(item, now) == DomainCertificateStatus.Revoked);
        var certificateExpired = issuedCertificates.Count(item => EffectiveCertificateStatus(item, now) == DomainCertificateStatus.Expired);
        var certificateRenewalRequired = issuedCertificates.Count(item => EffectiveCertificateStatus(item, now) == DomainCertificateStatus.RenewalRequired);
        var certificateExpiringSoon = issuedCertificates.Count(item =>
            EffectiveCertificateStatus(item, now) == DomainCertificateStatus.Active &&
            item.ExpiresAtUtc > now &&
            item.ExpiresAtUtc <= now.AddDays(30));
        var certificateRegistered = issuedCertificates.Count(item => item.BadgeLevel == DomainCertificateLevel.Registered);
        var certificateVerified = issuedCertificates.Count(item => item.BadgeLevel == DomainCertificateLevel.Verified);
        var certificateMonitored = issuedCertificates.Count(item => item.BadgeLevel == DomainCertificateLevel.Monitored);
        var certificateEnrollmentsPending = domainCertificates.Count(item =>
            item.CertificateId is null &&
            item.EnrollmentStatus is not DomainEnrollmentStatus.Suspended and not DomainEnrollmentStatus.Revoked);
        var hasScanData = authoritativeScans.Length > 0;
        var totalScans = authoritativeScans.Length;
        var scansToday = authoritativeScans.Count(scan => scan.LastCheckedUtc.UtcDateTime.Date == now.UtcDateTime.Date);
        var domainsScanned = authoritativeScans.Select(scan => scan.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var linksScanned = authoritativeScans.Sum(scan => scan.LinksScanned);
        var riskyLinksFound = authoritativeScans.Sum(scan => scan.RiskyLinksFound);
        var suspiciousLinksFound = authoritativeScans.Sum(scan => scan.SuspiciousLinksFound);
        var dangerousLinksFound = authoritativeScans.Sum(scan => scan.DangerousLinksFound);
        var trustedResults = authoritativeScans.Count(IsTrustedScan);
        var mostlyTrustedResults = authoritativeScans.Count(IsMostlyTrustedScan);
        var limitedTrustResults = authoritativeScans.Count(IsLimitedTrustScan);
        var unknownResults = authoritativeScans.Count(IsUnknownScan);
        var suspiciousResults = authoritativeScans.Count(IsSuspiciousScan);
        var highRiskResults = authoritativeScans.Count(IsHighRiskScan);
        var dangerousResults = authoritativeScans.Count(IsDangerousScan);
        var scansLast24Hours = authoritativeScans.Count(scan => scan.LastCheckedUtc >= now.AddHours(-24));
        var scansLast7Days = authoritativeScans.Count(scan => scan.LastCheckedUtc >= now.AddDays(-7));
        var averageHipScore = hasScanData
            ? (int)Math.Round(authoritativeScans.Average(scan => scan.Score))
            : 0;
        var latestScanUtc = authoritativeScans.FirstOrDefault()?.LastCheckedUtc;
        var clientTelemetryDomains = clientTelemetry.Select(scan => scan.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var clientTelemetryAverageScore = clientTelemetry.Length == 0
            ? 0
            : (int)Math.Round(clientTelemetry.Average(scan => scan.Score));
        var clientTelemetryTrustedResults = clientTelemetry.Count(scan => IsTrustedScan(scan) || IsMostlyTrustedScan(scan));
        var clientTelemetryCautionResults = clientTelemetry.Count(scan => IsLimitedTrustScan(scan) || IsUnknownScan(scan) || IsSuspiciousScan(scan));
        var clientTelemetryRiskResults = clientTelemetry.Count(scan => IsHighRiskScan(scan) || IsDangerousScan(scan));
        var latestClientTelemetryUtc = clientTelemetry.FirstOrDefault()?.LastCheckedUtc;
        var pendingManualReviews = reviews.Count(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo);
        var pendingGeneratedReviews = generatedReviews.Count(item => item.Status is AdminReviewStatus.Open or AdminReviewStatus.InReview or AdminReviewStatus.Escalated);
        var highSeverityReviews = reviews.Count(item => item.Priority is ReviewPriority.High or ReviewPriority.Critical) +
                                  generatedReviews.Count(item => item.Severity is AdminReviewSeverity.High or AdminReviewSeverity.Critical);
        var oldestOpenReviewUtc = reviews
            .Where(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo)
            .Select(item => item.CreatedAtUtc)
            .Concat(generatedReviews
                .Where(item => item.Status is AdminReviewStatus.Open or AdminReviewStatus.InReview or AdminReviewStatus.Escalated)
                .Select(item => item.CreatedAtUtc))
            .DefaultIfEmpty()
            .Min();
        var oldestOpenReviewAgeHours = oldestOpenReviewUtc == default ? 0 : (int)Math.Max(0, Math.Round((now - oldestOpenReviewUtc).TotalHours));
        var activeTrustRules = rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Active);
        var watchTrustRules = rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Watch);
        var activeBuiltInRules = BuiltInSiteSafetyRules.Create(new SiteSafetyRuleOptions()).Count;
        var activeAdminRules = adminSiteSafetyRules.Count(rule => rule.Status == AdminSiteSafetyRuleStatus.Active && rule.Mode == AdminSiteSafetyRuleMode.Enforced);
        var simulationRules = adminSiteSafetyRules.Count(rule => rule.Mode == AdminSiteSafetyRuleMode.Simulation);
        var watchOnlyRules = adminSiteSafetyRules.Count(rule => rule.Mode == AdminSiteSafetyRuleMode.WatchOnly);
        var disabledRules = rules.Count(rule => !rule.Enabled || rule.Mode == RuleMode.Disabled) +
                            adminSiteSafetyRules.Count(rule => rule.Status is AdminSiteSafetyRuleStatus.Disabled or AdminSiteSafetyRuleStatus.Archived);
        var hasFeedbackData = feedback.Count > 0;
        var reviewSourcesAvailable = reviewsRead.IsAvailable && generatedReviewsRead.IsAvailable;
        var ruleSourcesAvailable = rulesRead.IsAvailable && adminSiteSafetyRulesRead.IsAvailable;
        var suspiciousFeedbackSpikes = CountSuspiciousFeedbackSpikes(feedback);
        var externalProviderErrors = CountExternalProviderErrors(browserScans, generatedReviews);
        var hasExternalProviderData = externalProviderErrors > 0 ||
                                      generatedReviews.Any(item => item.Source == AdminReviewSource.ExternalProvider) ||
                                      browserScans.Any(HasExternalProviderMetadata);
        var verifiedWebsiteIdentities = websiteIdentities.Count(identity => identity.VerificationStatus == VerificationStatus.Verified);
        var pendingWebsiteIdentities = websiteIdentities.Count(identity =>
            identity.VerificationStatus is VerificationStatus.Pending or VerificationStatus.Unverified);
        var inactiveWebsiteIdentities = websiteIdentities.Count(identity =>
            identity.VerificationStatus is VerificationStatus.Suspended or VerificationStatus.Revoked or VerificationStatus.Expired);

        var riskyFindings = findings.Count(finding => IsRisky(finding.RiskLevel));
        var dangerousDomains = findings
            .Where(finding => finding.RiskLevel is RiskStatus.Dangerous or RiskStatus.Critical)
            .Select(finding => finding.Domain)
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var cards = new[]
        {
            Card("totalScans", "Total Scans", totalScans, hasScanData ? "BrowserPluginScanResults" : "No Data", !hasScanData, "Stored privacy-safe browser plugin scans."),
            Card("scansToday", "Scans Today", scansToday, hasScanData ? "Today" : "No Data", !hasScanData, "Stored browser plugin scans received today in UTC."),
            Card("trustedResults", "Trusted Results", trustedResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Trusted status."),
            Card("mostlyTrustedResults", "Mostly Trusted Results", mostlyTrustedResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with MostlyTrusted or ProbablySafe status."),
            Card("limitedTrustResults", "Limited Trust Results", limitedTrustResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans where HIP has limited trust data."),
            Card("unknownResults", "Unknown Results", unknownResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Unknown status."),
            Card("suspiciousResults", "Suspicious Results", suspiciousResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Suspicious or Caution status."),
            Card("highRiskResults", "High-Risk Results", highRiskResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with HighRisk status."),
            Card("dangerousResults", "Dangerous Results", dangerousResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Dangerous or Critical status."),
            Card("domainsScanned", "Domains Scanned", domainsScanned, hasScanData ? "Distinct" : "No Data", !hasScanData, "Distinct domains with stored browser scan results."),
            Card("linksScanned", "Links Scanned", linksScanned, hasScanData ? "Total" : "No Data", !hasScanData, "Total anchor href values scanned by browser clients."),
            Card("riskyLinksFound", "Risky Links", riskyLinksFound, riskyLinksFound > 0 ? "Needs Review" : "Clear", !hasScanData, "Total risky links found in stored browser scans."),
            Card("suspiciousLinksFound", "Suspicious Links", suspiciousLinksFound, suspiciousLinksFound > 0 ? "Watch" : "Clear", !hasScanData, "Total suspicious/high-risk links found in stored browser scans."),
            Card("dangerousLinksFound", "Dangerous Links", dangerousLinksFound, dangerousLinksFound > 0 ? "High Attention" : "Clear", !hasScanData, "Total dangerous/critical links found in stored browser scans."),
            Card("scansLast24Hours", "Last 24 Hours", scansLast24Hours, hasScanData ? "Recent" : "No Data", !hasScanData, "Browser plugin scans received in the last 24 hours."),
            Card("scansLast7Days", "Last 7 Days", scansLast7Days, hasScanData ? "Recent" : "No Data", !hasScanData, "Browser plugin scans received in the last 7 days."),
            Card("averageHipScore", "Average HIP Score", averageHipScore, hasScanData ? "Average" : "No Data", !hasScanData, "Average HIP score across stored browser scans."),
            Card("latestScan", "Latest Scan", latestScanUtc is null ? 0 : (int)Math.Max(0, Math.Round((now - latestScanUtc.Value).TotalMinutes)), latestScanUtc is null ? "No Data" : "Minutes Ago", !hasScanData, "Minutes since the latest stored browser scan."),
            Card("clientTelemetryObservations", "Client Telemetry", clientTelemetry.Length, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Untrusted" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Stored privacy-safe client observations that do not affect authoritative HIP scores."),
            Card("clientTelemetryDomains", "Observed Domains", clientTelemetryDomains, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Untrusted" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Distinct domains observed by untrusted browser clients."),
            Card("clientTelemetryAverageScore", "Observed Client Score", clientTelemetryAverageScore, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Informational" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Average client-observed score; informational only and not authoritative trust evidence."),
            Card("clientTelemetryTrustedResults", "Observed Trusted", clientTelemetryTrustedResults, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Informational" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Client observations classified as Trusted or MostlyTrusted; not authoritative."),
            Card("clientTelemetryCautionResults", "Observed Caution", clientTelemetryCautionResults, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Informational" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Client observations classified as limited, unknown, or suspicious; not authoritative."),
            Card("clientTelemetryRiskResults", "Observed Risk", clientTelemetryRiskResults, !clientTelemetryRead.IsAvailable ? "Unavailable" : clientTelemetry.Length > 0 ? "Informational" : "No Data", !clientTelemetryRead.IsAvailable || clientTelemetry.Length == 0, "Client observations classified as HighRisk, Dangerous, or Critical; not authoritative."),
            Card("latestClientTelemetry", "Latest Client Observation", latestClientTelemetryUtc is null ? 0 : (int)Math.Max(0, Math.Round((now - latestClientTelemetryUtc.Value).TotalMinutes)), !clientTelemetryRead.IsAvailable ? "Unavailable" : latestClientTelemetryUtc is null ? "No Data" : "Minutes Ago", !clientTelemetryRead.IsAvailable || latestClientTelemetryUtc is null, "Minutes since HIP stored the latest privacy-safe client observation."),
            Card("domainCertificatesTotal", "Current Certificates", certificateTotal, domainCertificatesRead.IsAvailable ? "Persisted" : "Unavailable", !domainCertificatesRead.IsAvailable, "Current persisted HIP Domain Trust Certificates."),
            Card("domainCertificatesActive", "Active Certificates", certificateActive, domainCertificatesRead.IsAvailable ? "Active" : "Unavailable", !domainCertificatesRead.IsAvailable, "Signed certificates that are active and not expired."),
            Card("domainCertificatesSuspended", "Suspended Certificates", certificateSuspended, domainCertificatesRead.IsAvailable ? "Lifecycle" : "Unavailable", !domainCertificatesRead.IsAvailable, "Current certificates suspended through the audited lifecycle."),
            Card("domainCertificatesRevoked", "Revoked Certificates", certificateRevoked, domainCertificatesRead.IsAvailable ? "Lifecycle" : "Unavailable", !domainCertificatesRead.IsAvailable, "Current certificates permanently revoked through the audited lifecycle."),
            Card("domainCertificatesExpired", "Expired Certificates", certificateExpired, domainCertificatesRead.IsAvailable ? "Lifecycle" : "Unavailable", !domainCertificatesRead.IsAvailable, "Certificates whose signed expiry has passed."),
            Card("domainCertificatesRenewalRequired", "Renewal Required", certificateRenewalRequired, domainCertificatesRead.IsAvailable ? "Lifecycle" : "Unavailable", !domainCertificatesRead.IsAvailable, "Certificates marked for renewal under the current policy."),
            Card("domainCertificatesExpiringSoon", "Expiring Soon", certificateExpiringSoon, domainCertificatesRead.IsAvailable ? "Next 30 Days" : "Unavailable", !domainCertificatesRead.IsAvailable, "Active certificates expiring within 30 days."),
            Card("domainCertificatesRegistered", "Registered Level", certificateRegistered, domainCertificatesRead.IsAvailable ? "Certificate Level" : "Unavailable", !domainCertificatesRead.IsAvailable, "Certificates proving domain control without making a site-safety claim."),
            Card("domainCertificatesVerified", "Verified Level", certificateVerified, domainCertificatesRead.IsAvailable ? "Certificate Level" : "Unavailable", !domainCertificatesRead.IsAvailable, "Certificates with completed identity and baseline security verification."),
            Card("domainCertificatesMonitored", "Monitored Level", certificateMonitored, domainCertificatesRead.IsAvailable ? "Certificate Level" : "Unavailable", !domainCertificatesRead.IsAvailable, "Certificates with current continuous-monitoring evidence."),
            Card("domainCertificateEnrollmentsPending", "Pending Enrollments", certificateEnrollmentsPending, domainCertificatesRead.IsAvailable ? "Enrollment" : "Unavailable", !domainCertificatesRead.IsAvailable, "Current domain enrollments that have not received a certificate."),
            Card("registeredWebsiteIdentities", "Registered Domains", websiteIdentities.Count, !websiteIdentitiesRead.IsAvailable ? "Unavailable" : websiteIdentities.Count > 0 ? "Registered" : "No Data", !websiteIdentitiesRead.IsAvailable, "Domains registered with HIP. Registration alone does not prove domain control or site safety."),
            Card("verifiedWebsiteIdentities", "Control Verified", verifiedWebsiteIdentities, !websiteIdentitiesRead.IsAvailable ? "Unavailable" : "Domain Control", !websiteIdentitiesRead.IsAvailable, "Domains where HIP verified control. This does not certify that a site is safe or compliant."),
            Card("pendingWebsiteIdentities", "Awaiting Verification", pendingWebsiteIdentities, !websiteIdentitiesRead.IsAvailable ? "Unavailable" : pendingWebsiteIdentities > 0 ? "Action Needed" : "Clear", !websiteIdentitiesRead.IsAvailable, "Registered domains still awaiting successful control verification."),
            Card("inactiveWebsiteIdentities", "Inactive Verifications", inactiveWebsiteIdentities, !websiteIdentitiesRead.IsAvailable ? "Unavailable" : inactiveWebsiteIdentities > 0 ? "Review" : "Clear", !websiteIdentitiesRead.IsAvailable, "Suspended, revoked, or expired domain verifications."),
            Card("riskyFindings", "Risky Findings", riskyFindings, !findingsRead.IsAvailable ? "Unavailable" : riskyFindings > 0 ? "Needs Review" : "Clear", !findingsRead.IsAvailable, "Risk finding reports with HighRisk, Dangerous, or Critical status."),
            Card("openReviewItems", "Open Review Items", pendingManualReviews, reviewsRead.IsAvailable ? "Queue" : "Unavailable", !reviewsRead.IsAvailable, "Manual review items that still need attention."),
            Card("pendingReviewItems", "Pending Review Items", pendingManualReviews + pendingGeneratedReviews, reviewsRead.IsAvailable && generatedReviewsRead.IsAvailable ? "Queue" : "Unavailable", !reviewsRead.IsAvailable || !generatedReviewsRead.IsAvailable, "Manual and generated review items that still need attention."),
            Card("highSeverityReviewItems", "High-Severity Reviews", highSeverityReviews, !reviewSourcesAvailable ? "Unavailable" : highSeverityReviews > 0 ? "Attention" : "Clear", !reviewSourcesAvailable, "High or critical manual/generated review items."),
            Card("oldestOpenReviewAgeHours", "Oldest Open Review", oldestOpenReviewAgeHours, !reviewSourcesAvailable ? "Unavailable" : oldestOpenReviewAgeHours > 0 ? "Hours" : "No Open Reviews", !reviewSourcesAvailable, "Age in hours of the oldest open manual or generated review item."),
            Card("pendingAppeals", "Pending Appeals", appeals.Count(item => item.Status is AppealStatus.Submitted or AppealStatus.InReview or AppealStatus.NeedsMoreInfo), appealsRead.IsAvailable ? "Queue" : "Unavailable", !appealsRead.IsAvailable, "Appeals waiting for review or more information."),
            Card("pendingReputationOverrides", "Pending Reputation Overrides", overrides.Count(item => item.Status == OverrideRequestStatus.Pending), overridesRead.IsAvailable ? "Queue" : "Unavailable", !overridesRead.IsAvailable, "Manual reputation change requests awaiting approval."),
            Card("feedbackReceived", "Feedback Received", feedback.Count, !feedbackRead.IsAvailable ? "Unavailable" : hasFeedbackData ? "Real Data" : "No Data", !feedbackRead.IsAvailable || !hasFeedbackData, "Persisted weighted trust feedback records."),
            Card("looksSafeFeedback", "Looks Safe Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.LooksSafe), !feedbackRead.IsAvailable ? "Unavailable" : hasFeedbackData ? "Real Data" : "No Data", !feedbackRead.IsAvailable || !hasFeedbackData, "Feedback records where users reported the site looked safe."),
            Card("looksSuspiciousFeedback", "Looks Suspicious Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.LooksSuspicious), !feedbackRead.IsAvailable ? "Unavailable" : hasFeedbackData ? "Real Data" : "No Data", !feedbackRead.IsAvailable || !hasFeedbackData, "Feedback records where users reported the site looked suspicious."),
            Card("reportIssueFeedback", "Report Issue Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.ReportIssue), !feedbackRead.IsAvailable ? "Unavailable" : hasFeedbackData ? "Real Data" : "No Data", !feedbackRead.IsAvailable || !hasFeedbackData, "Feedback records where users reported an issue."),
            Card("suspiciousFeedbackSpikes", "Suspicious Feedback Spikes", suspiciousFeedbackSpikes, !feedbackRead.IsAvailable ? "Unavailable" : hasFeedbackData ? "Real Data" : "No Data", !feedbackRead.IsAvailable || !hasFeedbackData, "Domains with five or more recent suspicious or issue feedback records."),
            Card("activeRules", "Active Rules", activeTrustRules + activeAdminRules + activeBuiltInRules, ruleSourcesAvailable ? "Rules" : "Partial", !ruleSourcesAvailable, "Built-in, trust, and admin rules currently enforcing behavior."),
            Card("activeBuiltInRules", "Active Built-In Rules", activeBuiltInRules, "Rules", false, "Code-based built-in Site Safety rules."),
            Card("activeAdminRules", "Active Admin Rules", activeAdminRules, adminSiteSafetyRulesRead.IsAvailable ? "Rules" : "Unavailable", !adminSiteSafetyRulesRead.IsAvailable, "Admin-created rules currently active or enforced."),
            Card("watchModeRules", "Watch Mode Rules", watchTrustRules, rulesRead.IsAvailable ? "Rules" : "Unavailable", !rulesRead.IsAvailable, "Enabled JSON trust rules observing before enforcement."),
            Card("watchOnlyRules", "Watch-Only Rules", watchOnlyRules, adminSiteSafetyRulesRead.IsAvailable ? "Rules" : "Unavailable", !adminSiteSafetyRulesRead.IsAvailable, "Admin Site Safety rules in watch-only mode."),
            Card("simulationRules", "Simulation Rules", simulationRules, adminSiteSafetyRulesRead.IsAvailable ? "Rules" : "Unavailable", !adminSiteSafetyRulesRead.IsAvailable, "Admin Site Safety rules in simulation mode."),
            Card("disabledRules", "Disabled Rules", disabledRules, ruleSourcesAvailable ? "Rules" : "Partial", !ruleSourcesAvailable, "Disabled trust or admin Site Safety rules."),
            Card("selfHealingCandidates", "Self-Healing Candidates", candidates.Count, candidatesRead.IsAvailable ? "Candidates" : "Unavailable", !candidatesRead.IsAvailable, "Generated rule candidates available for review."),
            Card("dangerousDomains", "Dangerous Domains", dangerousDomains, !findingsRead.IsAvailable ? "Unavailable" : dangerousDomains > 0 ? "High Attention" : "Clear", !findingsRead.IsAvailable, "Unique domains with Dangerous or Critical findings."),
            Card("externalProviderErrors", "External Provider Errors", externalProviderErrors, ExternalProviderStatus(externalProviderErrors, hasExternalProviderData), !hasExternalProviderData, "Provider failures from stored scan metadata and generated external-provider review signals."),
            Card("apiHealth", "API Health", 1, "Healthy", false, "Dashboard service responded successfully.")
        };

        var recentScans = browserScans
            .OrderByDescending(scan => scan.LastCheckedUtc)
            .Take(10)
            .Select(scan => new AdminRecentScanItem(
                scan.ScanResultId,
                scan.Domain,
                scan.Status,
                scan.Score,
                MetadataInt(scan, "domainTrustScore"),
                MetadataInt(scan, "pageTrustScore"),
                MetadataInt(scan, "contentRiskScore"),
                MetadataValue(scan, "confidence", MetadataValue(scan, "confidenceLevel", "Unknown")),
                scan.RiskLevel,
                scan.LinksScanned,
                scan.RiskyLinksFound,
                scan.DangerousLinksFound,
                scan.LastCheckedUtc,
                FirstReason(scan),
                SourceLabel(scan),
                MetadataValue(scan, "pluginVersion", "Unknown")))
            .ToArray();

        var topRiskyDomains = browserScans
            .GroupBy(scan => scan.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var scans = group.ToArray();
                var latest = scans.OrderByDescending(scan => scan.LastCheckedUtc).First();
                return new AdminRiskyDomainItem(
                    group.Key,
                    scans.Sum(scan => scan.RiskyLinksFound),
                    scans.Sum(scan => scan.DangerousLinksFound),
                    (int)Math.Round(scans.Average(scan => scan.Score)),
                    latest.LastCheckedUtc,
                    FirstReason(latest));
            })
            .Where(item => item.RiskyLinksFound > 0 || item.DangerousLinksFound > 0)
            .OrderByDescending(item => item.DangerousLinksFound)
            .ThenByDescending(item => item.RiskyLinksFound)
            .ThenBy(item => item.AverageHipScore)
            .Take(10)
            .ToArray();

        var recentThreats = BuildRecentThreats(browserScans, findings, reviews, generatedReviews, feedback);

        var browserScanActivity = recentScans
            .Select(scan => new AdminRecentActivityItem(
                "Browser Scan",
                "Domain",
                scan.Domain,
                ParseRiskStatus(scan.RiskLevel),
                $"{scan.LinksScanned} links scanned; {scan.RiskyLinksFound} risky links found. {scan.ReasonSummary}",
                scan.LastCheckedUtc));

        var certificateActivity = domainCertificates
            .OrderByDescending(item => item.UpdatedAtUtc)
            .Take(5)
            .Select(item => new AdminRecentActivityItem(
                "Domain Certificate",
                "Domain",
                item.Domain,
                null,
                CertificateActivitySummary(item, now),
                item.UpdatedAtUtc));

        var recentActivity = browserScanActivity
            .Concat(certificateActivity)
            .Concat(findings
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .Take(5)
            .Select(finding => new AdminRecentActivityItem(
                "Risk Finding",
                finding.TargetType.ToString(),
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                finding.DetectedAtUtc)))
            .Concat(reviews
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Review Item",
                    item.TargetType.ToString(),
                    item.TargetId,
                    item.RiskLevel,
                    item.Summary,
                    item.UpdatedAtUtc)))
            .Concat(generatedReviews
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Generated Review Signal",
                    item.TargetType.ToString(),
                    item.Domain,
                    ParseRiskStatus(item.CurrentStatus ?? string.Empty),
                    $"{item.ReviewReason}: {item.Summary}",
                    item.UpdatedAtUtc)))
            .Concat(feedback
                .OrderByDescending(item => item.SubmittedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Weighted Feedback",
                    "Domain",
                    item.Domain,
                    null,
                    $"Feedback type {item.FeedbackType} from {item.Source}.",
                    item.SubmittedAtUtc)))
            .Concat(auditLogs
                .OrderByDescending(item => item.CreatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Audit Log",
                    item.TargetType.ToString(),
                    item.TargetId,
                    null,
                    item.Summary,
                    item.CreatedAtUtc)))
            .Concat(candidates
                .OrderByDescending(item => item.CreatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Generated Rule Candidate",
                    "Rule",
                    item.ProposedRule.RuleId,
                    null,
                    item.CreatedReason,
                    item.CreatedAtUtc)))
            .Concat(overrides
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Reputation Change",
                    item.TargetType.ToString(),
                    item.TargetId,
                    null,
                    $"Requested score change from {item.CurrentScore} to {item.RequestedScore}.",
                    item.UpdatedAtUtc)))
            .OrderByDescending(item => item.CreatedAtUtc)
            .Take(12)
            .ToArray();

        var sourceStatuses = new[]
        {
            new AdminDashboardSourceStatus("clientTelemetry", clientTelemetryRead.IsAvailable, clientTelemetry.Length),
            Source("riskFindings", findingsRead),
            Source("trustRules", rulesRead),
            Source("generatedRuleCandidates", candidatesRead),
            Source("generatedReviews", generatedReviewsRead),
            Source("weightedFeedback", feedbackRead),
            Source("adminSiteSafetyRules", adminSiteSafetyRulesRead),
            Source("manualReviews", reviewsRead),
            Source("appeals", appealsRead),
            Source("reputationOverrides", overridesRead),
            Source("auditLogs", auditLogsRead),
            Source("websiteIdentities", websiteIdentitiesRead),
            Source("domainCertificates", domainCertificatesRead)
        };

        var dataSource = hasScanData
            ? "BrowserPluginScanResults"
            : clientTelemetry.Length > 0
                ? "ClientTelemetryOnly"
                : "NoStoredScanData";
        return new AdminDashboardSummary(cards, recentActivity, "Healthy", DateTimeOffset.UtcNow, dataSource, hasScanData, topRiskyDomains, recentScans, recentThreats)
        {
            Sources = sourceStatuses
        };
    }

    private static async Task<IReadOnlyCollection<AdminDomainCertificateSummary>> ListDomainCertificatesAsync(
        IDomainCertificateAdminQuery query,
        CancellationToken cancellationToken)
    {
        const int pageSize = 100;
        const int maximumItems = 10_000;
        var items = new List<AdminDomainCertificateSummary>();
        while (items.Count < maximumItems)
        {
            var page = await query.ListForAdminAsync(items.Count, pageSize, cancellationToken).ConfigureAwait(false);
            items.AddRange(page);
            if (page.Count < pageSize)
            {
                return items;
            }
        }

        throw new InvalidOperationException("Domain certificate dashboard projection exceeded its safe read bound.");
    }

    private static DomainCertificateStatus? EffectiveCertificateStatus(
        AdminDomainCertificateSummary certificate,
        DateTimeOffset now) =>
        certificate.ExpiresAtUtc <= now && certificate.CertificateStatus == DomainCertificateStatus.Active
            ? DomainCertificateStatus.Expired
            : certificate.CertificateStatus;

    private static string CertificateActivitySummary(
        AdminDomainCertificateSummary certificate,
        DateTimeOffset now)
    {
        if (certificate.CertificateId is null)
        {
            return $"Enrollment is {certificate.EnrollmentStatus}; no certificate has been issued.";
        }

        return $"{certificate.BadgeLevel} certificate is {EffectiveCertificateStatus(certificate, now)}.";
    }
    /// <summary>
    /// Reads an optional dashboard source with a small local budget so slow legacy stores cannot block the live scan dashboard.
    /// </summary>
    /// <typeparam name="T">Type of privacy-safe dashboard item being loaded.</typeparam>
    /// <param name="read">Repository read operation.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>Loaded items, or an empty collection when the optional source is unavailable.</returns>
    private static async Task<OptionalReadResult<T>> ReadOptionalAsync<T>(
        Func<CancellationToken, Task<IReadOnlyCollection<T>>> read,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(LegacyReadBudget);

        try
        {
            return new OptionalReadResult<T>(await read(timeout.Token), true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new OptionalReadResult<T>([], false);
        }
        catch
        {
            return new OptionalReadResult<T>([], false);
        }
    }

    private static AdminDashboardSourceStatus Source<T>(string key, OptionalReadResult<T> read) =>
        new(key, read.IsAvailable, read.Items.Count);

    private sealed record OptionalReadResult<T>(IReadOnlyCollection<T> Items, bool IsAvailable);

    /// <summary>
    /// Builds the threat-only dashboard stream from real privacy-safe HIP evidence.
    /// Clean scans are intentionally excluded so admins see actionable risk, not normal browsing activity.
    /// </summary>
    /// <param name="browserScans">Stored browser plugin scan summaries.</param>
    /// <param name="findings">Privacy-safe risk finding reports.</param>
    /// <param name="reviews">Manual review queue items.</param>
    /// <param name="generatedReviews">Generated admin review signals from Site Safety, providers, rules, and feedback.</param>
    /// <param name="feedback">Weighted feedback submissions.</param>
    /// <returns>Newest-first recent threat rows.</returns>
    private static IReadOnlyCollection<AdminRecentThreatItem> BuildRecentThreats(
        IReadOnlyCollection<BrowserScanResultRecord> browserScans,
        IReadOnlyCollection<RiskFindingReport> findings,
        IReadOnlyCollection<ReviewItem> reviews,
        IReadOnlyCollection<AdminReviewQueueItem> generatedReviews,
        IReadOnlyCollection<WeightedFeedbackSubmission> feedback)
    {
        var scanThreats = browserScans
            .Where(IsThreatScan)
            .Select(ToScanThreat);

        var findingThreats = findings
            .Where(finding => IsRisky(finding.RiskLevel))
            .Select(ToFindingThreat);

        var manualReviewThreats = reviews
            .Where(IsThreatReview)
            .Select(ToManualReviewThreat);

        var generatedReviewThreats = generatedReviews
            .Where(IsThreatGeneratedReview)
            .Select(ToGeneratedReviewThreat);

        var feedbackThreats = BuildFeedbackThreats(feedback);

        return scanThreats
            .Concat(findingThreats)
            .Concat(manualReviewThreats)
            .Concat(generatedReviewThreats)
            .Concat(feedbackThreats)
            .OrderByDescending(item => item.CreatedAtUtc)
            .Take(12)
            .ToArray();
    }

    /// <summary>
    /// Determines whether a risk status should count as risky on the dashboard.
    /// </summary>
    /// <param name="status">Risk status.</param>
    /// <returns>True when the status requires review or attention.</returns>
    private static bool IsRisky(RiskStatus status) =>
        status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    /// <summary>
    /// Creates a dashboard metric card.
    /// </summary>
    /// <param name="key">Stable key.</param>
    /// <param name="label">Display label.</param>
    /// <param name="value">Integer value.</param>
    /// <param name="status">Status label.</param>
    /// <param name="isPlaceholder">Whether this is no-data placeholder output.</param>
    /// <param name="description">Privacy-safe description.</param>
    /// <returns>Dashboard card.</returns>
    private static AdminDashboardCard Card(
        string key,
        string label,
        int value,
        string status,
        bool isPlaceholder,
        string description) =>
        new(key, label, value, status, isPlaceholder, description);

    /// <summary>
    /// Selects the first public-safe reason from a stored browser scan.
    /// </summary>
    /// <param name="scan">Stored browser scan result.</param>
    /// <returns>Plain-English reason summary.</returns>
    private static string FirstReason(BrowserScanResultRecord scan) =>
        scan.Reasons.FirstOrDefault(reason => !string.IsNullOrWhiteSpace(reason))
        ?? "Browser plugin scan summary.";

    /// <summary>
    /// Reads a privacy-safe metadata value without throwing when old scan records do not contain the key.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <param name="key">Metadata key.</param>
    /// <param name="fallback">Value used when metadata is missing.</param>
    /// <returns>Stored metadata value or fallback.</returns>
    private static string MetadataValue(BrowserScanResultRecord scan, string key, string fallback) =>
        scan.PrivacySafeMetadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? SanitizeThreatSummary(value)
            : fallback;

    /// <summary>
    /// Reads an optional integer score from privacy-safe scan metadata.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <param name="key">Metadata key.</param>
    /// <returns>Parsed score, or null when unavailable.</returns>
    private static int? MetadataInt(BrowserScanResultRecord scan, string key) =>
        scan.PrivacySafeMetadata.TryGetValue(key, out var value) && int.TryParse(value, out var parsed)
            ? Math.Clamp(parsed, 0, 100)
            : null;

    /// <summary>
    /// Builds a source label that identifies where the stored scan came from without exposing raw URLs.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>Dashboard-safe source label.</returns>
    private static string SourceLabel(BrowserScanResultRecord scan)
    {
        var metadataSource = MetadataValue(scan, "source", string.Empty);
        return string.IsNullOrWhiteSpace(metadataSource) ? scan.ScanSource : metadataSource;
    }

    /// <summary>
    /// Parses stored risk text for recent activity display.
    /// </summary>
    /// <param name="riskLevel">Stored risk level text.</param>
    /// <returns>Risk status or null when the text is not recognized.</returns>
    private static RiskStatus? ParseRiskStatus(string riskLevel) =>
        Enum.TryParse<RiskStatus>(riskLevel, ignoreCase: true, out var status) ? status : null;

    /// <summary>
    /// Counts domains with enough suspicious feedback volume to warrant dashboard attention.
    /// This uses only privacy-safe domain and feedback-type fields, never page text or reporter identity.
    /// </summary>
    /// <param name="feedback">Stored weighted feedback submissions.</param>
    /// <returns>Number of domains with suspicious feedback spikes.</returns>
    private static int CountSuspiciousFeedbackSpikes(IReadOnlyCollection<WeightedFeedbackSubmission> feedback) =>
        feedback
            .Where(item => item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue)
            .GroupBy(item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Count(group => group.Count() >= 5);

    /// <summary>
    /// Counts external provider failures from privacy-safe dashboard sources.
    /// Provider errors may arrive as scan metadata from the browser/API path or as generated review signals;
    /// the dashboard never calls external providers itself and never inspects provider raw response bodies.
    /// </summary>
    /// <param name="browserScans">Stored browser scan summaries.</param>
    /// <param name="generatedReviews">Generated admin review signals.</param>
    /// <returns>Number of known external provider errors.</returns>
    private static int CountExternalProviderErrors(
        IReadOnlyCollection<BrowserScanResultRecord> browserScans,
        IReadOnlyCollection<AdminReviewQueueItem> generatedReviews)
    {
        var metadataErrors = browserScans.Sum(scan => ProviderErrorCount(scan.PrivacySafeMetadata));
        var reviewErrors = generatedReviews.Count(IsExternalProviderErrorReview);
        return metadataErrors + reviewErrors;
    }

    /// <summary>
    /// Determines whether a generated review item represents an external provider failure rather than a provider threat hit.
    /// Threat hits are shown in Recent Threats, while failures are counted as provider errors.
    /// </summary>
    /// <param name="item">Generated admin review item.</param>
    /// <returns>True when the review represents an external provider error.</returns>
    private static bool IsExternalProviderErrorReview(AdminReviewQueueItem item) =>
        item.Source == AdminReviewSource.ExternalProvider &&
        (ContainsProviderErrorText(item.ReviewReason) ||
         ContainsProviderErrorText(item.Summary) ||
         ContainsProviderErrorText(item.EvidenceSummary));

    /// <summary>
    /// Detects whether stored scan metadata includes any external provider summary fields.
    /// The dashboard treats this as evidence that provider data is connected, even when the count is zero.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when the scan contains provider metadata.</returns>
    private static bool HasExternalProviderMetadata(BrowserScanResultRecord scan) =>
        scan.PrivacySafeMetadata.Keys.Any(key => key.Contains("provider", StringComparison.OrdinalIgnoreCase) ||
                                                 key.Contains("sslLabs", StringComparison.OrdinalIgnoreCase) ||
                                                 key.Contains("virusTotal", StringComparison.OrdinalIgnoreCase) ||
                                                 key.Contains("webRisk", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Reads known provider-error count metadata keys while ignoring malformed values.
    /// This keeps bad or old plugin metadata from breaking the admin dashboard.
    /// </summary>
    /// <param name="metadata">Privacy-safe scan metadata.</param>
    /// <returns>Provider error count from the metadata.</returns>
    private static int ProviderErrorCount(IReadOnlyDictionary<string, string> metadata)
    {
        var total = 0;
        foreach (var key in new[] { "externalProviderErrors", "providerErrors", "providerErrorCount", "siteSafetyProviderErrors" })
        {
            if (metadata.TryGetValue(key, out var value) && int.TryParse(value, out var parsed) && parsed > 0)
            {
                total += parsed;
            }
        }

        return total;
    }

    /// <summary>
    /// Detects safe, generic provider failure words. This intentionally does not parse raw provider payloads.
    /// </summary>
    /// <param name="value">Review reason or summary text.</param>
    /// <returns>True when the text identifies timeout/error/failure evidence.</returns>
    private static bool ContainsProviderErrorText(string value) =>
        value.Contains("error", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("timeout", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds the provider-error card status from real evidence availability.
    /// </summary>
    /// <param name="errorCount">Known provider error count.</param>
    /// <param name="hasExternalProviderData">Whether any provider data has reached dashboard storage.</param>
    /// <returns>Short card status.</returns>
    private static string ExternalProviderStatus(int errorCount, bool hasExternalProviderData)
    {
        if (!hasExternalProviderData)
        {
            return "Not connected yet";
        }

        return errorCount > 0 ? "Errors" : "Connected";
    }

    /// <summary>
    /// Determines whether a stored browser scan represents a recent threat rather than a normal clean page.
    /// This uses conservative status and count signals only; it never inspects page text or form values.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when the scan should appear in Recent Threats.</returns>
    private static bool IsThreatScan(BrowserScanResultRecord scan)
    {
        if (IsDangerousScan(scan) || IsHighRiskScan(scan))
        {
            return true;
        }

        if (IsSuspiciousScan(scan) && (scan.RiskyLinksFound > 0 || scan.SuspiciousLinksFound > 0 || HasStrongWarning(scan)))
        {
            return true;
        }

        return IsTrustedOrMostlyTrusted(scan) && (scan.RiskyLinksFound > 0 || scan.DangerousLinksFound > 0 || HasStrongWarning(scan));
    }

    /// <summary>
    /// Converts a stored browser scan into a privacy-safe threat row.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>Recent threat item.</returns>
    private static AdminRecentThreatItem ToScanThreat(BrowserScanResultRecord scan) =>
        new(
            $"scan-threat:{scan.ScanResultId}",
            scan.Domain,
            scan.PageUrlHash,
            "Scan",
            scan.Status,
            scan.RiskLevel,
            scan.Score,
            ScanSeverity(scan),
            scan.PrivacySafeMetadata.GetValueOrDefault("confidenceLevel", "Medium"),
            SanitizeThreatSummary(ScanThreatReason(scan)),
            scan.DangerousLinksFound > 0
                ? $"{scan.DangerousLinksFound} dangerous link(s) found."
                : scan.RiskyLinksFound > 0 ? $"{scan.RiskyLinksFound} risky link(s) found." : null,
            scan.ScanSource,
            scan.ScanResultId,
            null,
            null,
            scan.LastCheckedUtc);

    /// <summary>
    /// Converts a privacy-safe risk finding into a threat row.
    /// </summary>
    /// <param name="finding">Risk finding report.</param>
    /// <returns>Recent threat item.</returns>
    private static AdminRecentThreatItem ToFindingThreat(RiskFindingReport finding) =>
        new(
            $"finding-threat:{finding.ReportId}",
            finding.Domain,
            finding.UrlHash,
            finding.TargetType.ToString(),
            finding.RiskLevel.ToString(),
            finding.RiskLevel.ToString(),
            null,
            finding.RiskLevel.ToString(),
            finding.ReporterTrustLevel.ToString(),
            SanitizeThreatSummary(finding.Reason),
            SanitizeThreatSummary(finding.PrivacySafeEvidence.Summary),
            finding.SourceClient.ToString(),
            null,
            null,
            null,
            finding.DetectedAtUtc);

    /// <summary>
    /// Determines whether a manual review item belongs in the threat-only stream.
    /// </summary>
    /// <param name="item">Manual review item.</param>
    /// <returns>True when the item is open or high-impact enough for Recent Threats.</returns>
    private static bool IsThreatReview(ReviewItem item) =>
        item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo ||
        item.RiskLevel is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical ||
        item.Priority is ReviewPriority.High or ReviewPriority.Critical;

    /// <summary>
    /// Converts a manual review item into a privacy-safe threat row.
    /// </summary>
    /// <param name="item">Manual review item.</param>
    /// <returns>Recent threat item.</returns>
    private static AdminRecentThreatItem ToManualReviewThreat(ReviewItem item) =>
        new(
            $"review-threat:{item.ReviewItemId}",
            item.TargetType is TargetType.Domain or TargetType.Website or TargetType.Url ? item.TargetId : item.TargetId,
            null,
            item.TargetType.ToString(),
            item.Status.ToString(),
            item.RiskLevel.ToString(),
            null,
            item.Priority.ToString(),
            "ManualReview",
            SanitizeThreatSummary(item.Summary),
            SanitizeThreatSummary(item.EvidenceSummary),
            item.Source,
            null,
            item.ReviewItemId,
            null,
            item.UpdatedAtUtc);

    /// <summary>
    /// Determines whether a generated review signal is threat evidence rather than low-priority bookkeeping.
    /// </summary>
    /// <param name="item">Generated admin review item.</param>
    /// <returns>True when the generated review should appear in Recent Threats.</returns>
    private static bool IsThreatGeneratedReview(AdminReviewQueueItem item) =>
        item.Severity is AdminReviewSeverity.High or AdminReviewSeverity.Critical ||
        item.Source is AdminReviewSource.ExternalProvider or AdminReviewSource.UserFeedback ||
        StatusLooksThreatening(item.CurrentStatus) ||
        item.ReviewReason.Contains("login", StringComparison.OrdinalIgnoreCase) ||
        item.ReviewReason.Contains("provider", StringComparison.OrdinalIgnoreCase) ||
        item.ReviewReason.Contains("redirect", StringComparison.OrdinalIgnoreCase) ||
        item.ReviewReason.Contains("download", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Converts generated admin review evidence into a dashboard threat row.
    /// </summary>
    /// <param name="item">Generated review item.</param>
    /// <returns>Recent threat item.</returns>
    private static AdminRecentThreatItem ToGeneratedReviewThreat(AdminReviewQueueItem item) =>
        new(
            $"generated-review-threat:{item.ReviewId}",
            item.Domain,
            item.UrlHash,
            item.TargetType.ToString(),
            item.Status.ToString(),
            item.CurrentStatus ?? "ReviewSignal",
            item.CurrentFinalHipScore,
            item.Severity.ToString(),
            item.ConfidenceLevel ?? "Medium",
            SanitizeThreatSummary(item.Summary),
            SanitizeThreatSummary(item.EvidenceSummary),
            item.Source.ToString(),
            item.RelatedScanId,
            item.ReviewId,
            item.RelatedRuleId,
            item.UpdatedAtUtc);

    /// <summary>
    /// Builds repeated suspicious feedback threats. Feedback is treated as weak evidence and never as raw voting.
    /// </summary>
    /// <param name="feedback">Weighted feedback submissions.</param>
    /// <returns>Repeated feedback threat rows.</returns>
    private static IReadOnlyCollection<AdminRecentThreatItem> BuildFeedbackThreats(IReadOnlyCollection<WeightedFeedbackSubmission> feedback) =>
        feedback
            .Where(item => item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue)
            .GroupBy(item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() >= 5)
            .Select(group =>
            {
                var latest = group.OrderByDescending(item => item.SubmittedAtUtc).First();
                return new AdminRecentThreatItem(
                    $"feedback-threat:{group.Key}",
                    group.Key,
                    latest.PageUrlHash,
                    "Feedback",
                    "NeedsReview",
                    "FeedbackSignal",
                    null,
                    group.Count() >= 10 ? "High" : "Medium",
                    "Low",
                    "Repeated suspicious feedback was submitted for this domain. HIP treats feedback as supporting evidence, not proof.",
                    $"{group.Count()} suspicious feedback item(s) in the current dashboard data.",
                    latest.Source.ToString(),
                    null,
                    null,
                    null,
                    latest.SubmittedAtUtc);
            })
            .ToArray();

    /// <summary>
    /// Maps a stored scan to a dashboard severity label.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <returns>Severity label.</returns>
    private static string ScanSeverity(BrowserScanResultRecord scan)
    {
        if (IsDangerousScan(scan) || scan.DangerousLinksFound > 0)
        {
            return "Critical";
        }

        if (IsHighRiskScan(scan))
        {
            return "High";
        }

        return "Medium";
    }

    /// <summary>
    /// Builds a short reason for a scan threat without exposing the raw URL or page content.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <returns>Plain-English threat reason.</returns>
    private static string ScanThreatReason(BrowserScanResultRecord scan)
    {
        if (IsTrustedOrMostlyTrusted(scan) && (scan.RiskyLinksFound > 0 || scan.DangerousLinksFound > 0))
        {
            return "The parent domain has stronger trust, but this page or its links showed risky signals.";
        }

        if (scan.DangerousLinksFound > 0)
        {
            return "The latest browser scan found dangerous link signals on this page.";
        }

        if (scan.RiskyLinksFound > 0 || scan.SuspiciousLinksFound > 0)
        {
            return "The latest browser scan found suspicious link signals on this page.";
        }

        return FirstReason(scan);
    }

    /// <summary>
    /// Detects warning-style scan summaries using only public-safe reason text and action labels.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <returns>True when the scan contains a strong warning signal.</returns>
    private static bool HasStrongWarning(BrowserScanResultRecord scan) =>
        scan.RecommendedAction.Contains("Safety", StringComparison.OrdinalIgnoreCase) ||
        scan.RecommendedAction.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
        scan.Reasons.Any(reason =>
            reason.Contains("warning", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("download", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("redirect", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Determines whether a scan status indicates a trusted parent context where page/content risk still matters.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <returns>True when the scan label is trusted or mostly trusted.</returns>
    private static bool IsTrustedOrMostlyTrusted(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Trusted", "MostlyTrusted", "ProbablySafe");

    /// <summary>
    /// Checks nullable status text for high-risk labels.
    /// </summary>
    /// <param name="status">Status label.</param>
    /// <returns>True when the status is threatening.</returns>
    private static bool StatusLooksThreatening(string? status) =>
        !string.IsNullOrWhiteSpace(status) &&
        (status.Contains("Suspicious", StringComparison.OrdinalIgnoreCase) ||
         status.Contains("HighRisk", StringComparison.OrdinalIgnoreCase) ||
         status.Contains("Dangerous", StringComparison.OrdinalIgnoreCase) ||
         status.Contains("Critical", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Redacts obvious private-content markers from dashboard threat summaries.
    /// Upstream validators should block these already; this is a defensive UI/API boundary.
    /// </summary>
    /// <param name="summary">Summary text.</param>
    /// <returns>Safe summary text.</returns>
    private static string SanitizeThreatSummary(string summary) =>
        summary.Contains("page text", StringComparison.OrdinalIgnoreCase) ||
        summary.Contains("form value", StringComparison.OrdinalIgnoreCase) ||
        summary.Contains("password", StringComparison.OrdinalIgnoreCase) ||
        summary.Contains("token=", StringComparison.OrdinalIgnoreCase) ||
        summary.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
        summary.Contains("private message", StringComparison.OrdinalIgnoreCase)
            ? "[privacy-safe threat summary redacted]"
            : summary;

    /// <summary>
    /// Determines whether a stored scan is Trusted.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label is Trusted.</returns>
    private static bool IsTrustedScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Trusted");

    /// <summary>
    /// Determines whether a stored scan is mostly trusted.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates mostly trusted/probably safe.</returns>
    private static bool IsMostlyTrustedScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "MostlyTrusted", "ProbablySafe");

    /// <summary>
    /// Determines whether a stored scan has limited trust data.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates limited trust data.</returns>
    private static bool IsLimitedTrustScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "LimitedTrustData", "LimitedData");

    /// <summary>
    /// Determines whether a stored scan is unknown.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label is Unknown.</returns>
    private static bool IsUnknownScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Unknown");

    /// <summary>
    /// Determines whether a stored scan is suspicious or cautionary.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates suspicious/caution risk.</returns>
    private static bool IsSuspiciousScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Suspicious", "Caution");

    /// <summary>
    /// Determines whether a stored scan is high risk.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates high risk.</returns>
    private static bool IsHighRiskScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "HighRisk", "High Risk");

    /// <summary>
    /// Determines whether a stored scan is dangerous or critical.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates dangerous/critical risk.</returns>
    private static bool IsDangerousScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Dangerous", "Critical");

    /// <summary>
    /// Compares both stored status labels so older plugin payloads and newer layered labels remain compatible.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <param name="expectedLabels">Accepted status labels.</param>
    /// <returns>True when the stored status or risk label matches one of the accepted labels.</returns>
    private static bool MatchesScanStatus(BrowserScanResultRecord scan, params string[] expectedLabels)
    {
        var normalizedExpected = expectedLabels.Select(NormalizeStatusLabel).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return normalizedExpected.Contains(NormalizeStatusLabel(scan.Status)) ||
               normalizedExpected.Contains(NormalizeStatusLabel(scan.RiskLevel));
    }

    /// <summary>
    /// Normalizes dashboard status labels by ignoring whitespace and hyphens.
    /// </summary>
    /// <param name="value">Status label.</param>
    /// <returns>Comparable status label.</returns>
    private static string NormalizeStatusLabel(string value) =>
        value.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();
}
