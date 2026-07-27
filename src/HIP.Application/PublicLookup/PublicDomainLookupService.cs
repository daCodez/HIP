using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.Identity;
using HIP.Domain.Risk;
using HIP.Domain.Scoring;
using HIP.Application.Explanations;
using HIP.Domain.Identity;
using HIP.Domain.Certificates;
using Microsoft.Extensions.Logging;

namespace HIP.Application.PublicLookup;

/// <summary>
/// Builds public-safe HIP domain lookup results from stored scan data, falling back to a clear no-data state.
/// </summary>
/// <param name="browserScanResultRepository">Repository containing privacy-safe browser plugin scan summaries.</param>
/// <param name="logger">Optional logger used to record storage availability problems without exposing private scan data.</param>
public sealed class PublicDomainLookupService(
    IBrowserScanResultRepository browserScanResultRepository,
    ILogger<PublicDomainLookupService>? logger = null,
    ITrustExplanationAssistant? explanationAssistant = null,
    IWebsiteIdentityRepository? websiteIdentityRepository = null,
    IDomainCertificateAdminQuery? certificateAdminQuery = null) : IPublicDomainLookupService
{
    private static readonly HashSet<string> StrongDomainTrust = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "microsoft.com"
    };

    private static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
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
    /// Looks up a domain using stored browser scan data when available and avoids exposing private scan payloads.
    /// </summary>
    /// <param name="domain">Domain requested by the public lookup API or page.</param>
    /// <param name="cancellationToken">Token used to cancel persistence reads.</param>
    /// <returns>Public-safe lookup result.</returns>
    public async Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var websiteIdentity = await GetWebsiteIdentitySafelyAsync(normalized, cancellationToken);
        var certificateProgress = await GetCertificateProgressSafelyAsync(normalized, cancellationToken);
        var storedScan = await GetLatestStoredScanSafelyAsync(normalized, cancellationToken);
        var response = storedScan is null
            ? BuildNoStoredDataResponse(normalized, websiteIdentity)
            : BuildStoredScanResponse(normalized, storedScan, websiteIdentity);
        response = ApplyCertificateProgress(response, certificateProgress);
        if (storedScan is null || explanationAssistant is null)
        {
            return response;
        }

        var assistance = await explanationAssistant.TryExplainAsync(
            new TrustExplanationRequest(
                response.FinalHipScore,
                response.DomainTrustScore,
                response.PageTrustScore,
                response.ContentRiskScore,
                response.Status,
                BuildExplanationSignalCodes(response)),
            cancellationToken);
        return assistance is null
            ? response
            : response with { AssistedExplanation = assistance.Explanation, ExplanationSource = assistance.ProviderName };
    }

    /// <summary>
    /// Reads the registered website identity without allowing identity-storage outages to break public lookup.
    /// </summary>
    private async Task<WebsiteIdentity?> GetWebsiteIdentitySafelyAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        if (websiteIdentityRepository is null)
        {
            return null;
        }

        try
        {
            return await websiteIdentityRepository.GetAsync(normalizedDomain, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageAvailabilityFailure(exception))
        {
            logger?.LogWarning(
                exception,
                "HIP public lookup identity read failed for domain {Domain}. Continuing without identity state.",
                normalizedDomain);
            return null;
        }
    }

    /// <summary>Reads only public-safe certificate progress and degrades cleanly when storage is unavailable.</summary>
    private async Task<PublicDomainCertificateProgress?> GetCertificateProgressSafelyAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        if (certificateAdminQuery is null)
        {
            return null;
        }

        try
        {
            return await certificateAdminQuery.GetPublicProgressAsync(normalizedDomain, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageAvailabilityFailure(exception))
        {
            logger?.LogWarning(
                exception,
                "HIP public certificate progress read failed for domain {Domain}.",
                normalizedDomain);
            return null;
        }
    }

    /// <summary>Maps persisted lifecycle state to bounded public wording without review details.</summary>
    private static PublicDomainLookupResponse ApplyCertificateProgress(
        PublicDomainLookupResponse response,
        PublicDomainCertificateProgress? progress)
    {
        if (progress is null)
        {
            return response;
        }

        var label = progress.CertificateStatus switch
        {
            DomainCertificateStatus.Active => "Certificate active",
            DomainCertificateStatus.Suspended => "Certificate suspended",
            DomainCertificateStatus.Revoked => "Certificate revoked",
            DomainCertificateStatus.Expired => "Certificate expired",
            DomainCertificateStatus.RenewalRequired => "Certificate renewal required",
            DomainCertificateStatus.PendingReview => "Certificate review pending",
            _ => ApplicationProgressLabel(progress)
        };
        var monitoringStatus = progress.MonitoringEnabledAtUtc is null
            ? "Not enabled"
            : progress.MonitoringFailureCount > 0
                ? "Retry scheduled"
                : progress.LastMonitoringAtUtc is null
                    ? "Starting"
                    : "Active";
        var hasCurrentAuthenticatedMonitoringEvidence =
            monitoringStatus == "Active" &&
            string.Equals(response.ScorePresentation, PublicEvidencePresentation.ScoreAvailable, StringComparison.Ordinal) &&
            progress.LastMonitoringAtUtc >= response.LastCheckedUtc.AddMinutes(-5);

        return response with
        {
            CertificateApplicationStatus = progress.ApplicationStatus.ToString(),
            CertificateProgressStatus = label,
            MonitoringStatus = monitoringStatus,
            EvidenceConfidence = hasCurrentAuthenticatedMonitoringEvidence
                ? PublicEvidencePresentation.ConfidenceHigh
                : response.EvidenceConfidence
        };
    }

    private static string ApplicationProgressLabel(PublicDomainCertificateProgress progress) =>
        progress.ApplicationStatus switch
        {
            DomainCertificateApplicationStatus.Submitted => "Application submitted - awaiting HIP review",
            DomainCertificateApplicationStatus.ChangesRequested => "Application changes requested",
            DomainCertificateApplicationStatus.Denied => "Application denied",
            DomainCertificateApplicationStatus.Approved
                when progress.EnrollmentStatus == DomainEnrollmentStatus.Verified =>
                "Security review passed - certificate issuance pending",
            DomainCertificateApplicationStatus.Approved
                when progress.SecurityReviewCompletedAtUtc is not null &&
                     progress.UnresolvedCriticalFindings > 0 =>
                "Security review found requirements to address",
            DomainCertificateApplicationStatus.Approved
                when progress.SecurityReviewCompletedAtUtc is not null =>
                "Security review needs HIP review",
            DomainCertificateApplicationStatus.Approved =>
                "Application approved - security review pending",
            _ => "Certificate application not submitted"
        };
    private static IReadOnlyCollection<string> BuildExplanationSignalCodes(PublicDomainLookupResponse response)
    {
        var codes = new List<string> { $"status-{response.Status.ToString().ToLowerInvariant()}" };
        if (response.PublicBadgeEligible) codes.Add("identity-verified");
        if (response.RiskyLinksFound > 0) codes.Add("risky-links");
        if (response.SuspiciousLinksFound > 0) codes.Add("suspicious-links");
        if (response.DangerousLinksFound > 0) codes.Add("dangerous-links");
        return codes;
    }

    /// <summary>
    /// Reads the latest stored scan result while treating database connectivity failures as a no-data state.
    /// </summary>
    /// <param name="normalizedDomain">Already validated and normalized domain name.</param>
    /// <param name="cancellationToken">Token used to cancel the lookup when the caller disconnects.</param>
    /// <returns>The latest stored scan result, or null when storage is unavailable or no scan exists.</returns>
    /// <remarks>
    /// This method intentionally does not log URLs, URL hashes, page text, form values, tokens, or user identity.
    /// A PostgreSQL timeout should not make public lookup or the browser popup fail open or crash; HIP degrades to
    /// limited trust data until persistence recovers.
    /// </remarks>
    private async Task<BrowserScanResultRecord?> GetLatestStoredScanSafelyAsync(string normalizedDomain, CancellationToken cancellationToken)
    {
        try
        {
            return await browserScanResultRepository.GetLatestAuthoritativeByDomainAsync(normalizedDomain, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageAvailabilityFailure(exception))
        {
            logger?.LogWarning(
                exception,
                "HIP public lookup storage read failed for domain {Domain}. Returning a limited-trust no-data response.",
                normalizedDomain);
            return null;
        }
    }

    /// <summary>
    /// Determines whether an exception represents storage unavailability rather than invalid input or a coding error.
    /// </summary>
    /// <param name="exception">Exception raised while reading scan storage.</param>
    /// <returns>True when HIP should degrade to a no-data lookup response.</returns>
    private static bool IsStorageAvailabilityFailure(Exception exception) =>
        exception is TimeoutException
            or TaskCanceledException
            or System.Data.Common.DbException;

    /// <summary>
    /// Converts a stored browser plugin scan result into the public lookup shape without exposing page URL hashes or user identity.
    /// </summary>
    /// <param name="normalized">Normalized domain.</param>
    /// <param name="storedScan">Stored privacy-safe browser scan result.</param>
    /// <returns>Public lookup response sourced from the browser plugin scan.</returns>
    private static PublicDomainLookupResponse BuildStoredScanResponse(
        string normalized,
        BrowserScanResultRecord storedScan,
        WebsiteIdentity? websiteIdentity)
    {
        var layeredScore = BuildLayeredScore(normalized, storedScan);
        var status = StatusForScore(layeredScore.FinalHipScore);
        var identity = ProjectIdentity(websiteIdentity);
        var scanReasons = storedScan.Reasons.Count > 0
            ? storedScan.Reasons
            : ["Last browser scan completed without sending page text, form values, or private messages."];
        var reasons = identity.Reason is null
            ? scanReasons
            : scanReasons.Prepend(identity.Reason).ToArray();
        var knownRisks = status is RiskStatus.Suspicious or RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical
            ? scanReasons
            : [];

        return new PublicDomainLookupResponse(
            normalized,
            layeredScore.FinalHipScore,
            layeredScore.FinalHipScore,
            status,
            status.ToString(),
            identity.VerificationStatus,
            knownRisks,
            reasons,
            reasons.Append(layeredScore.Explanation).Append("This lookup is based on the latest privacy-safe browser plugin scan summary.").ToArray(),
            RecommendedActionFor(status),
            storedScan.LastCheckedUtc,
            identity.SignedIdentityStatus,
            identity.VerificationMethod,
            null,
            identity.SignatureStatus,
            identity.VerificationStatus,
            identity.SignatureValid,
            identity.PublicBadgeEligible,
            $"/lookup/{normalized}",
            layeredScore.DomainTrustScore,
            layeredScore.PageTrustScore,
            layeredScore.ContentRiskScore,
            layeredScore.Explanation,
            BuildStoredScanBreakdown(storedScan, layeredScore),
            storedScan.LinksScanned,
            storedScan.RiskyLinksFound,
            storedScan.SuspiciousLinksFound,
            storedScan.DangerousLinksFound,
            "BrowserPluginScan",
            "HIP is showing the latest privacy-safe browser plugin scan for this domain.")
        {
            DisplayScore = layeredScore.FinalHipScore,
            ScorePresentation = PublicEvidencePresentation.ScoreAvailable,
            EvidenceCoverage = PublicEvidencePresentation.CoverageSufficient,
            EvidenceConfidence = PublicEvidencePresentation.ConfidenceMedium
        };
    }

    /// <summary>
    /// Builds the explicit no-data state used when HIP has not yet stored a scan for the domain.
    /// </summary>
    /// <param name="normalized">Normalized domain.</param>
    /// <returns>Public lookup response with Unknown status and no private data.</returns>
    private static PublicDomainLookupResponse BuildNoStoredDataResponse(
        string normalized,
        WebsiteIdentity? websiteIdentity)
    {
        if (IsDangerousTestDomain(normalized))
        {
            return BuildDangerousNoStoredDataResponse(normalized, websiteIdentity);
        }

        var identity = ProjectIdentity(websiteIdentity);
        var message = "HIP has no authoritative site-safety assessment for this domain yet.";
        var reasons = identity.Reason is null
            ? new[] { message, "No private reports, user identities, page URLs, or browsing history are exposed in public lookup." }
            : new[] { identity.Reason, message, "No private reports, user identities, page URLs, or browsing history are exposed in public lookup." };
        return new PublicDomainLookupResponse(
            normalized,
            56,
            56,
            RiskStatus.LimitedTrustData,
            RiskStatus.LimitedTrustData.ToString(),
            identity.VerificationStatus,
            [],
            reasons,
            reasons,
            "ShowCaution",
            websiteIdentity?.LastCheckedAtUtc ?? websiteIdentity?.VerifiedAtUtc ?? DateTimeOffset.UtcNow,
            identity.SignedIdentityStatus,
            identity.VerificationMethod,
            null,
            identity.SignatureStatus,
            identity.VerificationStatus,
            identity.SignatureValid,
            identity.PublicBadgeEligible,
            $"/lookup/{normalized}",
            50,
            55,
            65,
            "HIP did not find strong trust signals for this website yet. No major risk signals were found, but the site has not earned a high trust score.",
            [
                new ScoreBreakdownItem("DomainTrustScore", 50, RiskStatus.LimitedTrustData, "HIP has limited root-domain trust data for this domain.", [message]),
                new ScoreBreakdownItem("PageTrustScore", 55, RiskStatus.LimitedTrustData, "HIP has not scanned a specific page for this domain yet.", [message]),
                new ScoreBreakdownItem("ContentRiskScore", 65, RiskStatus.LimitedTrustData, "No content risk signals are available yet, so this is not treated as trusted.", [message]),
                new ScoreBreakdownItem("FinalHipScore", 56, RiskStatus.LimitedTrustData, "Final score is capped by limited trust data.", [message])
            ],
            null,
            null,
            null,
            null,
            identity.PublicBadgeEligible ? "VerifiedIdentityOnly" : "NoStoredData",
            message);
    }

    /// <summary>
    /// Builds a dangerous no-data response for explicit test-domain patterns used by the MVP and tests.
    /// </summary>
    /// <param name="normalized">Normalized domain.</param>
    /// <returns>Public lookup response with dangerous test-domain status.</returns>
    private static PublicDomainLookupResponse BuildDangerousNoStoredDataResponse(
        string normalized,
        WebsiteIdentity? websiteIdentity)
    {
        var identity = ProjectIdentity(websiteIdentity);
        const string message = "Known suspicious test-domain pattern detected.";
        return new PublicDomainLookupResponse(
            normalized,
            8,
            8,
            RiskStatus.Dangerous,
            RiskStatus.Dangerous.ToString(),
            identity.VerificationStatus,
            [message],
            [message],
            ["HIP classified this domain as dangerous using public-safe MVP test-domain rules."],
            "RouteToSafetyPage",
            DateTimeOffset.UtcNow,
            identity.SignedIdentityStatus,
            identity.VerificationMethod,
            null,
            identity.SignatureStatus,
            identity.VerificationStatus,
            identity.SignatureValid,
            identity.PublicBadgeEligible,
            $"/lookup/{normalized}",
            20,
            10,
            5,
            "The domain matches a known dangerous MVP test pattern. Final HIP score is 8/100 after separate domain, page, and content scores.",
            [
                new ScoreBreakdownItem("DomainTrustScore", 20, RiskStatus.HighRisk, "Domain matches a known suspicious test pattern.", [message]),
                new ScoreBreakdownItem("PageTrustScore", 10, RiskStatus.HighRisk, "No safe page-specific signal is available for this test domain.", [message]),
                new ScoreBreakdownItem("ContentRiskScore", 5, RiskStatus.Dangerous, "Content is treated as dangerous for this test-domain pattern.", [message]),
                new ScoreBreakdownItem("FinalHipScore", 8, RiskStatus.Dangerous, "Final score reflects dangerous test-domain classification.", [message])
            ],
            null,
            null,
            null,
            null,
            "MvpDangerousTestPattern",
            message)
        {
            DisplayScore = 8,
            ScorePresentation = PublicEvidencePresentation.ScoreAvailable,
            EvidenceCoverage = PublicEvidencePresentation.CoverageSufficient,
            EvidenceConfidence = PublicEvidencePresentation.ConfidenceHigh
        };
    }

    /// <summary>
    /// Projects durable domain-control state without treating verification as organization vetting or site safety.
    /// </summary>
    private static PublicIdentityProjection ProjectIdentity(WebsiteIdentity? identity)
    {
        if (identity is null)
        {
            return PublicIdentityProjection.Unverified;
        }

        if (identity.VerificationStatus != VerificationStatus.Verified)
        {
            return new PublicIdentityProjection(
                identity.VerificationStatus.ToString(),
                "NotConfigured",
                identity.PreferredVerificationMethod.ToString(),
                "NotConfigured",
                null,
                false,
                null);
        }

        var signedWellKnown = identity.PreferredVerificationMethod == VerificationMethod.WellKnownHipJson;
        var methodLabel = signedWellKnown ? "signed .well-known/hip.json" : "DNS TXT";
        return new PublicIdentityProjection(
            "Verified",
            signedWellKnown ? "Verified" : "NotConfigured",
            identity.PreferredVerificationMethod.ToString(),
            signedWellKnown ? "Verified" : "NotConfigured",
            signedWellKnown ? true : null,
            true,
            $"HIP verified control of this domain using {methodLabel}. Domain control does not prove the site is safe.");
    }

    private sealed record PublicIdentityProjection(
        string VerificationStatus,
        string SignedIdentityStatus,
        string VerificationMethod,
        string SignatureStatus,
        bool? SignatureValid,
        bool PublicBadgeEligible,
        string? Reason)
    {
        public static PublicIdentityProjection Unverified { get; } =
            new("Unverified", "NotConfigured", "NotConfigured", "NotConfigured", null, false, null);
    }

    /// <summary>
    /// Builds a lightweight score breakdown from stored browser scan counts.
    /// </summary>
    /// <param name="storedScan">Stored privacy-safe browser scan result.</param>
    /// <param name="status">Mapped public risk status.</param>
    /// <returns>Public-safe score breakdown items.</returns>
    private static IReadOnlyCollection<ScoreBreakdownItem> BuildStoredScanBreakdown(BrowserScanResultRecord storedScan, LayeredLookupScore layeredScore) =>
    [
        new ScoreBreakdownItem(
            "DomainTrustScore",
            layeredScore.DomainTrustScore,
            StatusForScore(layeredScore.DomainTrustScore),
            "DomainTrustScore measures root-domain trust and does not automatically make every page safe.",
            ["Domain trust is evaluated separately from page and content risk."]),
        new ScoreBreakdownItem(
            "PageTrustScore",
            layeredScore.PageTrustScore,
            StatusForScore(layeredScore.PageTrustScore),
            "PageTrustScore measures the exact page or URL context from the latest browser plugin scan.",
            storedScan.Reasons),
        new ScoreBreakdownItem(
            "ContentRiskScore",
            layeredScore.ContentRiskScore,
            StatusForScore(layeredScore.ContentRiskScore),
            $"ContentRiskScore reflects download, link, and page-behavior risk from {storedScan.LinksScanned} scanned links.",
            [$"{storedScan.SuspiciousLinksFound} suspicious links and {storedScan.DangerousLinksFound} dangerous links were found. Downloads do not inherit full parent-domain trust."]),
        new ScoreBreakdownItem(
            "FinalHipScore",
            layeredScore.FinalHipScore,
            StatusForScore(layeredScore.FinalHipScore),
            layeredScore.Explanation,
            storedScan.Reasons)
    ];

    /// <summary>
    /// Builds the public layered HIP score from stored browser scan data.
    /// </summary>
    /// <param name="domain">Normalized root domain.</param>
    /// <param name="storedScan">Stored privacy-safe scan result.</param>
    /// <returns>Layered score components and final explanation.</returns>
    private static LayeredLookupScore BuildLayeredScore(string domain, BrowserScanResultRecord storedScan)
    {
        if (TryReadAuthenticatedLayeredScore(storedScan, out var authenticatedScore))
        {
            return authenticatedScore;
        }

        var domainTrust = DomainTrustScoreFor(domain, storedScan);
        var pageTrust = PageTrustScoreFor(storedScan);
        var contentScore = ContentRiskScoreFor(storedScan);
        var final = (int)Math.Round(domainTrust * 0.35 + pageTrust * 0.35 + contentScore * 0.30, MidpointRounding.AwayFromZero);

        if (domainTrust <= 60 && storedScan.RiskyLinksFound == 0 && storedScan.DangerousLinksFound == 0)
        {
            final = Math.Min(final, 60);
        }

        if (storedScan.Status.Equals("Dangerous", StringComparison.OrdinalIgnoreCase))
        {
            final = Math.Min(final, 9);
        }

        var explanation = BuildFinalExplanation(domain, domainTrust, pageTrust, contentScore, final);
        return new LayeredLookupScore(domainTrust, pageTrust, contentScore, final, explanation);
    }

    /// <summary>Uses server-authenticated score components when the stored projection is complete and internally consistent.</summary>
    private static bool TryReadAuthenticatedLayeredScore(
        BrowserScanResultRecord storedScan,
        out LayeredLookupScore layeredScore)
    {
        layeredScore = null!;
        if (!TryReadScore(storedScan.PrivacySafeMetadata, "domainTrustScore", out var domainTrust) ||
            !TryReadScore(storedScan.PrivacySafeMetadata, "pageTrustScore", out var pageTrust) ||
            !TryReadScore(storedScan.PrivacySafeMetadata, "contentRiskScore", out var contentScore) ||
            !TryReadScore(storedScan.PrivacySafeMetadata, "finalHipScore", out var finalScore) ||
            finalScore != storedScan.Score)
        {
            return false;
        }

        layeredScore = new LayeredLookupScore(
            domainTrust,
            pageTrust,
            contentScore,
            finalScore,
            $"HIP's latest authenticated server evaluation produced a final score of {finalScore}/100 from domain trust ({domainTrust}/100), page trust ({pageTrust}/100), and content safety ({contentScore}/100).");
        return true;
    }

    private static bool TryReadScore(
        IReadOnlyDictionary<string, string> metadata,
        string key,
        out int score)
    {
        score = 0;
        return metadata.TryGetValue(key, out var value) &&
               int.TryParse(
                   value,
                   System.Globalization.NumberStyles.None,
                   System.Globalization.CultureInfo.InvariantCulture,
                   out score) &&
               score is >= 0 and <= 100;
    }

    /// <summary>
    /// Calculates root-domain trust independently from specific page and content findings.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="storedScan">Stored scan result.</param>
    /// <returns>0-100 domain trust score.</returns>
    private static int DomainTrustScoreFor(string domain, BrowserScanResultRecord storedScan)
    {
        if (StrongDomainTrust.Contains(domain))
        {
            return 95;
        }

        if (domain.Contains("verified", StringComparison.OrdinalIgnoreCase))
        {
            return 85;
        }

        if (storedScan.DangerousLinksFound > 0 || storedScan.Status.Equals("Dangerous", StringComparison.OrdinalIgnoreCase) || IsDangerousTestDomain(domain))
        {
            return 35;
        }

        return 50;
    }

    /// <summary>
    /// Calculates exact-page trust from scan score and page-level risk counts.
    /// </summary>
    /// <param name="storedScan">Stored scan result.</param>
    /// <returns>0-100 page trust score.</returns>
    private static int PageTrustScoreFor(BrowserScanResultRecord storedScan)
    {
        var penalty = storedScan.DangerousLinksFound * 22 + storedScan.SuspiciousLinksFound * 12 + Math.Max(0, storedScan.RiskyLinksFound - storedScan.SuspiciousLinksFound - storedScan.DangerousLinksFound) * 8;
        var baseline = storedScan.LinksScanned == 0 ? 55 : Math.Min(storedScan.Score, 70);
        return Math.Clamp(baseline - penalty, 0, 100);
    }

    /// <summary>
    /// Calculates content score from link/download risk counts without inheriting full parent-domain trust.
    /// </summary>
    /// <param name="storedScan">Stored scan result.</param>
    /// <returns>0-100 content score where lower means riskier content.</returns>
    private static int ContentRiskScoreFor(BrowserScanResultRecord storedScan)
    {
        if (storedScan.LinksScanned == 0)
        {
            return 65;
        }

        var penalty = storedScan.DangerousLinksFound * 30 + storedScan.SuspiciousLinksFound * 18 + storedScan.RiskyLinksFound * 8;
        return Math.Clamp(72 - penalty, 0, 100);
    }

    /// <summary>
    /// Explains the final score in plain English without hiding the component scores.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="domainTrust">Domain trust score.</param>
    /// <param name="pageTrust">Page trust score.</param>
    /// <param name="contentScore">Content score.</param>
    /// <param name="final">Final HIP score.</param>
    /// <returns>Plain-English final score explanation.</returns>
    private static string BuildFinalExplanation(string domain, int domainTrust, int pageTrust, int contentScore, int final)
    {
        if (StrongDomainTrust.Contains(domain) && (pageTrust < 50 || contentScore < 50))
        {
            return $"The parent domain has strong trust signals ({domainTrust}/100), but this specific page and content show risk. Final HIP score is {final}/100 after lowering trust for page/content signals.";
        }

        if (domainTrust <= 60 && pageTrust >= 50 && contentScore >= 50)
        {
            return $"HIP did not find strong trust signals for this website yet. No major risk signals were found, but the site has not earned a high trust score. Final HIP score is {final}/100.";
        }

        return $"Final HIP score is {final}/100 from separate DomainTrustScore ({domainTrust}/100), PageTrustScore ({pageTrust}/100), and ContentRiskScore ({contentScore}/100).";
    }

    /// <summary>
    /// Detects the explicit MVP test-domain patterns that simulate known dangerous public data.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>True when the domain is a known MVP dangerous pattern.</returns>
    private static bool IsDangerousTestDomain(string domain) =>
        domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
        domain.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
        domain.Contains("scam", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Legacy demo scoring helper retained for tests or future fallback experiments.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>Demo HIP score result.</returns>
    private static HipScoreResult BuildSampleScore(string domain)
    {
        var isDangerousTestDomain = domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("scam", StringComparison.OrdinalIgnoreCase);
        var isShortener = ShortenerDomains.Contains(domain) || domain.Contains("short", StringComparison.OrdinalIgnoreCase);
        var isVerified = domain.Contains("verified", StringComparison.OrdinalIgnoreCase);

        var baseDomainScore = isDangerousTestDomain ? 10 : isShortener ? 42 : isVerified ? 92 : 72;
        var websiteScore = isDangerousTestDomain ? 16 : domain.Contains("new", StringComparison.OrdinalIgnoreCase) ? 48 : isVerified ? 88 : 74;
        var linkScore = isDangerousTestDomain ? 18 : isShortener ? 38 : 70;
        var contentScore = isDangerousTestDomain ? 24 : 62;
        var organizationScore = isVerified ? 86 : 58;
        var deviceKeyScore = isVerified ? 90 : 55;

        return HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(baseDomainScore), $"Domain reputation for {domain} is based on current HIP public signals.", [$"{domain} has a public domain reputation score of {baseDomainScore}/100."]), 2m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Website, ScoreValue.From(websiteScore), "Website risk reflects origin verification and known behavior signals.", ["Website behavior has been evaluated with available public facts."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Link, ScoreValue.From(linkScore), "Link score reflects redirect and shortener risk signals.", ["No private user content was used in this lookup."]), 1m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Sender, ScoreValue.From(60), "Sender reputation is unknown for a public domain-only lookup.", ["No sender identity was supplied."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Content, ScoreValue.From(contentScore), "Content score uses public website-level signals only.", ["No private content was inspected."]), 0.5m),
            new WeightedScore(new ScoreComponent(ScoreCategory.DeviceKey, ScoreValue.From(deviceKeyScore), "Device/key score reflects whether a signed HIP identity was found.", ["Initial lookup supports DNS TXT and .well-known/hip.json verification design."]), 0.75m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Organization, ScoreValue.From(organizationScore), "Organization reputation has limited public data in the mock foundation.", ["Organization-level reputation is not yet backed by a database."]), 0.75m)
        ]);
    }

    /// <summary>
    /// Maps a 0-100 HIP score to a public risk status band.
    /// </summary>
    /// <param name="score">HIP score.</param>
    /// <returns>Risk status.</returns>
    public static RiskStatus StatusForScore(int score) => score switch
    {
        <= 9 => RiskStatus.Dangerous,
        <= 24 => RiskStatus.HighRisk,
        <= 39 => RiskStatus.Suspicious,
        <= 49 => RiskStatus.Unknown,
        <= 69 => RiskStatus.LimitedTrustData,
        <= 84 => RiskStatus.MostlyTrusted,
        _ => RiskStatus.Trusted
    };

    /// <summary>
    /// Maps public risk status to a user-facing recommended action.
    /// </summary>
    /// <param name="status">Risk status.</param>
    /// <returns>Recommended action text.</returns>
    public static string RecommendedActionFor(RiskStatus status) => status switch
    {
        RiskStatus.Trusted or RiskStatus.MostlyTrusted or RiskStatus.ProbablySafe => "Allow",
        RiskStatus.LimitedTrustData or RiskStatus.Unknown or RiskStatus.Caution => "ShowCaution",
        RiskStatus.Suspicious => "ShowWarning",
        RiskStatus.HighRisk => "RouteToSafetyPage",
        RiskStatus.Dangerous => "RouteToSafetyPage",
        RiskStatus.Critical => "Block",
        _ => "ShowCaution"
    };

    /// <summary>
    /// Builds legacy demo reasons without private data.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="result">Demo scoring result.</param>
    /// <returns>Public-safe reason list.</returns>
    private static IReadOnlyCollection<string> BuildReasons(string domain, HipScoreResult result)
    {
        var reasons = new List<string>
        {
            "HIP MVP scoring uses public-safe demo signals until live reputation, rules, AI, and threat data are connected.",
            "No private chat logs, browsing history, or raw user-submitted private content were used in this lookup."
        };

        if (domain.Contains("verified", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("A placeholder signed identity signal is present for this demo domain.");
        }
        else
        {
            reasons.Add("No HIP signed website identity is configured yet.");
        }

        reasons.Add(result.FinalScore.Explanation);
        return reasons;
    }

    /// <summary>
    /// Builds legacy demo risk labels without private report details.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="status">Risk status.</param>
    /// <returns>Known public risk summaries.</returns>
    private static IReadOnlyCollection<string> BuildKnownRisks(string domain, RiskStatus status)
    {
        if (domain.Contains("danger", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("phishing", StringComparison.OrdinalIgnoreCase) ||
            domain.Contains("scam", StringComparison.OrdinalIgnoreCase))
        {
            return ["Known suspicious test-domain pattern detected", "MVP demo scoring classified this domain as dangerous."];
        }

        if (ShortenerDomains.Contains(domain) || domain.Contains("short", StringComparison.OrdinalIgnoreCase))
        {
            return ["Shortened URL behavior detected", "Shorteners can hide final destinations from users."];
        }

        return status is RiskStatus.Suspicious or RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical
            ? ["Domain has limited reputation history"]
            : [];
    }

    /// <summary>
    /// Layered score values used to avoid flattening domain, page, and content trust.
    /// </summary>
    /// <param name="DomainTrustScore">Root-domain trust score.</param>
    /// <param name="PageTrustScore">Exact page or URL trust score.</param>
    /// <param name="ContentRiskScore">Content score where lower means riskier content.</param>
    /// <param name="FinalHipScore">Final user-facing HIP score.</param>
    /// <param name="Explanation">Plain-English final score explanation.</param>
    private sealed record LayeredLookupScore(
        int DomainTrustScore,
        int PageTrustScore,
        int ContentRiskScore,
        int FinalHipScore,
        string Explanation);
}
