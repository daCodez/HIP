(function runHipContentScript() {
  if (window.__hipContentScriptLoaded) {
    return;
  }

  window.__hipContentScriptLoaded = true;

  const riskyStatuses = new Set(["Suspicious", "HighRisk", "Dangerous", "Critical"]);
  const attentionStatuses = new Set(["Unknown", "LimitedTrustData", "Caution", "Suspicious", "HighRisk", "Dangerous", "Critical"]);
  const ignoredProtocols = new Set(["javascript:", "mailto:", "tel:", "data:", "blob:"]);
  const downloadExtensions = new Set([".exe", ".zip", ".msi", ".dmg", ".pdf", ".docx", ".scr"]);
  const executableDownloadExtensions = new Set([".exe", ".msi", ".dmg", ".scr"]);
  const shortenerDomains = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "shorturl.at", "rebrand.ly"]);
  const reportedDomains = new Set();
  const pendingScanSubmissions = new Set();

  const currentDomain = normalizeHost(window.location.hostname);
  let settings = null;
  let pluginVersion = "HIP Plugin vunknown-dev";
  let lastSummary = emptySummary();

  if (!currentDomain) {
    return;
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "HIP_REFRESH_SCAN") {
      initialize()
        .then(() => sendResponse({ ok: true, result: lastSummary }))
        .catch(error => {
          handleInitializationError(error);
          sendResponse({ ok: false, error: error.message });
        });
      return true;
    }

    if (message?.type === "HIP_GET_CONTENT_SUMMARY") {
      sendResponse({ ok: true, result: lastSummary });
      return false;
    }

    return false;
  });

  initialize().catch(handleInitializationError);

  /**
   * Runs the privacy-safe page scan and publishes a summary for the popup.
   */
  async function initialize() {
    settings = await loadSettings();
    pluginVersion = await loadPluginVersion();
    lastSummary = emptySummary();
    markScanStage("Starting");
    publishSummary();

    if (isHipOwnedPage(window.location.href, settings)) {
      lastSummary.apiStatus = "Skipped";
      lastSummary.scanResultSubmission = "Skipped";
      lastSummary.scanResultDataSource = "HipOwnedPage";
      markScanStage("SkippedHipPage");
      lastSummary.website = {
        domain: currentDomain,
        status: "NotScanned",
        publicLookupUrl: `${settings.webBaseUrl}/lookup/domain/${encodeURIComponent(currentDomain)}`
      };
      publishSummary();
      return;
    }

    markScanStage("CheckingSiteScore");
    publishSummary();
    const currentLookup = await scoreSite(currentDomain, window.location.href);
    lastSummary.website = compactLookup(currentLookup);
    lastSummary.apiStatus = currentLookup ? "Available" : "Unavailable";
    publishSummary();

    if (settings.enableLinkScanning) {
      markScanStage("ScanningLinks");
      publishSummary();
      await scanLinks();
      publishSummary();
    }

    markScanStage("CheckingForms");
    publishSummary();
    await scanLoginForms();
    markScanStage("CollectingPageSignals");
    collectScriptSignals();
    publishSummary();
    markScanStage("CheckingSiteSafety");
    publishSummary();
    await scanSiteSafety().catch(error => {
      lastSummary.siteSafetyStatus = "Unavailable";
      lastSummary.siteSafetyError = error?.message || "HIP Site Safety unavailable.";
    });
    markScanStage("RenderingWarnings");
    await renderPageBannerIfNeeded(currentLookup);
    markScanStage("SubmittingSummary");
    publishSummary();
    await persistScanResult(currentLookup).catch(error => console.warn("HIP scan result persistence failed safely.", error));
    markScanStage("Complete");
    publishSummary();
  }

  /**
   * Publishes a privacy-safe failure summary when startup fails so the popup does not wait forever.
   * The error text is kept generic and never includes page body text, form values, cookies, or tokens.
   */
  function handleInitializationError(error) {
    console.warn("HIP content script failed safely.", error);
    lastSummary = lastSummary || emptySummary();
    lastSummary.apiStatus = "Unavailable";
    lastSummary.scanResultSubmission = "Failed";
    lastSummary.scanResultError = error?.message || "HIP page scan failed.";
    markScanStage("Failed");
    publishSummary();
  }

  /**
   * Scans page anchor href values only; page body text and form values are not read or submitted.
   */
  async function scanLinks() {
    const anchorsByDomain = new Map();

    for (const anchor of document.querySelectorAll("a[href]")) {
      const target = parseTarget(anchor);
      if (!target || target.domain === currentDomain) {
        continue;
      }

      target.isDownloadCandidate = isDownloadLike(target.url);
      target.linkContext = detectLinkContext(anchor);
      lastSummary.linksScanned++;
      if (target.isDownloadCandidate) {
        lastSummary.downloadCandidates++;
        lastSummary.downloadLinks.push(target.url.href);
      }
      if (isShortenerDomain(target.domain)) {
        lastSummary.shortenedLinkCandidates++;
      }
      if (isObfuscatedLinkLike(target.url, anchor)) {
        lastSummary.obfuscatedLinkCandidates++;
      }
      if (isRedirectLike(target.url)) {
        lastSummary.redirectCandidates++;
        lastSummary.redirectSignals.push(target.url.href);
      }
      if (isExecutableDownloadLike(target.url)) {
        lastSummary.executableDownloadCandidates++;
      }
      if (target.linkContext === "social-feed") {
        lastSummary.socialLinkCandidates++;
      }
      if (target.linkContext === "webmail") {
        lastSummary.webmailLinkCandidates++;
      }

      if (!anchorsByDomain.has(target.domain)) {
        anchorsByDomain.set(target.domain, []);
      }

      anchorsByDomain.get(target.domain).push({ anchor, target });
    }

    const scanResults = await scanPageLinks(Array.from(anchorsByDomain.values()).flat().map(item => item.target.url.href));
    if (!scanResults) {
      lastSummary.apiStatus = "Unavailable";
      return;
    }

    const resultsByUrl = new Map(scanResults.results.map(result => [result.url, result]));

    for (const items of anchorsByDomain.values()) {
      for (const item of items) {
        const result = resultsByUrl.get(item.target.url.href);
        if (!result) {
          continue;
        }

        const lookup = browserResultToLookup(result);
        if (lookup.status === "Unknown") {
          lastSummary.unknownLinks++;
        }
        if (lookup.status === "Suspicious" || lookup.status === "HighRisk") {
          lastSummary.suspiciousLinks++;
        }
        if (lookup.status === "Dangerous" || lookup.status === "Critical") {
          lastSummary.dangerousLinks++;
        }
        if (riskyStatuses.has(lookup.status)) {
          lastSummary.riskyLinks++;
        }

        applyLinkProtection(item.anchor, item.target, withLookupUrl(lookup), result);
      }
    }
  }

  async function scanLoginForms() {
    const forms = Array.from(document.querySelectorAll("form"));
    lastSummary.formsDetected = forms.length;
    lastSummary.loginFormsDetected = forms.filter(form => form.querySelector('input[type="password"]')).length;
    lastSummary.passwordFieldsDetected = document.querySelectorAll('input[type="password"]').length;
    lastSummary.paymentFieldsDetected = forms.filter(hasPaymentField).length;

    for (const form of forms) {
      if (!form.querySelector('input[type="password"]')) {
        continue;
      }

      const actionDomain = formActionDomain(form);
      if (!actionDomain || actionDomain === currentDomain) {
        continue;
      }

      lastSummary.crossDomainLoginForms++;
      const lookup = await scoreSite(actionDomain, `https://${actionDomain}`);
      if (lookup?.status && attentionStatuses.has(lookup.status)) {
        window.HipRiskBadgeRenderer.renderFormIndicator(form, lookup, "Login form submits to a different domain. HIP checked the action domain only; no form values were read.");
      }
    }
  }

  /**
   * Renders the injected banner only when settings and page risk justify interrupting the user.
   * The popup remains the default place for normal HIP details.
   */
  async function renderPageBannerIfNeeded(currentLookup) {
    if (!settings.enableWarningBanner || !currentLookup?.status || !shouldShowTrustBanner(currentLookup, lastSummary, settings)) {
      return;
    }

    const pageKey = await sha256(window.location.href);
    const dismissedResponse = await chrome.runtime.sendMessage({
      type: "HIP_GET_BANNER_DISMISSED",
      domain: currentLookup.domain || currentDomain,
      pageKey
    });
    if (dismissedResponse?.ok && dismissedResponse.result === true) {
      return;
    }

    window.HipRiskBadgeRenderer.renderTrustBanner(withBannerCopy(withLookupUrl(currentLookup), lastSummary), pluginVersion, {
      onFeedback: submitBannerFeedback,
      onDismiss: lookup => dismissTrustBanner(lookup, pageKey)
    });
  }

  function applyLinkProtection(anchor, target, lookup, browserResult = null) {
    const status = lookup.status;
    const verified = lookup.verificationStatus === "Verified" || lookup.signedIdentityStatus === "PostQuantumSignaturePresent";
    const shouldBadge = browserResult?.requiresIcon || shouldRenderBadge(status, verified, target.isDownloadCandidate);

    if (settings.showRiskyLinkIcons && shouldBadge) {
      const badgeStatus = browserResult?.label || (target.isDownloadCandidate && !riskyStatuses.has(status) ? "LimitedTrustData" : (verified && status === "Trusted" ? "Verified" : status));
      const badgeLookup = target.isDownloadCandidate
        ? { ...lookup, knownRisks: ["Download risk candidate"], finalHipScore: lookup.finalHipScore }
        : lookup;
      window.HipRiskBadgeRenderer.renderLinkBadge(anchor, badgeStatus, badgeLookup);
    }

    if (settings.enableSafetyPageRouting && riskyStatuses.has(status) && anchor.dataset.hipSafetyBound !== "true") {
      anchor.addEventListener("click", event =>
        window.HipSafetyPageRouter.routeClick(event, anchor, lookup, currentDomain), true);
      anchor.dataset.hipSafetyBound = "true";
      reportRiskFinding(anchor, target, lookup).catch(error => console.warn("HIP reporting failed safely.", error));
    }
  }

  function shouldRenderBadge(status, verified, isDownloadCandidate) {
    if (settings.scanMode === "Quiet") {
      return riskyStatuses.has(status) || isDownloadCandidate && status === "Dangerous";
    }

    if (settings.scanMode === "Normal") {
      return riskyStatuses.has(status) || verified && status === "Trusted" || isDownloadCandidate;
    }

    if (settings.scanMode === "Strict") {
      return attentionStatuses.has(status) || verified && status === "Trusted" || isDownloadCandidate;
    }

    return status !== "Trusted" || verified || isDownloadCandidate;
  }

  async function reportRiskFinding(anchor, target, lookup) {
    if (reportedDomains.has(lookup.domain)) {
      return;
    }

    reportedDomains.add(lookup.domain);
    const report = {
      reportId: "",
      sourceClient: "BrowserPlugin",
      platform: "Web",
      targetType: "Url",
      domain: lookup.domain,
      urlHash: await sha256(target.url.href),
      originalUrl: null,
      senderHash: null,
      riskLevel: lookup.status,
      reason: target.isDownloadCandidate
        ? "Download risk candidate on a risky link domain."
        : lookup.explanations?.[0] || lookup.knownRisks?.[0] || "HIP detected a risky link on the current page.",
      detectedAtUtc: new Date().toISOString(),
      reporterTrustLevel: "Medium",
      privacySafeEvidence: {
        evidenceType: "browser-link-risk",
        summary: "Browser plugin reported a risky link domain without page body text, form values, or private messages.",
        facts: {
          sourceDomain: currentDomain,
          targetDomain: lookup.domain,
          scanMode: settings.scanMode,
          linkContext: target.linkContext,
          downloadCandidate: String(target.isDownloadCandidate)
        },
        containsPrivateContent: false
      },
      hipSignature: "browser-plugin-signature-placeholder"
    };

    await chrome.runtime.sendMessage({ type: "HIP_REPORT_RISK_FINDING", report });
  }

  /**
   * Submits weighted trust feedback from the injected HIP banner.
   * The payload intentionally avoids page text, form values, cookies, tokens, and private content.
   */
  async function submitBannerFeedback(feedbackType, lookup) {
    const looksSafe = feedbackType === "LooksSafe";
    // These values mirror HIP.Domain.Reputation enum ordinals so the current API can bind feedback safely.
    const enumValues = {
      targetTypeWebsite: 5,
      eventPositiveReport: 0,
      eventSuspiciousReport: 2,
      severityLow: 0,
      severityMedium: 1,
      reporterTrustAnonymous: 0
    };
    const feedback = {
      targetType: enumValues.targetTypeWebsite,
      targetId: lookup?.domain || currentDomain,
      eventType: looksSafe ? enumValues.eventPositiveReport : enumValues.eventSuspiciousReport,
      severity: looksSafe ? enumValues.severityLow : enumValues.severityMedium,
      reporterTrustLevel: enumValues.reporterTrustAnonymous,
      reason: looksSafe
        ? "Browser plugin feedback: user reported the site looks safe."
        : "Browser plugin feedback: user reported the site looks suspicious.",
      platform: "Web",
      urlHash: await sha256(window.location.href)
    };

    const response = await chrome.runtime.sendMessage({ type: "HIP_SUBMIT_SITE_FEEDBACK", feedback });
    if (!response?.ok) {
      throw new Error(response?.error || "HIP feedback unavailable");
    }

    return response.result;
  }

  /**
   * Saves only a privacy-safe browser scan summary for future HIP scoring and dashboard use.
   * Page text, form values, email body text, and private messages are intentionally excluded.
   */
  async function persistScanResult(currentLookup) {
    if (!settings.submitScanResults) {
      lastSummary.scanResultSubmission = "Disabled";
      lastSummary.scanResultDataSource = "NotSubmitted";
      return;
    }

    if (!currentLookup) {
      lastSummary.scanResultSubmission = "Skipped";
      return;
    }

    lastSummary.scanResultSubmission = "Pending";
    lastSummary.pluginVersion = pluginVersion;
    lastSummary.isHttps = window.location.protocol === "https:";
    lastSummary.pageUrlHash = await sha256(window.location.href);
    const submissionKey = `${currentDomain}:${lastSummary.pageUrlHash}`;
    if (pendingScanSubmissions.has(submissionKey)) {
      lastSummary.scanResultSubmission = "Pending";
      lastSummary.scanResultDataSource = "AlreadySubmitting";
      return;
    }

    pendingScanSubmissions.add(submissionKey);
    const assessment = browserScanAssessment(currentLookup, lastSummary);
    const payload = {
      domain: currentDomain,
      pageUrl: settings.allowRawPageUrlSubmission === true ? stripQueryAndFragment(window.location.href) : null,
      pageUrlHash: lastSummary.pageUrlHash,
      pluginVersion,
      score: assessment.score,
      riskLevel: assessment.status,
      status: assessment.status,
      reasons: assessment.reasons,
      linksScanned: lastSummary.linksScanned,
      riskyLinksFound: lastSummary.riskyLinks,
      suspiciousLinksFound: lastSummary.suspiciousLinks,
      dangerousLinksFound: lastSummary.dangerousLinks,
      recommendedAction: recommendedSiteAction(assessment.status),
      privacySafeMetadata: {
        scanMode: settings.scanMode,
        apiStatus: lastSummary.apiStatus,
        scanTimestampUtc: new Date().toISOString(),
        isHttps: String(lastSummary.isHttps),
        downloadCandidates: String(lastSummary.downloadCandidates),
        executableDownloadCandidates: String(lastSummary.executableDownloadCandidates),
        formsDetected: String(lastSummary.formsDetected),
        loginFormsDetected: String(lastSummary.loginFormsDetected),
        passwordFieldsDetected: String(lastSummary.passwordFieldsDetected),
        paymentFieldsDetected: String(lastSummary.paymentFieldsDetected),
        crossDomainLoginForms: String(lastSummary.crossDomainLoginForms),
        shortenedLinkCandidates: String(lastSummary.shortenedLinkCandidates),
        obfuscatedLinkCandidates: String(lastSummary.obfuscatedLinkCandidates),
        redirectCandidates: String(lastSummary.redirectCandidates),
        socialLinkCandidates: String(lastSummary.socialLinkCandidates),
        webmailLinkCandidates: String(lastSummary.webmailLinkCandidates),
        siteSafetyDataSource: lastSummary.siteSafetyDataSource,
        siteSafetyStatus: lastSummary.siteSafetyStatus,
        confidence: lastSummary.confidenceLevel,
        domainTrustScore: String(lastSummary.domainTrustScore ?? ""),
        pageTrustScore: String(lastSummary.pageTrustScore ?? ""),
        contentRiskScore: String(lastSummary.contentRiskScore ?? ""),
        finalHipScore: String(lastSummary.finalHipScore ?? ""),
        providerEvidenceCount: String(lastSummary.providerEvidenceCount ?? 0),
        pluginVersion
      }
    };

    try {
      const response = await chrome.runtime.sendMessage({ type: "HIP_SAVE_SCAN_RESULT", result: payload });
      if (!response?.ok) {
        lastSummary.scanResultSubmission = "Failure";
        lastSummary.scanResultError = response?.error || "Submission failed";
        console.warn("HIP scan result was not persisted.", response?.error);
        return;
      }

      lastSummary.scanResultSubmission = "Success";
      lastSummary.scanResultDataSource = "BrowserPluginScan";
      lastSummary.lastSubmittedUtc = response.result?.lastCheckedUtc || new Date().toISOString();
    } finally {
      pendingScanSubmissions.delete(submissionKey);
    }
  }

  async function lookupDomain(domain) {
    const response = await chrome.runtime.sendMessage({ type: "HIP_LOOKUP_DOMAIN", domain });
    if (!response?.ok) {
      console.warn("HIP unavailable for domain lookup.", domain, response?.error);
      return null;
    }

    return response.result;
  }

  async function scoreSite(domain, url) {
    const response = await chrome.runtime.sendMessage({ type: "HIP_SCORE_SITE", request: { domain, url } });
    if (!response?.ok) {
      console.warn("HIP unavailable for site score.", domain, response?.error);
      return null;
    }

    return response.result;
  }

  async function scanPageLinks(links) {
    const response = await chrome.runtime.sendMessage({
      type: "HIP_SCAN_LINKS",
      pageUrl: window.location.href,
      links
    });

    if (!response?.ok) {
      console.warn("HIP unavailable for link scan.", response?.error);
      return null;
    }

    return response.result;
  }

  /**
   * Runs Site Safety automatically from the content script after structural page signals are collected.
   * The request sends counts, public evidence URLs, and the current URL only; it never sends page body text,
   * form values, cookies, tokens, passwords, or private message content.
   */
  async function scanSiteSafety() {
    if (!isSiteSafetyEligibleUrl(window.location.href)) {
      lastSummary.siteSafetyStatus = "Skipped";
      lastSummary.siteSafetyDataSource = "IneligibleUrl";
      return null;
    }

    const request = buildSiteSafetyRequest();
    const response = await chrome.runtime.sendMessage({ type: "HIP_SCAN_SITE_SAFETY", request });
    if (!response?.ok) {
      lastSummary.siteSafetyStatus = "Unavailable";
      lastSummary.siteSafetyError = response?.error || "HIP Site Safety unavailable.";
      return null;
    }

    lastSummary.siteSafetyStatus = response.result?.status || "Unknown";
    lastSummary.siteSafetyDataSource = "SiteSafetyScan";
    lastSummary.siteSafetyScannedAtUtc = response.result?.scannedAtUtc || new Date().toISOString();
    lastSummary.domainTrustScore = response.result?.domainTrustScore ?? null;
    lastSummary.pageTrustScore = response.result?.pageTrustScore ?? null;
    lastSummary.contentRiskScore = response.result?.contentRiskScore ?? null;
    lastSummary.finalHipScore = response.result?.finalHipScore ?? null;
    lastSummary.confidenceLevel = response.result?.confidenceLevel || "Unknown";
    lastSummary.providerEvidenceCount = Array.isArray(response.result?.providerEvidence)
      ? response.result.providerEvidence.length
      : 0;
    return response.result;
  }

  /**
   * Builds the privacy-safe Site Safety request from structural page observations.
   * Evidence URL lists are filtered to public HTTP(S) URLs so the API does not receive localhost/private targets.
   */
  function buildSiteSafetyRequest() {
    return {
      url: window.location.href,
      pluginVersion,
      observedSignals: {
        downloadLinks: filterSafePublicUrls(lastSummary.downloadLinks),
        hasLoginForm: lastSummary.loginFormsDetected > 0,
        hasPasswordField: lastSummary.passwordFieldsDetected > 0,
        hasPaymentField: lastSummary.paymentFieldsDetected > 0,
        inlineScriptCount: lastSummary.inlineScriptCount,
        externalScriptUrls: filterSafePublicUrls(lastSummary.externalScriptUrls),
        suspiciousScriptPatternCount: lastSummary.suspiciousScriptPatternCount,
        trustDataAvailable: lastSummary.scanResultDataSource === "BrowserPluginScan",
        shortenedLinkCount: lastSummary.shortenedLinkCandidates,
        obfuscatedLinkCount: lastSummary.obfuscatedLinkCandidates,
        redirectChain: filterSafePublicUrls(lastSummary.redirectSignals)
      }
    };
  }

  /**
   * Removes query strings and fragments before any explicitly enabled raw URL diagnostic submission.
   * Normal background scan submissions send only pageUrlHash, because query strings often contain private tokens.
   */
  function stripQueryAndFragment(pageUrl) {
    try {
      const url = new URL(pageUrl);
      if (!["http:", "https:"].includes(url.protocol)) {
        return null;
      }

      url.search = "";
      url.hash = "";
      return url.toString();
    } catch {
      return null;
    }
  }

  async function loadSettings() {
    const response = await chrome.runtime.sendMessage({ type: "HIP_GET_SETTINGS" });
    return response?.ok ? response.result : {
      enableLinkBadges: true,
      showRiskyLinkIcons: true,
      enableLinkScanning: true,
      enableWarningBanner: true,
      enableSafetyRouting: true,
      enableSafetyPageRouting: true,
      submitScanResults: true,
      bannerDisplayMode: "WarningsOnly",
      scanMode: "Normal"
    };
  }

  /**
   * Detects the configured HIP API/Web hosts so the extension does not recursively scan HIP's own UI.
   * This prevents localhost lookup pages from generating noisy API-unavailable errors during development.
   */
  function isHipOwnedPage(pageUrl, currentSettings = {}) {
    try {
      const pageOrigin = new URL(pageUrl).origin;
      const hipOrigins = [currentSettings.apiBaseUrl, currentSettings.hipApiBaseUrl, currentSettings.webBaseUrl]
        .filter(Boolean)
        .map(value => new URL(value).origin);
      return hipOrigins.includes(pageOrigin);
    } catch {
      return false;
    }
  }

  /**
   * Checks whether the current tab URL is safe to submit to the Site Safety API.
   * Localhost and private-network URLs are skipped client-side because the server rejects them as SSRF protection.
   */
  function isSiteSafetyEligibleUrl(pageUrl) {
    try {
      const url = new URL(pageUrl);
      return ["http:", "https:"].includes(url.protocol) &&
        !isHipOwnedPage(pageUrl, settings) &&
        !isInternalHost(url.hostname);
    } catch {
      return false;
    }
  }

  /**
   * Filters optional evidence URLs before sending Site Safety requests.
   * This protects local networks and keeps expected API validation failures out of extension diagnostics.
   */
  function filterSafePublicUrls(values) {
    if (!Array.isArray(values)) {
      return [];
    }

    return values
      .filter(value => typeof value === "string")
      .filter(isSiteSafetyEligibleUrl);
  }

  /**
   * Detects local and private hosts using the same conservative checks as the shared API client helper.
   */
  function isInternalHost(hostname) {
    const host = normalizeHost(hostname);
    if (!host ||
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host === "::1" ||
      host === "[::1]") {
      return true;
    }

    const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!ipv4) {
      return false;
    }

    const octets = ipv4.slice(1).map(Number);
    if (octets.some(octet => Number.isNaN(octet) || octet < 0 || octet > 255)) {
      return true;
    }

    return octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168);
  }

  /**
   * Loads the dev/MVP extension version through the background worker.
   * The background worker reads manifest.json, so content scripts do not hardcode version strings.
   */
  async function loadPluginVersion() {
    const response = await chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" });
    return response?.ok ? response.result : "HIP Plugin vunknown-dev";
  }

  /**
   * Publishes the latest privacy-safe scan summary to the extension background worker.
   * This keeps the popup updated even when it opens after the content script has already started scanning.
   */
  function publishSummary() {
    lastSummary.updatedAt = new Date().toISOString();
    chrome.runtime.sendMessage({ type: "HIP_SCAN_SUMMARY", summary: lastSummary }).catch(() => {});
  }

  /**
   * Marks the current page scan stage without collecting private page content.
   * Stages are UI/debug hints only; HIP scoring decisions come from structured scan evidence.
   */
  function markScanStage(stage) {
    lastSummary.scanStage = stage;
    lastSummary.lastScanUtc = new Date().toISOString();
  }

  function parseTarget(anchor) {
    const href = anchor.getAttribute("href");
    if (!href || href.startsWith("#")) {
      return null;
    }

    let url;
    try {
      url = new URL(href, window.location.href);
    } catch {
      return null;
    }

    if (ignoredProtocols.has(url.protocol)) {
      return null;
    }

    return {
      url,
      domain: normalizeHost(url.hostname)
    };
  }

  function isDownloadLike(url) {
    const pathname = url.pathname.toLowerCase();
    return downloadExtensions.has(pathname.slice(pathname.lastIndexOf("."))) || url.searchParams.has("download");
  }

  /**
   * Detects executable download candidates without downloading or inspecting file contents.
   */
  function isExecutableDownloadLike(url) {
    const pathname = url.pathname.toLowerCase();
    return executableDownloadExtensions.has(pathname.slice(pathname.lastIndexOf(".")));
  }

  /**
   * Detects common URL shortener hosts from href structure only.
   * HIP stores only the count for scan summaries, avoiding page text and private content.
   */
  function isShortenerDomain(domain) {
    return shortenerDomains.has(normalizeHost(domain));
  }

  /**
   * Detects obfuscated URL structure without reading surrounding page body text.
   */
  function isObfuscatedLinkLike(url, anchor) {
    const rawHref = anchor.getAttribute("href") || "";
    return rawHref.includes("hxxp") ||
      rawHref.includes("[.]") ||
      /%[0-9a-f]{2}/i.test(url.href) ||
      /@/.test(url.username || "") ||
      /\d+\.\d+\.\d+\.\d+/.test(url.hostname);
  }

  /**
   * Detects redirect-style links using URL path and parameter names only.
   */
  function isRedirectLike(url) {
    const redirectParameterNames = ["url", "u", "redirect", "redirect_url", "target", "dest", "destination", "next"];
    return redirectParameterNames.some(name => url.searchParams.has(name)) ||
      /\/(redirect|out|away|go|link)\b/i.test(url.pathname);
  }

  function detectLinkContext(anchor) {
    if (anchor.closest('[role="feed"], [data-testid*="tweet"], article, .feed, .post, .timeline')) {
      return "social-feed";
    }

    if (anchor.closest('[aria-label*="mail" i], [class*="mail" i], [data-testid*="message" i], [role="mail" i]')) {
      return "webmail";
    }

    return "page-link";
  }

  function formActionDomain(form) {
    const action = form.getAttribute("action");
    if (!action) {
      return currentDomain;
    }

    try {
      return normalizeHost(new URL(action, window.location.href).hostname);
    } catch {
      return currentDomain;
    }
  }

  /**
   * Detects payment field presence without reading values, names beyond labels, or typed content.
   */
  function hasPaymentField(form) {
    return Boolean(form.querySelector('input[autocomplete*="cc-" i], input[name*="card" i], input[id*="card" i], input[name*="payment" i], input[id*="payment" i]'));
  }

  /**
   * Collects script structure facts without reading or sending script contents.
   * HIP uses these counts for Site Safety risk scoring while avoiding page text collection.
   */
  function collectScriptSignals() {
    const scripts = Array.from(document.querySelectorAll("script"));
    lastSummary.inlineScriptCount = scripts.filter(script => !script.src).length;
    lastSummary.externalScriptUrls = scripts
      .filter(script => Boolean(script.src))
      .slice(0, 25)
      .map(script => script.src);
    lastSummary.suspiciousScriptPatternCount = 0;
  }

  function normalizeHost(hostname) {
    return (hostname || "").replace(/^www\./i, "").toLowerCase();
  }

  function withLookupUrl(lookup) {
    return {
      ...lookup,
      publicLookupUrl: lookup.publicLookupUrl || `${settings.webBaseUrl}/lookup/domain/${encodeURIComponent(lookup.domain)}`
    };
  }

  function browserResultToLookup(result) {
    return {
      domain: result.domain,
      finalHipScore: result.score,
      status: result.riskLevel,
      verificationStatus: "Unverified",
      signedIdentityStatus: "NoSignedIdentityFound",
      knownRisks: result.reasons || [],
      explanations: result.reasons || [],
      publicLookupUrl: result.publicLookupUrl,
      safetyPageUrl: result.safetyPageUrl
    };
  }

  function compactLookup(lookup) {
    if (!lookup) {
      return null;
    }

    return {
      domain: lookup.domain,
      finalHipScore: lookup.finalHipScore,
      status: lookup.status,
      verificationStatus: lookup.verificationStatus,
      identityVerificationStatus: lookup.identityVerificationStatus,
      lastCheckedUtc: lookup.lastCheckedUtc,
      publicLookupUrl: lookup.publicLookupUrl
    };
  }

  /**
   * Picks display-safe reasons from HIP lookup data without reading page body text.
   */
  function safeReasons(lookup) {
    const reasons = lookup?.knownRisks?.length ? lookup.knownRisks : lookup?.explanations || lookup?.reasons || [];
    return reasons.length > 0 ? reasons : ["No risky links found by the browser plugin scan."];
  }

  /**
   * Uses actual browser scan counts when lookup is still HIP's bootstrap no-data state.
   * This prevents the first successful content scan from persisting "not scanned yet" as a real result.
   */
  function browserScanAssessment(lookup, summary = {}) {
    if (summary.siteSafetyDataSource === "SiteSafetyScan" && Number.isInteger(summary.finalHipScore)) {
      const status = mapSiteSafetyStatus(summary.siteSafetyStatus);
      return {
        score: summary.finalHipScore,
        status,
        reasons: siteSafetyScanReasons(summary)
      };
    }

    if (!isLookupNoDataState(lookup)) {
      const status = lookup?.status || "Unknown";
      return {
        score: lookup?.finalHipScore ?? lookup?.score ?? 0,
        status,
        reasons: safeReasons(lookup)
      };
    }

    const dangerousLinks = summary.dangerousLinks ?? 0;
    const suspiciousLinks = summary.suspiciousLinks ?? 0;
    const riskyLinks = summary.riskyLinks ?? 0;
    const unknownLinks = summary.unknownLinks ?? 0;
    const downloadCandidates = summary.downloadCandidates ?? 0;
    const linksScanned = summary.linksScanned ?? 0;
    const score = Math.max(0, Math.min(100, 80 - dangerousLinks * 30 - suspiciousLinks * 18 - Math.max(0, riskyLinks - suspiciousLinks - dangerousLinks) * 12 - unknownLinks * 6 - downloadCandidates * 4));

    return {
      score,
      status: browserScanStatus(score, dangerousLinks, suspiciousLinks, riskyLinks, unknownLinks),
      reasons: browserScanReasons({ linksScanned, riskyLinks, suspiciousLinks, dangerousLinks, unknownLinks, downloadCandidates })
    };
  }

  /**
   * Converts Site Safety labels to the public/dashboard status labels used by stored browser scan summaries.
   */
  function mapSiteSafetyStatus(status) {
    if (status === "Clean") {
      return "MostlyTrusted";
    }

    if (status === "LimitedData") {
      return "LimitedTrustData";
    }

    return ["Unknown", "Suspicious", "HighRisk", "Dangerous"].includes(status)
      ? status
      : "Unknown";
  }

  /**
   * Explains an automatic Site Safety-backed browser scan without exposing raw page contents.
   */
  function siteSafetyScanReasons(summary = {}) {
    const reasons = ["HIP ran a privacy-safe Site Safety scan using structural browser observations."];
    if (summary.confidenceLevel) {
      reasons.push(`Site Safety confidence: ${summary.confidenceLevel}.`);
    }

    if ((summary.providerEvidenceCount ?? 0) > 0) {
      reasons.push(`${summary.providerEvidenceCount} evidence provider result${summary.providerEvidenceCount === 1 ? " was" : "s were"} included.`);
    }

    return reasons;
  }

  /**
   * Detects lookup responses that explicitly mean HIP has no stored scan yet.
   */
  function isLookupNoDataState(lookup) {
    const reasons = [...(lookup?.knownRisks || []), ...(lookup?.explanations || []), ...(lookup?.reasons || [])];
    return !lookup ||
      lookup.dataSource === "NoStoredData" ||
      reasons.some(reason => typeof reason === "string" && reason.includes("HIP has not scanned this domain yet"));
  }

  /**
   * Maps privacy-safe browser scan counts to a status without claiming complete real-world trust.
   */
  function browserScanStatus(score, dangerousLinks, suspiciousLinks, riskyLinks, unknownLinks) {
    if (dangerousLinks > 0) {
      return "Dangerous";
    }

    if (suspiciousLinks > 0 || riskyLinks > 0) {
      return "Suspicious";
    }

    if (unknownLinks > 0 || score <= 60) {
      return "LimitedTrustData";
    }

    return "MostlyTrusted";
  }

  /**
   * Builds plain-English reasons from scan counts without including page body text or form values.
   */
  function browserScanReasons({ linksScanned, riskyLinks, suspiciousLinks, dangerousLinks, unknownLinks, downloadCandidates }) {
    const reasons = [`Browser plugin scanned ${linksScanned} external links on this page without sending page text or form values.`];

    if (riskyLinks === 0 && suspiciousLinks === 0 && dangerousLinks === 0) {
      reasons.push("No risky external links were found in this browser plugin scan.");
    }

    if (suspiciousLinks > 0) {
      reasons.push(`${suspiciousLinks} suspicious external link${suspiciousLinks === 1 ? " was" : "s were"} found.`);
    }

    if (dangerousLinks > 0) {
      reasons.push(`${dangerousLinks} dangerous external link${dangerousLinks === 1 ? " was" : "s were"} found.`);
    }

    if (unknownLinks > 0) {
      reasons.push(`${unknownLinks} external link${unknownLinks === 1 ? " has" : "s have"} unknown HIP status.`);
    }

    if (downloadCandidates > 0) {
      reasons.push(`${downloadCandidates} download-like link${downloadCandidates === 1 ? " was" : "s were"} detected for caution.`);
    }

    return reasons;
  }

  /**
   * Maps the current website status to a persisted action summary for later dashboards.
   */
  function recommendedSiteAction(status) {
    if (riskyStatuses.has(status)) {
      return "RouteToSafetyPage";
    }

    if (status === "Unknown" || status === "LimitedTrustData" || status === "Caution") {
      return "ShowLabel";
    }

    return "Allow";
  }

  /**
   * Decides whether the page-level banner should interrupt the user.
   */
  function shouldShowTrustBanner(lookup, summary, currentSettings) {
    const mode = currentSettings.bannerDisplayMode || "WarningsOnly";
    if (mode === "NeverShow" || currentSettings.enableWarningBanner === false) {
      return false;
    }

    if (mode === "AlwaysShow") {
      return true;
    }

    const status = lookup?.status || "Unknown";
    if (mode === "DangerousOnly") {
      return status === "Dangerous";
    }

    if (status === "Suspicious" || status === "HighRisk" || status === "Dangerous") {
      return true;
    }

    if (status === "LimitedTrustData") {
      return hasRiskyLimitedTrustSignals(summary);
    }

    return false;
  }

  /**
   * Detects LimitedTrustData cases that deserve a banner using privacy-safe structural facts only.
   * The content script does not read or store page text, form values, passwords, tokens, or cookies.
   */
  function hasRiskyLimitedTrustSignals(summary = {}) {
    return summary.loginFormsDetected > 0 ||
      summary.passwordFieldsDetected > 0 ||
      summary.paymentFieldsDetected > 0 ||
      summary.executableDownloadCandidates > 0 ||
      summary.suspiciousRedirects > 0 ||
      summary.containsPhishingWording === true ||
      summary.containsScamWording === true ||
      summary.containsImpersonationWording === true ||
      summary.knownRiskyProviderEvidence === true ||
      summary.trustedDomainRiskMismatch === true ||
      summary.riskyUserGeneratedContent === true;
  }

  /**
   * Adds concise banner copy based on status and structural risk facts.
   */
  function withBannerCopy(lookup, summary = {}) {
    if (lookup.status === "Dangerous" || lookup.status === "Critical") {
      return {
        ...lookup,
        bannerTitle: "HIP Warning: Dangerous Site",
        bannerReason: "HIP found strong phishing or malware indicators. Avoid entering passwords or downloading files."
      };
    }

    if (lookup.status === "HighRisk") {
      return {
        ...lookup,
        bannerTitle: "HIP Warning: This page may be risky.",
        bannerReason: lookup.knownRisks?.[0] || lookup.explanations?.[0] || "HIP found high-risk signals on this page."
      };
    }

    if (lookup.status === "Suspicious") {
      return {
        ...lookup,
        bannerTitle: "HIP Notice: This page may need review.",
        bannerReason: lookup.knownRisks?.[0] || lookup.explanations?.[0] || "HIP found signals that should be reviewed before you trust this page."
      };
    }

    if (lookup.status === "LimitedTrustData" && hasRiskyLimitedTrustSignals(summary)) {
      const limitedReason = limitedTrustBannerReason(summary);
      return {
        ...lookup,
        bannerTitle: limitedReason === "This page has limited trust data and contains login fields."
          ? "HIP Notice: This page has limited trust data and contains login fields."
          : "HIP Notice: This page may need review.",
        bannerReason: limitedReason
      };
    }

    return lookup;
  }

  /**
   * Explains why a LimitedTrustData page is being interrupted without exposing private page content.
   */
  function limitedTrustBannerReason(summary = {}) {
    if (summary.paymentFieldsDetected > 0) {
      return "This page has limited trust data and contains payment fields.";
    }

    if (summary.loginFormsDetected > 0 || summary.passwordFieldsDetected > 0) {
      return "This page has limited trust data and contains login fields.";
    }

    if (summary.executableDownloadCandidates > 0) {
      return "This page has limited trust data and links to an executable download.";
    }

    if (summary.suspiciousRedirects > 0) {
      return "This page has limited trust data and suspicious redirect signals.";
    }

    if (summary.containsPhishingWording || summary.containsScamWording) {
      return "This page has limited trust data and contains scam or phishing signals.";
    }

    if (summary.containsImpersonationWording) {
      return "This page has limited trust data and contains impersonation signals.";
    }

    if (summary.knownRiskyProviderEvidence) {
      return "This page has limited trust data and a configured safety provider reported risky evidence.";
    }

    if (summary.trustedDomainRiskMismatch) {
      return "The parent domain has trust signals, but this page has risky content signals.";
    }

    return "This page has limited trust data and risky page behavior.";
  }

  /**
   * Saves banner dismissal in extension-owned storage so websites cannot forge HIP trust decisions.
   * Dismissal is page-scoped by URL hash and does not hide warnings on other pages.
   */
  async function dismissTrustBanner(lookup, pageKey) {
    await chrome.runtime.sendMessage({
      type: "HIP_SET_BANNER_DISMISSED",
      domain: lookup?.domain || currentDomain,
      pageKey
    });
  }

  function emptySummary() {
    return {
      apiStatus: "Checking",
      website: null,
      linksScanned: 0,
      riskyLinks: 0,
      suspiciousLinks: 0,
      dangerousLinks: 0,
      unknownLinks: 0,
      downloadCandidates: 0,
      executableDownloadCandidates: 0,
      downloadLinks: [],
      shortenedLinkCandidates: 0,
      obfuscatedLinkCandidates: 0,
      redirectCandidates: 0,
      redirectSignals: [],
      formsDetected: 0,
      loginFormsDetected: 0,
      passwordFieldsDetected: 0,
      paymentFieldsDetected: 0,
      crossDomainLoginForms: 0,
      socialLinkCandidates: 0,
      webmailLinkCandidates: 0,
      inlineScriptCount: 0,
      externalScriptUrls: [],
      suspiciousScriptPatternCount: 0,
      siteSafetyStatus: "Pending",
      siteSafetyDataSource: "Pending",
      siteSafetyScannedAtUtc: null,
      siteSafetyError: null,
      domainTrustScore: null,
      pageTrustScore: null,
      contentRiskScore: null,
      finalHipScore: null,
      confidenceLevel: "Unknown",
      providerEvidenceCount: 0,
      scanResultSubmission: "Pending",
      scanResultDataSource: "Pending",
      scanStage: "Pending",
      lastSubmittedUtc: null,
      lastScanUtc: null,
      updatedAt: null,
      scanResultError: null,
      pageUrlHash: null,
      isHttps: window.location.protocol === "https:",
      pluginVersion
    };
  }

  async function sha256(value) {
    const encoded = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    return `sha256:${Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
  }
})();
