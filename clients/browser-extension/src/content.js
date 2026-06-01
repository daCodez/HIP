(function runHipContentScript() {
  const riskyStatuses = new Set(["HighRisk", "Dangerous", "Critical"]);
  const attentionStatuses = new Set(["Unknown", "Caution", "HighRisk", "Dangerous", "Critical"]);
  const ignoredProtocols = new Set(["javascript:", "mailto:", "tel:", "data:", "blob:"]);
  const downloadExtensions = new Set([".exe", ".zip", ".msi", ".dmg", ".pdf", ".docx", ".scr"]);
  const reportedDomains = new Set();

  const currentDomain = normalizeHost(window.location.hostname);
  let settings = null;
  let lastSummary = emptySummary();
  let pluginVersion = "HIP Plugin vunknown-dev";

  if (!currentDomain) {
    return;
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "HIP_REFRESH_SCAN") {
      initialize()
        .then(() => sendResponse({ ok: true, result: lastSummary }))
        .catch(error => sendResponse({ ok: false, error: error.message }));
      return true;
    }

    if (message?.type === "HIP_GET_CONTENT_SUMMARY") {
      sendResponse({ ok: true, result: lastSummary });
      return false;
    }

    return false;
  });

  initialize().catch(error => console.warn("HIP content script failed safely.", error));

  /**
   * Runs the privacy-safe page scan and publishes a summary for the popup.
   */
  async function initialize() {
    settings = await loadSettings();
    pluginVersion = await loadPluginVersion();
    lastSummary = emptySummary();
    const currentLookup = await scoreSite(currentDomain, window.location.href);
    lastSummary.website = compactLookup(currentLookup);
    lastSummary.apiStatus = currentLookup ? "Available" : "Unavailable";

    if (settings.enableWarningBanner && currentLookup?.status) {
      window.HipRiskBadgeRenderer.renderTrustBanner(withLookupUrl(currentLookup), pluginVersion);
    }

    if (settings.enableLinkScanning) {
      await scanLinks();
    }

    await scanLoginForms();
    await persistScanResult(currentLookup).catch(error => console.warn("HIP scan result persistence failed safely.", error));
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
        if (lookup.status === "HighRisk") {
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

  function applyLinkProtection(anchor, target, lookup, browserResult = null) {
    const status = lookup.status;
    const verified = lookup.verificationStatus === "Verified" || lookup.signedIdentityStatus === "PostQuantumSignaturePresent";
    const shouldBadge = browserResult?.requiresIcon || shouldRenderBadge(status, verified, target.isDownloadCandidate);

    if (settings.showRiskyLinkIcons && shouldBadge) {
      const badgeStatus = browserResult?.label || (target.isDownloadCandidate && !riskyStatuses.has(status) ? "Caution" : (verified && status === "Trusted" ? "Verified" : status));
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
    const assessment = browserScanAssessment(currentLookup, lastSummary);
    const payload = {
      domain: currentDomain,
      pageUrl: window.location.href,
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
        downloadCandidates: String(lastSummary.downloadCandidates),
        formsDetected: String(lastSummary.formsDetected),
        loginFormsDetected: String(lastSummary.loginFormsDetected),
        crossDomainLoginForms: String(lastSummary.crossDomainLoginForms),
        socialLinkCandidates: String(lastSummary.socialLinkCandidates),
        webmailLinkCandidates: String(lastSummary.webmailLinkCandidates)
      }
    };

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
      scanMode: "Normal"
    };
  }

  /**
   * Loads the dev/MVP extension version through the background worker.
   * The background worker reads manifest.json, so content scripts do not hardcode version strings.
   */
  async function loadPluginVersion() {
    const response = await chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" });
    return response?.ok ? response.result : "HIP Plugin vunknown-dev";
  }

  function publishSummary() {
    chrome.runtime.sendMessage({ type: "HIP_SCAN_SUMMARY", summary: lastSummary }).catch(() => {});
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
      return "HighRisk";
    }

    if (unknownLinks > 0 || score <= 60) {
      return "Caution";
    }

    return "ProbablySafe";
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

    if (status === "Unknown" || status === "Caution") {
      return "ShowLabel";
    }

    return "Allow";
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
      formsDetected: 0,
      loginFormsDetected: 0,
      crossDomainLoginForms: 0,
      socialLinkCandidates: 0,
      webmailLinkCandidates: 0,
      scanResultSubmission: "Pending",
      scanResultDataSource: "Pending",
      lastSubmittedUtc: null,
      scanResultError: null
    };
  }

  async function sha256(value) {
    const encoded = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    return `sha256:${Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
  }
})();
