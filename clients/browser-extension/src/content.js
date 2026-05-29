(function runHipContentScript() {
  const riskyStatuses = new Set(["HighRisk", "Dangerous", "Critical"]);
  const attentionStatuses = new Set(["Unknown", "Caution", "HighRisk", "Dangerous", "Critical"]);
  const ignoredProtocols = new Set(["javascript:", "mailto:", "tel:", "data:", "blob:"]);
  const downloadExtensions = new Set([".exe", ".zip", ".msi", ".dmg", ".pdf", ".docx", ".scr"]);
  const reportedDomains = new Set();

  const currentDomain = normalizeHost(window.location.hostname);
  let settings = null;
  let lastSummary = emptySummary();

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

  async function initialize() {
    settings = await loadSettings();
    lastSummary = emptySummary();
    const currentLookup = await lookupDomain(currentDomain);
    lastSummary.website = compactLookup(currentLookup);
    lastSummary.apiStatus = currentLookup ? "Available" : "Unavailable";

    if (settings.enableWarningBanner && currentLookup?.status && riskyStatuses.has(currentLookup.status)) {
      window.HipRiskBadgeRenderer.renderWarningBanner(withLookupUrl(currentLookup));
    }

    await scanLinks();
    await scanLoginForms();
    publishSummary();
  }

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

    for (const [domain, items] of anchorsByDomain) {
      const lookup = await lookupDomain(domain);
      if (!lookup?.status) {
        lastSummary.apiStatus = "Unavailable";
        continue;
      }

      if (lookup.status === "Unknown") {
        lastSummary.unknownLinks += items.length;
      }
      if (riskyStatuses.has(lookup.status)) {
        lastSummary.riskyLinks += items.length;
      }

      for (const item of items) {
        applyLinkProtection(item.anchor, item.target, withLookupUrl(lookup));
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
      const lookup = await lookupDomain(actionDomain);
      if (lookup?.status && attentionStatuses.has(lookup.status)) {
        window.HipRiskBadgeRenderer.renderFormIndicator(form, lookup, "Login form submits to a different domain. HIP checked the action domain only; no form values were read.");
      }
    }
  }

  function applyLinkProtection(anchor, target, lookup) {
    const status = lookup.status;
    const verified = lookup.verificationStatus === "Verified" || lookup.signedIdentityStatus === "PostQuantumSignaturePresent";
    const shouldBadge = shouldRenderBadge(status, verified, target.isDownloadCandidate);

    if (settings.enableLinkBadges && shouldBadge) {
      const badgeStatus = target.isDownloadCandidate && !riskyStatuses.has(status) ? "Caution" : (verified && status === "Trusted" ? "Verified" : status);
      const badgeLookup = target.isDownloadCandidate
        ? { ...lookup, knownRisks: ["Download risk candidate"], finalHipScore: lookup.finalHipScore }
        : lookup;
      window.HipRiskBadgeRenderer.renderLinkBadge(anchor, badgeStatus, badgeLookup);
    }

    if (settings.enableSafetyRouting && riskyStatuses.has(status) && anchor.dataset.hipSafetyBound !== "true") {
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

  async function lookupDomain(domain) {
    const response = await chrome.runtime.sendMessage({ type: "HIP_LOOKUP_DOMAIN", domain });
    if (!response?.ok) {
      console.warn("HIP unavailable for domain lookup.", domain, response?.error);
      return null;
    }

    return response.result;
  }

  async function loadSettings() {
    const response = await chrome.runtime.sendMessage({ type: "HIP_GET_SETTINGS" });
    return response?.ok ? response.result : {
      enableLinkBadges: true,
      enableWarningBanner: true,
      enableSafetyRouting: true,
      scanMode: "Normal"
    };
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
      publicLookupUrl: lookup.publicLookupUrl || `https://localhost:7053/lookup/domain/${encodeURIComponent(lookup.domain)}`
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

  function emptySummary() {
    return {
      apiStatus: "Checking",
      website: null,
      linksScanned: 0,
      riskyLinks: 0,
      unknownLinks: 0,
      downloadCandidates: 0,
      formsDetected: 0,
      loginFormsDetected: 0,
      crossDomainLoginForms: 0,
      socialLinkCandidates: 0,
      webmailLinkCandidates: 0
    };
  }

  async function sha256(value) {
    const encoded = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    return `sha256:${Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
  }
})();
