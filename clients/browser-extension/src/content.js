(function runHipContentScript() {
  const riskyStatuses = new Set(["HighRisk", "Dangerous", "Critical"]);
  const attentionStatuses = new Set(["Unknown", "Caution", "HighRisk", "Dangerous", "Critical"]);
  const ignoredProtocols = new Set(["javascript:", "mailto:", "tel:", "data:", "blob:"]);
  const reportedDomains = new Set();

  const currentDomain = normalizeHost(window.location.hostname);
  if (!currentDomain) {
    return;
  }

  initialize().catch(error => console.warn("HIP content script failed safely.", error));

  async function initialize() {
    const currentLookup = await lookupDomain(currentDomain);
    if (currentLookup?.status && riskyStatuses.has(currentLookup.status)) {
      window.HipRiskBadgeRenderer.renderWarningBanner(withLookupUrl(currentLookup));
    }

    await scanLinks();
  }

  async function scanLinks() {
    const anchorsByDomain = new Map();

    for (const anchor of document.querySelectorAll("a[href]")) {
      const target = parseTarget(anchor);
      if (!target || target.domain === currentDomain) {
        continue;
      }

      if (!anchorsByDomain.has(target.domain)) {
        anchorsByDomain.set(target.domain, []);
      }

      anchorsByDomain.get(target.domain).push(anchor);
    }

    for (const [domain, anchors] of anchorsByDomain) {
      const lookup = await lookupDomain(domain);
      if (!lookup?.status) {
        continue;
      }

      for (const anchor of anchors) {
        applyLinkProtection(anchor, withLookupUrl(lookup));
      }
    }
  }

  function applyLinkProtection(anchor, lookup) {
    const status = lookup.status;
    const verified = lookup.verificationStatus === "Verified" || lookup.signedIdentityStatus === "PostQuantumSignaturePresent";

    if (verified && status === "Trusted") {
      window.HipRiskBadgeRenderer.renderLinkBadge(anchor, "Verified", lookup);
      return;
    }

    if (attentionStatuses.has(status)) {
      window.HipRiskBadgeRenderer.renderLinkBadge(anchor, status, lookup);
    }

    if (riskyStatuses.has(status) && anchor.dataset.hipSafetyBound !== "true") {
      anchor.addEventListener("click", event =>
        window.HipSafetyPageRouter.routeClick(event, anchor, lookup, currentDomain), true);
      anchor.dataset.hipSafetyBound = "true";
      reportRiskFinding(anchor, lookup).catch(error => console.warn("HIP reporting failed safely.", error));
    }
  }

  async function reportRiskFinding(anchor, lookup) {
    if (reportedDomains.has(lookup.domain)) {
      return;
    }

    reportedDomains.add(lookup.domain);
    const targetUrl = new URL(anchor.href, window.location.href);
    const report = {
      reportId: "",
      sourceClient: "BrowserPlugin",
      platform: "Web",
      targetType: "Url",
      domain: lookup.domain,
      urlHash: await sha256(targetUrl.href),
      originalUrl: null,
      senderHash: null,
      riskLevel: lookup.status,
      reason: lookup.explanations?.[0] || lookup.knownRisks?.[0] || "HIP detected a risky link on the current page.",
      detectedAtUtc: new Date().toISOString(),
      reporterTrustLevel: "Medium",
      privacySafeEvidence: {
        evidenceType: "browser-link-risk",
        summary: "Browser plugin reported a risky link domain without page body text.",
        facts: {
          sourceDomain: currentDomain,
          targetDomain: lookup.domain
        },
        containsPrivateContent: false
      },
      hipSignature: "browser-plugin-signature-placeholder"
    };

    await chrome.runtime.sendMessage({ type: "HIP_REPORT_RISK_FINDING", report });
  }

  async function sha256(value) {
    const encoded = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    return `sha256:${Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
  }

  async function lookupDomain(domain) {
    const response = await chrome.runtime.sendMessage({ type: "HIP_LOOKUP_DOMAIN", domain });
    if (!response?.ok) {
      console.warn("HIP unavailable for domain lookup.", domain, response?.error);
      return null;
    }

    return response.result;
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

  function normalizeHost(hostname) {
    return (hostname || "").replace(/^www\./i, "").toLowerCase();
  }

  function withLookupUrl(lookup) {
    return {
      ...lookup,
      publicLookupUrl: lookup.publicLookupUrl || `https://localhost:7053/lookup/domain/${encodeURIComponent(lookup.domain)}`
    };
  }
})();
