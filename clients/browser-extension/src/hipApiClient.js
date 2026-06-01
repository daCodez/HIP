export const HIP_CONFIG = Object.freeze({
  apiBaseUrl: "https://localhost:7257",
  webBaseUrl: "https://localhost:7053"
});

export const DEFAULT_HIP_SETTINGS = Object.freeze({
  hipApiBaseUrl: HIP_CONFIG.apiBaseUrl,
  apiBaseUrl: HIP_CONFIG.apiBaseUrl,
  webBaseUrl: HIP_CONFIG.webBaseUrl,
  submitScanResults: true,
  enableLinkScanning: true,
  showRiskyLinkIcons: true,
  enableSafetyPageRouting: true,
  enableLinkBadges: true,
  enableWarningBanner: true,
  enableSafetyRouting: true,
  scanMode: "Normal"
});

export class HipApiClient {
  constructor(config = HIP_CONFIG) {
    this.config = normalizeHipSettings(config);
  }

  async lookupDomain(domain) {
    if (!domain) {
      throw new Error("Domain is required.");
    }

    const url = `${this.config.apiBaseUrl}/api/v1/public/lookup/domain/${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(`HIP lookup failed with status ${response.status}.`);
    }

    return response.json();
  }

  async scoreSite(request) {
    const url = `${this.config.apiBaseUrl}/api/v1/browser/score-site`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: request?.url || "",
        domain: request?.domain || ""
      })
    });

    if (!response.ok) {
      throw new Error(`HIP site scoring failed with status ${response.status}.`);
    }

    return response.json();
  }

  async scanLinks(pageUrl, links) {
    const url = `${this.config.apiBaseUrl}/api/v1/browser/scan-links`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        pageUrl,
        links: Array.isArray(links) ? links : []
      })
    });

    if (!response.ok) {
      throw new Error(`HIP link scanning failed with status ${response.status}.`);
    }

    return response.json();
  }

  async reportRiskFinding(report) {
    const url = `${this.config.apiBaseUrl}/api/v1/public/risk-findings`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(report)
    });

    if (!response.ok) {
      throw new Error(`HIP risk finding report failed with status ${response.status}.`);
    }

    return response.json();
  }

  /**
   * Saves the current scan summary without sending page text, form values, or private messages.
   * The HIP API hashes the page URL and keeps only privacy-safe counts and reasons.
   */
  async saveScanResult(result) {
    if (!isValidBaseUrl(this.config.apiBaseUrl)) {
      throw new Error("Invalid HIP API base URL.");
    }

    const url = `${this.config.apiBaseUrl}/api/v1/browser/scan-results`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(result)
    });

    if (!response.ok) {
      throw new Error(`HIP scan result persistence failed with status ${response.status}.`);
    }

    return response.json();
  }

  safetyPageUrl(originalUrl, sourceDomain, riskStatus) {
    const url = new URL("/safety", this.config.webBaseUrl);
    url.searchParams.set("url", originalUrl);
    url.searchParams.set("source", "browser");

    if (sourceDomain) {
      url.searchParams.set("sourceDomain", sourceDomain);
    }

    if (riskStatus) {
      url.searchParams.set("risk", riskStatus);
    }

    return url.toString();
  }
}

export async function loadHipSettings() {
  if (!globalThis.chrome?.storage?.sync) {
    return normalizeHipSettings(DEFAULT_HIP_SETTINGS);
  }

  const stored = await chrome.storage.sync.get(DEFAULT_HIP_SETTINGS);
  return normalizeHipSettings({
    ...DEFAULT_HIP_SETTINGS,
    ...stored
  });
}

export async function saveHipSettings(settings) {
  const normalized = normalizeHipSettings({
    ...DEFAULT_HIP_SETTINGS,
    ...settings
  });
  await chrome.storage.sync.set(normalized);
  return normalized;
}

/**
 * Normalizes legacy and current settings names so older installed extensions keep working.
 * `hipApiBaseUrl` is the explicit setting name, while `apiBaseUrl` remains as compatibility alias.
 */
export function normalizeHipSettings(settings = {}) {
  const apiBaseUrl = settings.hipApiBaseUrl || settings.apiBaseUrl || HIP_CONFIG.apiBaseUrl;
  const enableSafetyPageRouting = settings.enableSafetyPageRouting ?? settings.enableSafetyRouting ?? true;
  const showRiskyLinkIcons = settings.showRiskyLinkIcons ?? settings.enableLinkBadges ?? true;

  return {
    ...settings,
    hipApiBaseUrl: apiBaseUrl,
    apiBaseUrl,
    webBaseUrl: settings.webBaseUrl || HIP_CONFIG.webBaseUrl,
    submitScanResults: settings.submitScanResults ?? true,
    enableLinkScanning: settings.enableLinkScanning ?? true,
    showRiskyLinkIcons,
    enableLinkBadges: showRiskyLinkIcons,
    enableSafetyPageRouting,
    enableSafetyRouting: enableSafetyPageRouting,
    enableWarningBanner: settings.enableWarningBanner ?? true,
    scanMode: settings.scanMode || "Normal"
  };
}

/**
 * Builds the privacy-safe scan result payload submitted after a content scan.
 * The payload intentionally excludes page text, form values, passwords, tokens, and private messages.
 */
export function buildScanResultPayload({ domain, pageUrl, lookup, summary = {}, settings = {}, submittedAtUtc = new Date().toISOString() }) {
  const status = lookup?.status || "Unknown";
  return {
    domain,
    pageUrl,
    score: lookup?.finalHipScore ?? lookup?.score ?? 0,
    riskLevel: status,
    status,
    reasons: safeReasons(lookup),
    linksScanned: summary.linksScanned ?? 0,
    riskyLinksFound: summary.riskyLinks ?? 0,
    suspiciousLinksFound: summary.suspiciousLinks ?? 0,
    dangerousLinksFound: summary.dangerousLinks ?? 0,
    recommendedAction: recommendedSiteAction(status),
    privacySafeMetadata: {
      scanMode: settings.scanMode || "Normal",
      apiStatus: summary.apiStatus || "Unknown",
      scanTimestampUtc: submittedAtUtc,
      downloadCandidates: String(summary.downloadCandidates ?? 0),
      formsDetected: String(summary.formsDetected ?? 0),
      loginFormsDetected: String(summary.loginFormsDetected ?? 0),
      crossDomainLoginForms: String(summary.crossDomainLoginForms ?? 0),
      socialLinkCandidates: String(summary.socialLinkCandidates ?? 0),
      webmailLinkCandidates: String(summary.webmailLinkCandidates ?? 0)
    }
  };
}

export function normalizeHost(hostname) {
  return (hostname || "").replace(/^www\./i, "").toLowerCase();
}

export function statusNeedsAttention(status) {
  return ["Unknown", "Caution", "HighRisk", "Dangerous", "Critical"].includes(status);
}

export function statusNeedsSafetyRoute(status) {
  return ["HighRisk", "Dangerous", "Critical"].includes(status);
}

export function safeBrowserSafetyPageUrl(webBaseUrl, originalUrl, sourceDomain, riskStatus) {
  const client = new HipApiClient({ apiBaseUrl: HIP_CONFIG.apiBaseUrl, webBaseUrl });
  return client.safetyPageUrl(originalUrl, sourceDomain, riskStatus);
}

export function isVerifiedStatus(lookup) {
  return lookup?.verificationStatus === "Verified" || lookup?.signedIdentityStatus === "PostQuantumSignaturePresent";
}

/**
 * Validates a configured HIP base URL without throwing during normal settings loading.
 */
export function isValidBaseUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Selects display-safe reasons without reading or packaging page body text.
 */
function safeReasons(lookup) {
  const reasons = lookup?.knownRisks?.length ? lookup.knownRisks : lookup?.explanations || lookup?.reasons || [];
  return reasons.length > 0 ? reasons : ["No risky links found by the browser plugin scan."];
}

/**
 * Maps website status to the persisted action summary used by HIP lookup and dashboards.
 */
function recommendedSiteAction(status) {
  if (statusNeedsSafetyRoute(status)) {
    return "RouteToSafetyPage";
  }

  if (status === "Unknown" || status === "Caution") {
    return "ShowCaution";
  }

  return "Allow";
}
