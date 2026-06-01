export const HIP_CONFIG = Object.freeze({
  apiBaseUrl: "https://localhost:7257",
  webBaseUrl: "https://localhost:7053"
});

export const DEFAULT_HIP_SETTINGS = Object.freeze({
  apiBaseUrl: HIP_CONFIG.apiBaseUrl,
  webBaseUrl: HIP_CONFIG.webBaseUrl,
  enableLinkBadges: true,
  enableWarningBanner: true,
  enableSafetyRouting: true,
  scanMode: "Normal"
});

export class HipApiClient {
  constructor(config = HIP_CONFIG) {
    this.config = config;
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
    return { ...DEFAULT_HIP_SETTINGS };
  }

  const stored = await chrome.storage.sync.get(DEFAULT_HIP_SETTINGS);
  return {
    ...DEFAULT_HIP_SETTINGS,
    ...stored
  };
}

export async function saveHipSettings(settings) {
  const normalized = {
    ...DEFAULT_HIP_SETTINGS,
    ...settings
  };
  await chrome.storage.sync.set(normalized);
  return normalized;
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
