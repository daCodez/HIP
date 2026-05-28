export const HIP_CONFIG = Object.freeze({
  apiBaseUrl: "https://localhost:7257",
  webBaseUrl: "https://localhost:7053"
});

export class HipApiClient {
  constructor(config = HIP_CONFIG) {
    this.config = config;
  }

  async lookupDomain(domain) {
    if (!domain) {
      throw new Error("Domain is required.");
    }

    const url = `${this.config.apiBaseUrl}/api/public/lookup/domain/${encodeURIComponent(domain)}`;
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

  safetyPageUrl(originalUrl, sourceDomain, riskStatus) {
    const url = new URL("/safety", this.config.webBaseUrl);
    url.searchParams.set("url", originalUrl);

    if (sourceDomain) {
      url.searchParams.set("source", sourceDomain);
    }

    if (riskStatus) {
      url.searchParams.set("risk", riskStatus);
    }

    return url.toString();
  }
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

export function isVerifiedStatus(lookup) {
  return lookup?.verificationStatus === "Verified" || lookup?.signedIdentityStatus === "PostQuantumSignaturePresent";
}
