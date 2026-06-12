export const HIP_CONFIG = Object.freeze({
  apiBaseUrl: "http://localhost:5099",
  webBaseUrl: "http://localhost:5123"
});

export const HIP_EXTENSION_CHANNEL = "dev";

export const HIP_FETCH_TIMEOUT_MS = 8000;

export const REPUTATION_FEEDBACK_ENUMS = Object.freeze({
  targetType: Object.freeze({
    Website: 5
  }),
  eventType: Object.freeze({
    PositiveReport: 0,
    SuspiciousReport: 2
  }),
  severity: Object.freeze({
    Low: 0,
    Medium: 1,
    High: 2
  }),
  reporterTrustLevel: Object.freeze({
    Anonymous: 0
  })
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
  allowRawPageUrlSubmission: false,
  scanMode: "Normal",
  bannerDisplayMode: "WarningsOnly",
  externalProvidersEnabled: true,
  sslLabsEnabled: true,
  googleWebRiskEnabled: false,
  virusTotalEnabled: false,
  instanceId: null
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
    const response = await fetchWithTimeout(url, {
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
    const response = await fetchWithTimeout(url, {
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
    const response = await fetchWithTimeout(url, {
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

  /**
   * Runs HIP's Site Safety Scan for the current page URL.
   * The request sends only the URL and optional privacy-safe observations; it never sends page text or form values.
   */
  async scanSiteSafety(request) {
    const payload = {
      url: request?.url || "",
      observedSignals: request?.observedSignals || null,
      pluginVersion: request?.pluginVersion || null
    };
    const apiUrl = `${this.config.apiBaseUrl}/api/v1/site-safety/scan`;
    const apiResponse = await this.postJson(apiUrl, payload);

    if (apiResponse.ok) {
      return apiResponse.json();
    }

    const webUrl = `${this.config.webBaseUrl}/api/v1/site-safety/scan`;
    if (apiResponse.status === 404 && normalizeHost(this.config.webBaseUrl) !== normalizeHost(this.config.apiBaseUrl)) {
      const webResponse = await this.postJson(webUrl, payload);
      if (webResponse.ok) {
        return webResponse.json();
      }

      throw new Error(`HIP site safety scan failed with API status ${apiResponse.status} and Web status ${webResponse.status}.`);
    }

    throw new Error(`HIP site safety scan failed with status ${apiResponse.status}.`);
  }

  /**
   * Sends a JSON POST without including private page text or form values.
   */
  async postJson(url, payload) {
    return fetchWithTimeout(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        ...this.instanceHeaders()
      },
      body: JSON.stringify(payload)
    });
  }

  /**
   * Builds per-instance request headers so HIP can apply the right provider settings during scans.
   * The value is a random extension-install identifier, not a user name or browsing-history identifier.
   */
  instanceHeaders() {
    return this.config.instanceId
      ? { "X-HIP-Instance-Id": this.config.instanceId }
      : {};
  }

  /**
   * Builds a privacy-safe Site Safety Scan request from the popup and content-script summary.
   * Only counts and URL lists needed for file-extension checks are included; page body text is excluded.
   */
  buildSiteSafetyRequest(pageUrl, summary = {}) {
    return {
      url: pageUrl,
      pluginVersion: summary.pluginVersion || null,
      observedSignals: {
        downloadLinks: Array.isArray(summary.downloadLinks) ? summary.downloadLinks : [],
        hasLoginForm: (summary.loginFormsDetected ?? 0) > 0,
        hasPasswordField: (summary.passwordFieldsDetected ?? summary.loginFormsDetected ?? 0) > 0,
        hasPaymentField: (summary.paymentFieldsDetected ?? 0) > 0,
        inlineScriptCount: summary.inlineScriptCount ?? 0,
        externalScriptUrls: Array.isArray(summary.externalScriptUrls) ? summary.externalScriptUrls : [],
        suspiciousScriptPatternCount: summary.suspiciousScriptPatternCount ?? 0,
        trustDataAvailable: summary.scanResultDataSource === "BrowserPluginScan",
        shortenedLinkCount: summary.shortenedLinkCandidates ?? 0,
        obfuscatedLinkCount: summary.obfuscatedLinkCandidates ?? 0,
        redirectChain: Array.isArray(summary.redirectSignals) ? summary.redirectSignals : []
      }
    };
  }

  async reportRiskFinding(report) {
    const url = `${this.config.apiBaseUrl}/api/v1/public/risk-findings`;
    const response = await fetchWithTimeout(url, {
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
   * Submits weighted public site feedback through the reputation feedback endpoint.
   * This is separate from risk findings so "Looks Safe" feedback is accepted as weak trust evidence,
   * not misclassified as a threat report.
   */
  async submitSiteFeedback(feedback) {
    const url = `${this.config.apiBaseUrl}/api/v1/public/feedback`;
    const response = await fetchWithTimeout(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        ...this.instanceHeaders()
      },
      body: JSON.stringify(feedback)
    });

    if (response.status === 409) {
      return {
        accepted: true,
        duplicateSuppressed: true,
        message: "Duplicate feedback submission already accepted recently."
      };
    }

    if (!response.ok) {
      throw new Error(`HIP site feedback failed with status ${response.status}.`);
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
    const response = await fetchWithTimeout(url, {
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

  /**
   * Loads the HIP server-side external provider settings for the dev/MVP options page.
   * The endpoint is admin-protected on the HIP side, so callers must handle authorization failures safely.
   */
  async getExternalProviderSettings() {
    const url = `${this.config.apiBaseUrl}/api/v1/site-safety/external-providers`;
    const response = await fetchWithTimeout(url, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        ...this.instanceHeaders()
      }
    });

    if (!response.ok) {
      throw new Error(`HIP provider settings lookup failed with status ${response.status}.`);
    }

    return response.json();
  }

  /**
   * Updates HIP server-side external provider settings using the complete safe settings document.
   * The browser extension sends only provider configuration flags and never sends page text or form values.
   */
  async updateExternalProviderSettings(settings) {
    const url = `${this.config.apiBaseUrl}/api/v1/site-safety/external-providers`;
    const response = await fetchWithTimeout(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        ...this.instanceHeaders()
      },
      body: JSON.stringify(settings)
    });

    if (!response.ok) {
      throw new Error(`HIP provider settings update failed with status ${response.status}.`);
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

/**
 * Calls fetch with a bounded timeout so extension pages do not sit in a loading state indefinitely.
 * The timeout failure is intentionally generic because request details may include local dev ports.
 */
export async function fetchWithTimeout(url, options = {}, timeoutMs = HIP_FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: options.signal || controller.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("HIP request timed out.");
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function loadHipSettings() {
  if (!globalThis.chrome?.storage?.sync) {
    return normalizeHipSettings({
      ...DEFAULT_HIP_SETTINGS,
      instanceId: createInstanceId()
    });
  }

  const stored = await chrome.storage.sync.get(DEFAULT_HIP_SETTINGS);
  const settings = normalizeHipSettings({
    ...DEFAULT_HIP_SETTINGS,
    ...stored
  });

  if (!settings.instanceId) {
    settings.instanceId = createInstanceId();
    await chrome.storage.sync.set({ instanceId: settings.instanceId });
  }

  return settings;
}

export async function saveHipSettings(settings) {
  const existing = globalThis.chrome?.storage?.sync && !settings.instanceId
    ? await chrome.storage.sync.get({ instanceId: null })
    : {};
  const normalized = normalizeHipSettings({
    ...DEFAULT_HIP_SETTINGS,
    ...existing,
    ...settings
  });

  if (!normalized.instanceId) {
    normalized.instanceId = createInstanceId();
  }

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
    scanMode: settings.scanMode || "Normal",
    bannerDisplayMode: normalizeBannerDisplayMode(settings.bannerDisplayMode),
    externalProvidersEnabled: settings.externalProvidersEnabled ?? true,
    sslLabsEnabled: settings.sslLabsEnabled ?? true,
    googleWebRiskEnabled: settings.googleWebRiskEnabled ?? false,
    virusTotalEnabled: settings.virusTotalEnabled ?? false,
    instanceId: typeof settings.instanceId === "string" && settings.instanceId.trim()
      ? settings.instanceId.trim()
      : null
  };
}

/**
 * Creates a stable random extension instance identifier for per-instance server preferences.
 * This is intentionally not derived from the browser profile, user name, tab URL, or page content.
 */
export function createInstanceId() {
  const random = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) {
    crypto.getRandomValues(random);
  } else {
    for (let index = 0; index < random.length; index += 1) {
      random[index] = Math.floor(Math.random() * 256);
    }
  }

  return `hip-ext-${Array.from(random).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Decides whether the page-level HIP banner should show.
 * The popup remains the default details surface; banners are reserved for meaningful user-facing risk.
 */
export function shouldShowTrustBanner(lookup, summary = {}, settings = {}) {
  const mode = normalizeBannerDisplayMode(settings.bannerDisplayMode);
  if (mode === "NeverShow" || settings.enableWarningBanner === false) {
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
 * Detects the special LimitedTrustData cases that justify interrupting the user.
 * These checks use only structural counts and labels, never page text, form values, passwords, or tokens.
 */
export function hasRiskyLimitedTrustSignals(summary = {}) {
  return (summary.loginFormsDetected ?? 0) > 0 ||
    (summary.passwordFieldsDetected ?? 0) > 0 ||
    (summary.paymentFieldsDetected ?? 0) > 0 ||
    (summary.executableDownloadCandidates ?? 0) > 0 ||
    (summary.suspiciousRedirects ?? 0) > 0 ||
    (summary.containsPhishingWording ?? false) === true ||
    (summary.containsScamWording ?? false) === true ||
    (summary.containsImpersonationWording ?? false) === true ||
    (summary.knownRiskyProviderEvidence ?? false) === true ||
    (summary.trustedDomainRiskMismatch ?? false) === true ||
    (summary.riskyUserGeneratedContent ?? false) === true;
}

/**
 * Normalizes future banner display settings so older extension installs default to warnings only.
 */
export function normalizeBannerDisplayMode(value) {
  return ["WarningsOnly", "DangerousOnly", "AlwaysShow", "NeverShow"].includes(value)
    ? value
    : "WarningsOnly";
}

/**
 * Formats the extension version shown in dev/MVP surfaces.
 * The raw version should come from manifest.json through chrome.runtime.getManifest().
 */
export function formatPluginVersion(manifestVersion, channel = HIP_EXTENSION_CHANNEL) {
  const version = manifestVersion || "unknown";
  return `HIP Plugin v${version}-${channel}`;
}

/**
 * Builds the privacy-safe scan result payload submitted after a content scan.
 * The payload intentionally excludes page text, form values, passwords, tokens, and private messages.
 */
export function buildScanResultPayload({ domain, pageUrl, pageUrlHash = null, lookup, summary = {}, settings = {}, pluginVersion = null, submittedAtUtc = new Date().toISOString() }) {
  const assessment = browserScanAssessment(lookup, summary);
  const status = assessment.status;
  return {
    domain,
    pageUrl: settings.allowRawPageUrlSubmission === true ? stripQueryAndFragment(pageUrl) : null,
    pageUrlHash,
    pluginVersion,
    score: assessment.score,
    riskLevel: status,
    status,
    reasons: assessment.reasons,
    linksScanned: summary.linksScanned ?? 0,
    riskyLinksFound: summary.riskyLinks ?? 0,
    suspiciousLinksFound: summary.suspiciousLinks ?? 0,
    dangerousLinksFound: summary.dangerousLinks ?? 0,
    recommendedAction: recommendedSiteAction(status),
    privacySafeMetadata: {
      scanMode: settings.scanMode || "Normal",
      apiStatus: summary.apiStatus || "Unknown",
      scanTimestampUtc: submittedAtUtc,
      isHttps: String(summary.isHttps === true),
      downloadCandidates: String(summary.downloadCandidates ?? 0),
      executableDownloadCandidates: String(summary.executableDownloadCandidates ?? 0),
      formsDetected: String(summary.formsDetected ?? 0),
      loginFormsDetected: String(summary.loginFormsDetected ?? 0),
      passwordFieldsDetected: String(summary.passwordFieldsDetected ?? 0),
      paymentFieldsDetected: String(summary.paymentFieldsDetected ?? 0),
      crossDomainLoginForms: String(summary.crossDomainLoginForms ?? 0),
      shortenedLinkCandidates: String(summary.shortenedLinkCandidates ?? 0),
      obfuscatedLinkCandidates: String(summary.obfuscatedLinkCandidates ?? 0),
      redirectCandidates: String(summary.redirectCandidates ?? 0),
      socialLinkCandidates: String(summary.socialLinkCandidates ?? 0),
      webmailLinkCandidates: String(summary.webmailLinkCandidates ?? 0),
      pluginVersion: pluginVersion || summary.pluginVersion || "Unknown"
    }
  };
}

/**
 * Removes query strings and fragments from optional raw URLs before any explicit submission.
 * Normal scan submissions send only pageUrlHash; this helper protects future opt-in raw URL diagnostics.
 */
export function stripQueryAndFragment(pageUrl) {
  if (!pageUrl) {
    return null;
  }

  try {
    const url = new URL(pageUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }

    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Builds the privacy-safe feedback request submitted by the injected trust banner.
 * Feedback is trust evidence, not a raw vote; HIP weights anonymous browser feedback conservatively server-side.
 */
export async function buildBannerFeedbackReport({ feedbackType, domain, pageUrl, lookup = {}, settings = {}, reportedAtUtc = new Date().toISOString(), hashUrl = defaultSha256 }) {
  return buildSiteFeedbackRequest({
    feedbackType,
    domain,
    pageUrl,
    source: "BrowserPluginBanner",
    lookup,
    settings,
    reportedAtUtc,
    hashUrl
  });
}

/**
 * Builds the privacy-safe feedback request used by popup and banner controls.
 * The payload matches HIP's public reputation feedback contract and intentionally excludes raw page text,
 * form values, cookies, tokens, passwords, and full URLs.
 */
export async function buildSiteFeedbackRequest({ feedbackType, domain, pageUrl, source = "BrowserPluginPopup", lookup = {}, settings = {}, reportedAtUtc = new Date().toISOString(), hashUrl = defaultSha256 }) {
  const normalizedFeedbackType = normalizeFeedbackType(feedbackType);
  const looksSafe = normalizedFeedbackType === "LooksSafe";
  const reportIssue = normalizedFeedbackType === "ReportIssue";
  const severity = looksSafe
    ? REPUTATION_FEEDBACK_ENUMS.severity.Low
    : reportIssue
      ? REPUTATION_FEEDBACK_ENUMS.severity.High
      : REPUTATION_FEEDBACK_ENUMS.severity.Medium;

  return {
    targetType: REPUTATION_FEEDBACK_ENUMS.targetType.Website,
    targetId: domain,
    eventType: looksSafe ? REPUTATION_FEEDBACK_ENUMS.eventType.PositiveReport : REPUTATION_FEEDBACK_ENUMS.eventType.SuspiciousReport,
    severity,
    reporterTrustLevel: REPUTATION_FEEDBACK_ENUMS.reporterTrustLevel.Anonymous,
    reason: looksSafe
      ? "Browser plugin feedback: user reported the site looks safe."
      : reportIssue
        ? "Browser plugin feedback: user reported an issue with this site."
        : "Browser plugin feedback: user reported the site looks suspicious.",
    platform: "Web",
    urlHash: await hashUrl(pageUrl),
    metadata: {
      source,
      feedbackType: normalizedFeedbackType,
      domain,
      displayedStatus: lookup?.status || "Unknown",
      displayedScore: String(lookup?.finalHipScore ?? lookup?.score ?? "Unknown"),
      scanMode: settings.scanMode || "Normal",
      reportedAtUtc
    },
  };
}

/**
 * Normalizes trusted feedback button values so unexpected UI labels cannot create arbitrary event types.
 */
export function normalizeFeedbackType(feedbackType) {
  return ["LooksSafe", "LooksSuspicious", "ReportIssue"].includes(feedbackType)
    ? feedbackType
    : "LooksSuspicious";
}

/**
 * Converts scan counts into a useful browser-plugin score when public lookup has no prior stored data.
 * This prevents the first successful scan from persisting HIP's bootstrap "not scanned yet" state as real data.
 */
export function browserScanAssessment(lookup, summary = {}) {
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
  const status = browserScanStatus(score, dangerousLinks, suspiciousLinks, riskyLinks, unknownLinks);

  return {
    score,
    status,
    reasons: browserScanReasons({ linksScanned, riskyLinks, suspiciousLinks, dangerousLinks, unknownLinks, downloadCandidates })
  };
}

export function normalizeHost(hostname) {
  return (hostname || "").replace(/^www\./i, "").toLowerCase();
}

/**
 * Detects pages owned by the configured HIP API or HIP Web app.
 * The browser extension should not recursively scan HIP's own UI because that creates noisy localhost errors
 * and does not produce useful trust evidence about third-party sites.
 */
export function isHipOwnedPageUrl(pageUrl, settings = {}) {
  try {
    const normalizedSettings = normalizeHipSettings(settings);
    const pageOrigin = new URL(pageUrl).origin;
    const hipOrigins = [
      normalizedSettings.apiBaseUrl,
      normalizedSettings.webBaseUrl
    ]
      .filter(Boolean)
      .map(value => new URL(value).origin);

    return hipOrigins.includes(pageOrigin);
  } catch {
    return false;
  }
}

export function statusNeedsAttention(status) {
  return ["Unknown", "LimitedTrustData", "Caution", "Suspicious", "HighRisk", "Dangerous", "Critical"].includes(status);
}

export function statusNeedsSafetyRoute(status) {
  return ["Suspicious", "HighRisk", "Dangerous", "Critical"].includes(status);
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
 * Detects HIP's explicit no-data lookup state so scan persistence can store the scan's own findings.
 */
function isLookupNoDataState(lookup) {
  const reasons = [...(lookup?.knownRisks || []), ...(lookup?.explanations || []), ...(lookup?.reasons || [])];
  return !lookup ||
    lookup.dataSource === "NoStoredData" ||
    reasons.some(reason => typeof reason === "string" && reason.includes("HIP has not scanned this domain yet"));
}

/**
 * Maps privacy-safe browser scan counts to a status without claiming full real-world safety.
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
 * Builds plain-English scan reasons from counts and excludes page body text, form values, and private content.
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
 * Maps website status to the persisted action summary used by HIP lookup and dashboards.
 */
function recommendedSiteAction(status) {
  if (statusNeedsSafetyRoute(status)) {
    return "RouteToSafetyPage";
  }

  if (status === "Unknown" || status === "LimitedTrustData" || status === "Caution") {
    return "ShowCaution";
  }

  return "Allow";
}

/**
 * Hashes URLs before report submission so full browsing paths are not required in feedback payloads.
 */
async function defaultSha256(value) {
  const encoded = new TextEncoder().encode(value || "");
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return `sha256:${Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
}
