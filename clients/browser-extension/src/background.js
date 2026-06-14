import { formatPluginVersion, HipApiClient, loadHipSettings, normalizeHost } from "./hipApiClient.js";

const lookupCache = new Map();
const scanSummaries = new Map();
const pendingScanResultSaves = new Set();
const cacheTtlMs = 5 * 60 * 1000;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "HIP_GET_PLUGIN_VERSION") {
    sendResponse({ ok: true, result: getPluginVersion() });
    return false;
  }

  if (message?.type === "HIP_GET_SETTINGS") {
    loadHipSettings()
      .then(settings => sendResponse({ ok: true, result: settings }))
      .catch(error => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  if (message?.type === "HIP_GET_BANNER_DISMISSED") {
    isBannerDismissed(message.domain, message.pageKey)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  if (message?.type === "HIP_SET_BANNER_DISMISSED") {
    setBannerDismissed(message.domain, message.pageKey)
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  if (message?.type === "HIP_LOOKUP_DOMAIN") {
    lookupDomain(message.domain)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP lookup unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCORE_SITE") {
    scoreSite(message.request)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP site score unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCAN_LINKS") {
    scanLinks(message.pageUrl, message.links)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP link scan unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCAN_SITE_SAFETY") {
    scanSiteSafety(message.request)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        sendResponse({ ok: false, error: safeSiteSafetyError(error) });
      });

    return true;
  }

  if (message?.type === "HIP_SAFETY_URL") {
    safetyPageUrl(message.originalUrl, message.sourceDomain, message.riskStatus)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  if (message?.type === "HIP_REPORT_RISK_FINDING") {
    reportRiskFinding(message.report)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP risk finding report unavailable.", error);
        sendResponse({ ok: false, error: "HIP reporting unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SUBMIT_SITE_FEEDBACK") {
    submitSiteFeedback(message.feedback)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP site feedback unavailable.", error);
        sendResponse({ ok: false, error: "HIP feedback unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SAVE_SCAN_RESULT") {
    saveScanResult(message.result)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP scan result persistence unavailable.", error);
        sendResponse({ ok: false, error: "HIP scan result persistence unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCAN_SUMMARY") {
    const tabId = _sender?.tab?.id;
    if (typeof tabId === "number") {
      scanSummaries.set(tabId, { ...message.summary, updatedAt: new Date().toISOString() });
    }

    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "HIP_GET_SCAN_SUMMARY") {
    const tabId = message.tabId;
    sendResponse({ ok: true, result: scanSummaries.get(tabId) || null });
    return false;
  }

  return false;
});

async function lookupDomain(domain) {
  const normalized = normalizeHost(domain);
  const cacheKey = `lookup:${normalized}`;
  const settings = await loadHipSettings();
  const cached = lookupCache.get(cacheKey);
  if (cached && Date.now() - cached.createdAt < cacheTtlMs) {
    return cached.value;
  }

  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const value = await client.lookupDomain(normalized);
  lookupCache.set(cacheKey, { createdAt: Date.now(), value });
  return value;
}

async function scoreSite(request) {
  const domain = normalizeHost(request?.domain);
  const cacheKey = `score:${domain}`;
  const settings = await loadHipSettings();
  const cached = domain ? lookupCache.get(cacheKey) : null;
  if (cached && Date.now() - cached.createdAt < cacheTtlMs) {
    return cached.value;
  }

  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const value = await client.scoreSite(request);
  if (domain) {
    lookupCache.set(cacheKey, { createdAt: Date.now(), value });
  }

  return value;
}

async function scanLinks(pageUrl, links) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  return client.scanLinks(pageUrl, links);
}

/**
 * Runs the server-side Site Safety scan from the background worker.
 * Keeping network access here lets page content scripts collect structural signals without owning API details.
 */
async function scanSiteSafety(request) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  return client.scanSiteSafety(request);
}

/**
 * Returns a deliberately generic Site Safety error for extension UI surfaces.
 * Expected 400/404 responses should not leak URLs, local ports, or validation details into page-visible state.
 */
function safeSiteSafetyError(error) {
  return error?.message?.includes("status 400") || error?.message?.includes("status 404")
    ? "HIP Site Safety unavailable for this page."
    : "HIP Site Safety unavailable.";
}

async function safetyPageUrl(originalUrl, sourceDomain, riskStatus) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  return client.safetyPageUrl(originalUrl, sourceDomain, riskStatus);
}

async function reportRiskFinding(report) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  return client.reportRiskFinding(report);
}

/**
 * Submits weak, weighted site feedback through HIP's public reputation feedback API.
 * Browser feedback is unauthenticated in the MVP, so the server treats it as Anonymous evidence.
 */
async function submitSiteFeedback(feedback) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  return client.submitSiteFeedback(feedback);
}

/**
 * Persists a privacy-safe scan summary through the configured HIP API.
 * This keeps storage in the background script so content scripts never handle API secrets later.
 */
async function saveScanResult(result) {
  const saveKey = scanResultSaveKey(result);
  if (pendingScanResultSaves.has(saveKey)) {
    return {
      saved: false,
      domain: normalizeHost(result?.domain),
      lastCheckedUtc: new Date().toISOString(),
      duplicateSuppressed: true
    };
  }

  pendingScanResultSaves.add(saveKey);
  try {
    const settings = await loadHipSettings();
    const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
    return await client.saveScanResult(result);
  } finally {
    pendingScanResultSaves.delete(saveKey);
  }
}

/**
 * Builds a short duplicate-prevention key for rapid scan submissions from the same page.
 * It prefers the page URL hash so the background worker does not need to store or compare raw full URLs.
 */
function scanResultSaveKey(result = {}) {
  return `${normalizeHost(result.domain)}:${result.pageUrlHash || result.pageUrl || "unknown"}`;
}

/**
 * Reads the extension manifest version once through the browser runtime API.
 * This avoids hardcoding dev/MVP version strings in popup, content, and settings UI files.
 */
function getPluginVersion() {
  return formatPluginVersion(chrome.runtime.getManifest().version);
}

/**
 * Reads a page-scoped banner dismissal flag from extension-owned storage.
 * Websites cannot tamper with chrome.storage.local, unlike page localStorage.
 */
async function isBannerDismissed(domain, pageKey) {
  const key = bannerDismissalKey(domain, pageKey);
  const stored = await chrome.storage.local.get({ [key]: false });
  return stored[key] === true;
}

/**
 * Saves a page-scoped banner dismissal flag in extension-owned storage.
 * The domain fallback preserves compatibility with older messages, but current content scripts pass a URL hash.
 */
async function setBannerDismissed(domain, pageKey) {
  await chrome.storage.local.set({ [bannerDismissalKey(domain, pageKey)]: true });
}

/**
 * Builds a stable storage key for local banner dismissal state without storing raw URLs.
 */
function bannerDismissalKey(domain, pageKey) {
  return `hip.bannerDismissed.${normalizeHost(domain)}.${pageKey || "domain"}`;
}
