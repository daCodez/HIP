import { formatPluginVersion, HipApiClient, loadHipSettings, normalizeHost } from "./hipApiClient.js";

const lookupCache = new Map();
const scanSummaries = new Map();
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

  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
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

  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  const value = await client.scoreSite(request);
  if (domain) {
    lookupCache.set(cacheKey, { createdAt: Date.now(), value });
  }

  return value;
}

async function scanLinks(pageUrl, links) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  return client.scanLinks(pageUrl, links);
}

async function safetyPageUrl(originalUrl, sourceDomain, riskStatus) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  return client.safetyPageUrl(originalUrl, sourceDomain, riskStatus);
}

async function reportRiskFinding(report) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  return client.reportRiskFinding(report);
}

/**
 * Persists a privacy-safe scan summary through the configured HIP API.
 * This keeps storage in the background script so content scripts never handle API secrets later.
 */
async function saveScanResult(result) {
  const settings = await loadHipSettings();
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  return client.saveScanResult(result);
}

/**
 * Reads the extension manifest version once through the browser runtime API.
 * This avoids hardcoding dev/MVP version strings in popup, content, and settings UI files.
 */
function getPluginVersion() {
  return formatPluginVersion(chrome.runtime.getManifest().version);
}
