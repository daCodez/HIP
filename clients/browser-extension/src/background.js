import { HipApiClient, loadHipSettings, normalizeHost } from "./hipApiClient.js";

const lookupCache = new Map();
const scanSummaries = new Map();
const cacheTtlMs = 5 * 60 * 1000;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
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
  const settings = await loadHipSettings();
  const cached = lookupCache.get(normalized);
  if (cached && Date.now() - cached.createdAt < cacheTtlMs) {
    return cached.value;
  }

  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  const value = await client.lookupDomain(normalized);
  lookupCache.set(normalized, { createdAt: Date.now(), value });
  return value;
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
