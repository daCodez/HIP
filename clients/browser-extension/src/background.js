import { HipApiClient, HIP_CONFIG, normalizeHost } from "./hipApiClient.js";

const client = new HipApiClient(HIP_CONFIG);
const lookupCache = new Map();
const cacheTtlMs = 5 * 60 * 1000;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
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
    sendResponse({
      ok: true,
      result: client.safetyPageUrl(message.originalUrl, message.sourceDomain, message.riskStatus)
    });
  }

  if (message?.type === "HIP_REPORT_RISK_FINDING") {
    client.reportRiskFinding(message.report)
      .then(result => sendResponse({ ok: true, result }))
      .catch(error => {
        console.warn("HIP risk finding report unavailable.", error);
        sendResponse({ ok: false, error: "HIP reporting unavailable" });
      });

    return true;
  }

  return false;
});

async function lookupDomain(domain) {
  const normalized = normalizeHost(domain);
  const cached = lookupCache.get(normalized);
  if (cached && Date.now() - cached.createdAt < cacheTtlMs) {
    return cached.value;
  }

  const value = await client.lookupDomain(normalized);
  lookupCache.set(normalized, { createdAt: Date.now(), value });
  return value;
}
