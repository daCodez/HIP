import { formatPluginVersion, HipApiClient, loadHipSettings, normalizeHost } from "./hipApiClient.js";
import { safeExtensionResult, validateBackgroundMessage } from "./extensionMessageContracts.js";
import { BoundedLruStore, FastScanCache, privacySafeScanCacheKey, RecentSubmissionDeduper } from "./fastScanCache.js";
import {
  activateInstallationKey,
  prepareInstallationKey,
  reconcileInstallationKeys,
  removeInstallationKey,
  signInstallationChallenge,
  stageInstallationKey
} from "./installationIdentity.js";

const fastScanCache = new FastScanCache();
const scanSubmissionDeduper = new RecentSubmissionDeduper();
const scanSummaries = new BoundedLruStore(128);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const validation = validateBackgroundMessage(message, _sender, chrome.runtime.id);
  if (!validation.ok) {
    sendResponse({ ok: false, error: validation.error });
    return false;
  }
  message = validation.message;

  if (message?.type === "HIP_GET_PLUGIN_VERSION") {
    sendResponse({ ok: true, result: safeExtensionResult(getPluginVersion()) });
    return false;
  }

  if (message?.type === "HIP_GET_SETTINGS") {
    loadHipSettings()
      .then(settings => sendResponse({ ok: true, result: safeExtensionResult(settings) }))
      .catch(() => sendResponse({ ok: false, error: "HIP settings unavailable" }));

    return true;
  }

  if (message?.type === "HIP_GET_BANNER_DISMISSED") {
    isBannerDismissed(message.domain, message.pageKey)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(() => sendResponse({ ok: false, error: "HIP preference unavailable" }));

    return true;
  }

  if (message?.type === "HIP_SET_BANNER_DISMISSED") {
    setBannerDismissed(message.domain, message.pageKey)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false, error: "HIP preference unavailable" }));

    return true;
  }

  if (message?.type === "HIP_LOOKUP_DOMAIN") {
    lookupDomain(message.domain)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        console.warn("HIP lookup unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCORE_SITE") {
    scoreSite(message.request)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        console.warn("HIP site score unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCAN_LINKS") {
    scanLinks(message.pageUrl, message.links)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        console.warn("HIP link scan unavailable.", error);
        sendResponse({ ok: false, error: "HIP unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SCAN_SITE_SAFETY") {
    scanSiteSafety(message.request)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        sendResponse({ ok: false, error: safeSiteSafetyError(error) });
      });

    return true;
  }

  if (message?.type === "HIP_SAFETY_URL") {
    safetyPageUrl(message.originalUrl, message.sourceDomain, message.riskStatus)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(() => sendResponse({ ok: false, error: "HIP safety routing unavailable" }));

    return true;
  }

  if (message?.type === "HIP_REPORT_RISK_FINDING") {
    reportRiskFinding(message.report)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        console.warn("HIP risk finding report unavailable.", error);
        sendResponse({ ok: false, error: "HIP reporting unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SUBMIT_SITE_FEEDBACK") {
    submitSiteFeedback(message.feedback)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(error => {
        console.warn("HIP site feedback unavailable.", error);
        sendResponse({ ok: false, error: "HIP feedback unavailable" });
      });

    return true;
  }

  if (message?.type === "HIP_SAVE_SCAN_RESULT") {
    saveScanResult(message.result)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
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
    sendResponse({ ok: true, result: safeExtensionResult(scanSummaries.get(tabId) || null) });
    return false;
  }

  if (message?.type === "HIP_DEVICE_CAPABILITIES") {
    handleDeviceOperation(_sender, () => ({ supported: true, algorithm: "ECDSA-P256-SHA256" }))
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_PREPARE") {
    handleDeviceOperation(_sender, prepareInstallationKey)
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_STAGE") {
    handleDeviceOperation(_sender, () => stageInstallationKey(message.handle, message.deviceId))
      .then(() => sendResponse({ ok: true, result: { staged: true } }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_SIGN_CHALLENGE") {
    handleDeviceOperation(_sender, () => signInstallationChallenge(message.deviceId, message.signingInput))
      .then(signature => sendResponse({ ok: true, result: safeExtensionResult({ signature }) }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_ACTIVATE") {
    handleDeviceOperation(_sender, () => activateInstallationKey(message.deviceId))
      .then(() => sendResponse({ ok: true, result: { activated: true } }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_REMOVE") {
    handleDeviceOperation(_sender, () => removeInstallationKey(message.deviceId))
      .then(removed => sendResponse({ ok: true, result: { removed } }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  if (message?.type === "HIP_DEVICE_RECONCILE") {
    handleDeviceOperation(_sender, () => reconcileInstallationKeys(message.activeDeviceIds))
      .then(result => sendResponse({ ok: true, result: safeExtensionResult(result) }))
      .catch(() => sendResponse({ ok: false, error: "HIP extension registration unavailable" }));
    return true;
  }

  return false;
});

async function lookupDomain(domain) {
  const normalized = normalizeHost(domain);
  const settings = await loadHipSettings();
  const cacheKey = await scanCacheKey("lookup", settings, { domain: normalized });
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const cached = await fastScanCache.getOrCreate(cacheKey, () => client.lookupDomain(normalized));
  return cached.value;
}

async function scoreSite(request) {
  const domain = normalizeHost(request?.domain);
  const settings = await loadHipSettings();
  const cacheKey = await scanCacheKey("score", settings, { domain, url: request.url });
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const cached = await fastScanCache.getOrCreate(cacheKey, () => client.scoreSite(request));
  return cached.value;
}

async function scanLinks(pageUrl, links) {
  const settings = await loadHipSettings();
  const cacheKey = await scanCacheKey("links", settings, { pageUrl, links });
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const cached = await fastScanCache.getOrCreate(cacheKey, () => client.scanLinks(pageUrl, links));
  return cached.value;
}

/**
 * Runs the server-side Site Safety scan from the background worker.
 * Keeping network access here lets page content scripts collect structural signals without owning API details.
 */
async function scanSiteSafety(request) {
  const settings = await loadHipSettings();
  const cacheKey = await scanCacheKey("site-safety", settings, request);
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const cached = await fastScanCache.getOrCreate(cacheKey, () => client.scanSiteSafety(request));
  return cached.value;
}

/**
 * Includes service identity and every result-affecting request field, but hashes
 * the complete structure before it enters the in-memory cache.
 */
async function scanCacheKey(kind, settings, request) {
  return privacySafeScanCacheKey(kind, {
    apiBaseUrl: settings.apiBaseUrl,
    webBaseUrl: settings.webBaseUrl,
    instanceId: settings.instanceId,
    request
  });
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
  const saveKey = await scanResultSaveKey(result);
  const execution = await scanSubmissionDeduper.run(saveKey, async () => {
    const settings = await loadHipSettings();
    const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
    return await client.saveScanResult(result);
  });

  if (!execution.executed) {
    return {
      saved: false,
      domain: normalizeHost(result?.domain),
      lastCheckedUtc: new Date().toISOString(),
      duplicateSuppressed: true
    };
  }

  return execution.value;
}

/**
 * Builds a short duplicate-prevention key for rapid scan submissions from the same page.
 * It prefers the page URL hash so the background worker does not need to store or compare raw full URLs.
 */
async function scanResultSaveKey(result = {}) {
  return privacySafeScanCacheKey("scan-submit", {
    domain: normalizeHost(result.domain),
    pageUrlHash: result.pageUrlHash || null
  });
}

async function handleDeviceOperation(sender, operation) {
  const settings = await loadHipSettings();
  const senderUrl = sender?.url || sender?.tab?.url;
  if (!senderUrl || new URL(senderUrl).origin !== new URL(settings.webBaseUrl).origin) {
    throw new Error("HIP extension registration sender is invalid.");
  }
  return operation();
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
