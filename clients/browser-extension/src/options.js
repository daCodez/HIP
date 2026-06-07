import { DEFAULT_HIP_SETTINGS, HipApiClient, loadHipSettings, saveHipSettings } from "./hipApiClient.js";

const form = document.getElementById("settingsForm");
const status = document.getElementById("status");
const pluginVersion = document.getElementById("pluginVersion");
const providerStatus = document.getElementById("providerStatus");
let currentProviderSettings = null;
let currentInstanceId = null;
const fields = {
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  webBaseUrl: document.getElementById("webBaseUrl"),
  scanMode: document.getElementById("scanMode"),
  bannerDisplayMode: document.getElementById("bannerDisplayMode"),
  enableLinkBadges: document.getElementById("enableLinkBadges"),
  enableLinkScanning: document.getElementById("enableLinkScanning"),
  enableWarningBanner: document.getElementById("enableWarningBanner"),
  enableSafetyRouting: document.getElementById("enableSafetyRouting"),
  submitScanResults: document.getElementById("submitScanResults"),
  externalProvidersEnabled: document.getElementById("externalProvidersEnabled"),
  sslLabsEnabled: document.getElementById("sslLabsEnabled"),
  googleWebRiskEnabled: document.getElementById("googleWebRiskEnabled"),
  virusTotalEnabled: document.getElementById("virusTotalEnabled")
};

document.getElementById("refreshProviders").addEventListener("click", async () => {
  await refreshProviderSettings();
});

document.getElementById("restoreDefaults").addEventListener("click", async () => {
  await saveHipSettings(DEFAULT_HIP_SETTINGS);
  render(DEFAULT_HIP_SETTINGS);
  currentProviderSettings = null;
  status.textContent = "Defaults restored.";
  providerStatus.textContent = "Provider preferences restored locally. Save settings to sync with HIP.";
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const settings = readForm();
  const savedSettings = await saveHipSettings(settings);
  const syncMessage = await syncProviderSettings(savedSettings);
  render(savedSettings);
  status.textContent = "Settings saved.";
  providerStatus.textContent = syncMessage;
});

initialize().catch(error => {
  status.textContent = `Settings unavailable: ${error.message}`;
});

/**
 * Loads persisted settings and renders the options form without sending any scan data.
 */
async function initialize() {
  pluginVersion.textContent = await loadPluginVersion();
  const settings = await loadHipSettings();
  currentInstanceId = settings.instanceId;
  render(settings);
  await refreshProviderSettings(settings);
}

/**
 * Renders both current and compatibility settings names so older installs upgrade safely.
 */
function render(settings) {
  fields.apiBaseUrl.value = settings.hipApiBaseUrl || settings.apiBaseUrl;
  fields.webBaseUrl.value = settings.webBaseUrl;
  fields.scanMode.value = settings.scanMode;
  fields.bannerDisplayMode.value = settings.bannerDisplayMode || "WarningsOnly";
  fields.enableLinkBadges.checked = settings.showRiskyLinkIcons ?? settings.enableLinkBadges;
  fields.enableLinkScanning.checked = settings.enableLinkScanning;
  fields.enableWarningBanner.checked = settings.enableWarningBanner;
  fields.enableSafetyRouting.checked = settings.enableSafetyPageRouting ?? settings.enableSafetyRouting;
  fields.submitScanResults.checked = settings.submitScanResults;
  fields.externalProvidersEnabled.checked = settings.externalProvidersEnabled;
  fields.sslLabsEnabled.checked = settings.sslLabsEnabled;
  fields.googleWebRiskEnabled.checked = settings.googleWebRiskEnabled;
  fields.virusTotalEnabled.checked = settings.virusTotalEnabled;
}

/**
 * Reads the options form into the settings object consumed by content and background scripts.
 */
function readForm() {
  return {
    hipApiBaseUrl: fields.apiBaseUrl.value.trim(),
    apiBaseUrl: fields.apiBaseUrl.value.trim(),
    webBaseUrl: fields.webBaseUrl.value.trim(),
    scanMode: fields.scanMode.value,
    bannerDisplayMode: fields.bannerDisplayMode.value,
    showRiskyLinkIcons: fields.enableLinkBadges.checked,
    enableLinkBadges: fields.enableLinkBadges.checked,
    enableLinkScanning: fields.enableLinkScanning.checked,
    enableWarningBanner: fields.enableWarningBanner.checked,
    enableSafetyPageRouting: fields.enableSafetyRouting.checked,
    enableSafetyRouting: fields.enableSafetyRouting.checked,
    submitScanResults: fields.submitScanResults.checked,
    externalProvidersEnabled: fields.externalProvidersEnabled.checked,
    sslLabsEnabled: fields.sslLabsEnabled.checked,
    googleWebRiskEnabled: fields.googleWebRiskEnabled.checked,
    virusTotalEnabled: fields.virusTotalEnabled.checked,
    instanceId: currentInstanceId
  };
}

/**
 * Loads provider settings from HIP and renders them as switch values when the admin API is reachable.
 * Failure leaves local preferences intact because provider enforcement remains server-side.
 */
async function refreshProviderSettings(settings = null) {
  const activeSettings = settings || readForm();
  const client = new HipApiClient({ apiBaseUrl: activeSettings.apiBaseUrl, webBaseUrl: activeSettings.webBaseUrl, instanceId: activeSettings.instanceId });
  providerStatus.textContent = "Checking provider settings...";

  try {
    currentProviderSettings = await client.getExternalProviderSettings();
    renderProviderSettings(currentProviderSettings);
    providerStatus.textContent = "Provider settings loaded from HIP.";
  } catch (error) {
    currentProviderSettings = null;
    providerStatus.textContent = `Provider settings saved locally only. HIP admin sync unavailable: ${error.message}`;
  }
}

/**
 * Renders HIP server provider settings without exposing secrets or raw provider responses.
 */
function renderProviderSettings(providerSettings) {
  fields.externalProvidersEnabled.checked = providerSettings.externalProvidersEnabled;
  fields.sslLabsEnabled.checked = providerSettings.sslLabs?.enabled ?? true;
  fields.googleWebRiskEnabled.checked = providerSettings.googleWebRisk?.enabled ?? false;
  fields.virusTotalEnabled.checked = providerSettings.virusTotal?.enabled ?? false;
}

/**
 * Attempts to synchronize provider switches to the HIP admin API while preserving existing provider details.
 */
async function syncProviderSettings(settings) {
  const client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl, instanceId: settings.instanceId });
  const base = currentProviderSettings || defaultProviderSettings();
  const request = {
    ...base,
    externalProvidersEnabled: settings.externalProvidersEnabled,
    sslLabs: {
      ...base.sslLabs,
      enabled: settings.sslLabsEnabled
    },
    googleWebRisk: {
      ...base.googleWebRisk,
      enabled: settings.googleWebRiskEnabled
    },
    virusTotal: {
      ...base.virusTotal,
      enabled: settings.virusTotalEnabled
    }
  };

  try {
    currentProviderSettings = await client.updateExternalProviderSettings(request);
    return "Provider settings synced with HIP.";
  } catch (error) {
    return `Provider preferences saved locally. HIP admin sync failed: ${error.message}`;
  }
}

/**
 * Provides the complete safe provider settings shape required by the HIP admin endpoint.
 */
function defaultProviderSettings() {
  return {
    externalProvidersEnabled: true,
    allowFullUrlChecks: false,
    providerTimeout: "00:00:10",
    defaultCacheDuration: "06:00:00",
    sslLabs: {
      enabled: true,
      endpoint: "https://api.ssllabs.com/api/v3/analyze",
      apiKey: null,
      allowFullUrl: false,
      cacheDuration: null
    },
    googleWebRisk: {
      enabled: false,
      endpoint: null,
      apiKey: null,
      allowFullUrl: false,
      cacheDuration: null
    },
    virusTotal: {
      enabled: false,
      endpoint: null,
      apiKey: null,
      allowFullUrl: false,
      cacheDuration: null
    }
  };
}

/**
 * Loads the extension version from the background worker for settings/debug confirmation.
 */
async function loadPluginVersion() {
  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" });
  return response?.ok ? response.result : "HIP Plugin vunknown-dev";
}
