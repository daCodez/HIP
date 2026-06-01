import { DEFAULT_HIP_SETTINGS, loadHipSettings, saveHipSettings } from "./hipApiClient.js";

const form = document.getElementById("settingsForm");
const status = document.getElementById("status");
const pluginVersion = document.getElementById("pluginVersion");
const fields = {
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  webBaseUrl: document.getElementById("webBaseUrl"),
  scanMode: document.getElementById("scanMode"),
  enableLinkBadges: document.getElementById("enableLinkBadges"),
  enableLinkScanning: document.getElementById("enableLinkScanning"),
  enableWarningBanner: document.getElementById("enableWarningBanner"),
  enableSafetyRouting: document.getElementById("enableSafetyRouting"),
  submitScanResults: document.getElementById("submitScanResults")
};

document.getElementById("restoreDefaults").addEventListener("click", async () => {
  await saveHipSettings(DEFAULT_HIP_SETTINGS);
  render(DEFAULT_HIP_SETTINGS);
  status.textContent = "Defaults restored.";
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const settings = await saveHipSettings(readForm());
  render(settings);
  status.textContent = "Settings saved.";
});

initialize().catch(error => {
  status.textContent = `Settings unavailable: ${error.message}`;
});

/**
 * Loads persisted settings and renders the options form without sending any scan data.
 */
async function initialize() {
  pluginVersion.textContent = await loadPluginVersion();
  render(await loadHipSettings());
}

/**
 * Renders both current and compatibility settings names so older installs upgrade safely.
 */
function render(settings) {
  fields.apiBaseUrl.value = settings.hipApiBaseUrl || settings.apiBaseUrl;
  fields.webBaseUrl.value = settings.webBaseUrl;
  fields.scanMode.value = settings.scanMode;
  fields.enableLinkBadges.checked = settings.showRiskyLinkIcons ?? settings.enableLinkBadges;
  fields.enableLinkScanning.checked = settings.enableLinkScanning;
  fields.enableWarningBanner.checked = settings.enableWarningBanner;
  fields.enableSafetyRouting.checked = settings.enableSafetyPageRouting ?? settings.enableSafetyRouting;
  fields.submitScanResults.checked = settings.submitScanResults;
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
    showRiskyLinkIcons: fields.enableLinkBadges.checked,
    enableLinkBadges: fields.enableLinkBadges.checked,
    enableLinkScanning: fields.enableLinkScanning.checked,
    enableWarningBanner: fields.enableWarningBanner.checked,
    enableSafetyPageRouting: fields.enableSafetyRouting.checked,
    enableSafetyRouting: fields.enableSafetyRouting.checked,
    submitScanResults: fields.submitScanResults.checked
  };
}

/**
 * Loads the extension version from the background worker for settings/debug confirmation.
 */
async function loadPluginVersion() {
  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" });
  return response?.ok ? response.result : "HIP Plugin vunknown-dev";
}
