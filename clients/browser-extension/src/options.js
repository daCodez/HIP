import { DEFAULT_HIP_SETTINGS, loadHipSettings, saveHipSettings } from "./hipApiClient.js";

const form = document.getElementById("settingsForm");
const status = document.getElementById("status");
const fields = {
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  webBaseUrl: document.getElementById("webBaseUrl"),
  scanMode: document.getElementById("scanMode"),
  enableLinkBadges: document.getElementById("enableLinkBadges"),
  enableWarningBanner: document.getElementById("enableWarningBanner"),
  enableSafetyRouting: document.getElementById("enableSafetyRouting")
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

async function initialize() {
  render(await loadHipSettings());
}

function render(settings) {
  fields.apiBaseUrl.value = settings.apiBaseUrl;
  fields.webBaseUrl.value = settings.webBaseUrl;
  fields.scanMode.value = settings.scanMode;
  fields.enableLinkBadges.checked = settings.enableLinkBadges;
  fields.enableWarningBanner.checked = settings.enableWarningBanner;
  fields.enableSafetyRouting.checked = settings.enableSafetyRouting;
}

function readForm() {
  return {
    apiBaseUrl: fields.apiBaseUrl.value.trim(),
    webBaseUrl: fields.webBaseUrl.value.trim(),
    scanMode: fields.scanMode.value,
    enableLinkBadges: fields.enableLinkBadges.checked,
    enableWarningBanner: fields.enableWarningBanner.checked,
    enableSafetyRouting: fields.enableSafetyRouting.checked
  };
}
