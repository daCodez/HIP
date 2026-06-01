import { HipApiClient, DEFAULT_HIP_SETTINGS, loadHipSettings, normalizeHost } from "./hipApiClient.js";
import { buildPopupViewModel, unavailableMessage } from "./popupViewModel.js";

let settings = DEFAULT_HIP_SETTINGS;
let client = new HipApiClient(settings);
let activeTabId = null;
let activeTabUrl = null;
let activeLookup = null;

const elements = {
  domain: document.getElementById("domain"),
  state: document.getElementById("state"),
  scorePanel: document.getElementById("scorePanel"),
  reasonsPanel: document.getElementById("reasonsPanel"),
  score: document.getElementById("score"),
  status: document.getElementById("status"),
  statusBadge: document.getElementById("statusBadge"),
  verified: document.getElementById("verified"),
  identityStatus: document.getElementById("identityStatus"),
  lastChecked: document.getElementById("lastChecked"),
  scanPanel: document.getElementById("scanPanel"),
  apiStatus: document.getElementById("apiStatus"),
  linksScanned: document.getElementById("linksScanned"),
  riskyLinks: document.getElementById("riskyLinks"),
  unknownLinks: document.getElementById("unknownLinks"),
  downloadCandidates: document.getElementById("downloadCandidates"),
  loginForms: document.getElementById("loginForms"),
  lastScan: document.getElementById("lastScan"),
  reasons: document.getElementById("reasons"),
  lookupLink: document.getElementById("lookupLink"),
  safetyLink: document.getElementById("safetyLink"),
  refreshScan: document.getElementById("refreshScan"),
  settingsButton: document.getElementById("settingsButton")
};

elements.refreshScan.addEventListener("click", refreshScan);
elements.settingsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());
initialize().catch(error => showUnavailable(error));

async function initialize() {
  settings = await loadHipSettings();
  client = new HipApiClient({ apiBaseUrl: settings.apiBaseUrl, webBaseUrl: settings.webBaseUrl });
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTabId = tab?.id ?? null;
  const currentUrl = tab?.url ? new URL(tab.url) : null;
  activeTabUrl = currentUrl?.toString() || null;

  if (!currentUrl || !["http:", "https:"].includes(currentUrl.protocol)) {
    elements.domain.textContent = "No website tab selected";
    elements.state.textContent = "HIP checks run on HTTP and HTTPS pages.";
    elements.state.className = "state unavailable";
    return;
  }

  const domain = normalizeHost(currentUrl.hostname);
  elements.domain.textContent = domain;

  const lookup = await client.scoreSite({ url: currentUrl.toString(), domain });
  activeLookup = lookup;
  const summary = await renderScanSummary();
  renderLookup(lookup, summary);
}

function renderLookup(lookup, summary = {}) {
  const viewModel = buildPopupViewModel(lookup, summary, settings, activeTabUrl);
  elements.state.hidden = true;
  elements.scorePanel.hidden = false;
  elements.reasonsPanel.hidden = false;

  elements.domain.textContent = viewModel.domain;
  elements.score.textContent = viewModel.scoreText;
  elements.status.textContent = viewModel.statusLabel;
  elements.status.dataset.status = viewModel.status;
  elements.statusBadge.textContent = viewModel.statusLabel;
  elements.statusBadge.className = `status-badge ${viewModel.statusClass}`;
  elements.verified.textContent = viewModel.verifiedText;
  elements.identityStatus.textContent = viewModel.identityText;
  elements.lastChecked.textContent = viewModel.lastCheckedText;

  elements.reasons.replaceChildren(...viewModel.reasons.map(reason => {
    const item = document.createElement("li");
    item.textContent = reason;
    return item;
  }));

  elements.lookupLink.href = viewModel.lookupUrl;
  elements.lookupLink.hidden = false;
  elements.safetyLink.href = viewModel.safetyDetailsUrl || "#";
  elements.safetyLink.hidden = !viewModel.safetyDetailsUrl;
}

async function renderScanSummary() {
  if (!activeTabId) {
    return {};
  }

  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_SCAN_SUMMARY", tabId: activeTabId });
  const summary = response?.result || {};
  const viewModel = buildPopupViewModel(activeLookup, summary, settings, activeTabUrl);
  elements.scanPanel.hidden = false;
  elements.apiStatus.textContent = viewModel.apiStatus;
  elements.linksScanned.textContent = viewModel.linksScanned;
  elements.riskyLinks.textContent = viewModel.riskyLinks;
  elements.unknownLinks.textContent = viewModel.unknownLinks;
  elements.downloadCandidates.textContent = viewModel.downloadCandidates;
  elements.loginForms.textContent = viewModel.loginFormsDetected;
  elements.lastScan.textContent = viewModel.lastScanText;
  return summary;
}

async function refreshScan() {
  if (!activeTabId) {
    return;
  }

  elements.refreshScan.disabled = true;
  try {
    await chrome.tabs.sendMessage(activeTabId, { type: "HIP_REFRESH_SCAN" });
    const summary = await renderScanSummary();
    if (activeLookup) {
      renderLookup(activeLookup, summary);
    }
  } catch (error) {
    console.warn("HIP scan refresh unavailable.", error);
  } finally {
    elements.refreshScan.disabled = false;
  }
}

function showUnavailable(error) {
  console.warn("HIP popup unavailable.", error);
  elements.state.textContent = unavailableMessage();
  elements.state.className = "state unavailable";
}
