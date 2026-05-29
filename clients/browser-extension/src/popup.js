import { HipApiClient, DEFAULT_HIP_SETTINGS, loadHipSettings, normalizeHost } from "./hipApiClient.js";

let settings = DEFAULT_HIP_SETTINGS;
let client = new HipApiClient(settings);
let activeTabId = null;

const elements = {
  domain: document.getElementById("domain"),
  state: document.getElementById("state"),
  scorePanel: document.getElementById("scorePanel"),
  reasonsPanel: document.getElementById("reasonsPanel"),
  score: document.getElementById("score"),
  status: document.getElementById("status"),
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
  reasons: document.getElementById("reasons"),
  lookupLink: document.getElementById("lookupLink"),
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

  if (!currentUrl || !["http:", "https:"].includes(currentUrl.protocol)) {
    elements.domain.textContent = "No website tab selected";
    elements.state.textContent = "HIP checks run on HTTP and HTTPS pages.";
    elements.state.className = "state unavailable";
    return;
  }

  const domain = normalizeHost(currentUrl.hostname);
  elements.domain.textContent = domain;

  const lookup = await client.lookupDomain(domain);
  renderLookup(lookup);
  await renderScanSummary();
}

function renderLookup(lookup) {
  elements.state.hidden = true;
  elements.scorePanel.hidden = false;
  elements.reasonsPanel.hidden = false;

  elements.score.textContent = `${lookup.finalHipScore}/100`;
  elements.status.textContent = lookup.status;
  elements.status.dataset.status = lookup.status;
  elements.verified.textContent = lookup.verificationStatus === "Verified" ? "Yes" : "No";
  elements.identityStatus.textContent = lookup.identityVerificationStatus || lookup.signedIdentityStatus || "Unknown";
  elements.lastChecked.textContent = new Date(lookup.lastCheckedUtc).toLocaleString();

  const reasons = lookup.knownRisks?.length ? lookup.knownRisks : lookup.explanations || [];
  elements.reasons.replaceChildren(...reasons.slice(0, 5).map(reason => {
    const item = document.createElement("li");
    item.textContent = reason;
    return item;
  }));

  elements.lookupLink.href = `${settings.webBaseUrl}/lookup/domain/${encodeURIComponent(lookup.domain)}`;
  elements.lookupLink.hidden = false;
}

async function renderScanSummary() {
  if (!activeTabId) {
    return;
  }

  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_SCAN_SUMMARY", tabId: activeTabId });
  const summary = response?.result || {};
  elements.scanPanel.hidden = false;
  elements.apiStatus.textContent = summary.apiStatus || "Unknown";
  elements.linksScanned.textContent = summary.linksScanned ?? 0;
  elements.riskyLinks.textContent = summary.riskyLinks ?? 0;
  elements.unknownLinks.textContent = summary.unknownLinks ?? 0;
  elements.downloadCandidates.textContent = summary.downloadCandidates ?? 0;
  elements.loginForms.textContent = summary.loginFormsDetected ?? 0;
}

async function refreshScan() {
  if (!activeTabId) {
    return;
  }

  elements.refreshScan.disabled = true;
  try {
    await chrome.tabs.sendMessage(activeTabId, { type: "HIP_REFRESH_SCAN" });
    await renderScanSummary();
  } catch (error) {
    console.warn("HIP scan refresh unavailable.", error);
  } finally {
    elements.refreshScan.disabled = false;
  }
}

function showUnavailable(error) {
  console.warn("HIP popup unavailable.", error);
  elements.state.textContent = "HIP unavailable";
  elements.state.className = "state unavailable";
}
