import { HipApiClient, DEFAULT_HIP_SETTINGS, loadHipSettings, normalizeHost } from "./hipApiClient.js";
import { buildPopupViewModel, loadingSummaryViewModel, unavailableMessage } from "./popupViewModel.js";

let settings = DEFAULT_HIP_SETTINGS;
let client = new HipApiClient(settings);
let activeTabId = null;
let activeTabUrl = null;
let activeLookup = null;
let activeSiteSafety = null;

const summaryPollAttempts = 6;
const summaryPollDelayMs = 450;

const elements = {
  domain: document.getElementById("domain"),
  pluginVersion: document.getElementById("pluginVersion"),
  state: document.getElementById("state"),
  scorePanel: document.getElementById("scorePanel"),
  reasonsPanel: document.getElementById("reasonsPanel"),
  score: document.getElementById("score"),
  status: document.getElementById("status"),
  statusBadge: document.getElementById("statusBadge"),
  domainTrustScore: document.getElementById("domainTrustScore"),
  pageTrustScore: document.getElementById("pageTrustScore"),
  contentRiskScore: document.getElementById("contentRiskScore"),
  finalHipScoreExplanation: document.getElementById("finalHipScoreExplanation"),
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
  lastSubmitted: document.getElementById("lastSubmitted"),
  dataSource: document.getElementById("dataSource"),
  siteSafetyPanel: document.getElementById("siteSafetyPanel"),
  siteSafetyStatus: document.getElementById("siteSafetyStatus"),
  siteSafetySummary: document.getElementById("siteSafetySummary"),
  malwareRisk: document.getElementById("malwareRisk"),
  phishingRisk: document.getElementById("phishingRisk"),
  redirectRisk: document.getElementById("redirectRisk"),
  downloadRisk: document.getElementById("downloadRisk"),
  scriptRisk: document.getElementById("scriptRisk"),
  reasons: document.getElementById("reasons"),
  lookupLink: document.getElementById("lookupLink"),
  safetyLink: document.getElementById("safetyLink"),
  refreshScan: document.getElementById("refreshScan"),
  settingsButton: document.getElementById("settingsButton")
};

elements.refreshScan.addEventListener("click", refreshScan);
elements.settingsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());
initialize().catch(error => showUnavailable(error));

/**
 * Initializes the popup with the active tab URL and current HIP score.
 */
async function initialize() {
  settings = await loadHipSettings();
  elements.pluginVersion.textContent = await loadPluginVersion();
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
  renderLoadingSummary("Checking page scan");
  const summary = await waitForScanSummary();
  await renderSiteSafety(summary).catch(error => console.warn("HIP Site Safety Scan unavailable.", error));
  renderLookup(lookup, summary);
}

/**
 * Renders the website score and lookup links from public-safe HIP response data.
 */
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
  elements.domainTrustScore.textContent = viewModel.domainTrustScoreText;
  elements.pageTrustScore.textContent = viewModel.pageTrustScoreText;
  elements.contentRiskScore.textContent = viewModel.contentRiskScoreText;
  elements.finalHipScoreExplanation.textContent = viewModel.finalHipScoreExplanation;
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

/**
 * Renders the content-script scan summary, including scan-result submission state.
 */
async function renderScanSummary() {
  if (!activeTabId) {
    return {};
  }

  const summary = await getScanSummary();
  renderSummary(summary);
  return summary;
}

/**
 * Shows visible loading indicators while the content script is still scanning.
 */
function renderLoadingSummary(stage = "Checking") {
  const viewModel = loadingSummaryViewModel(stage);
  elements.scanPanel.hidden = false;
  elements.apiStatus.textContent = viewModel.apiStatus;
  elements.linksScanned.textContent = viewModel.linksScanned;
  elements.riskyLinks.textContent = viewModel.riskyLinks;
  elements.unknownLinks.textContent = viewModel.unknownLinks;
  elements.downloadCandidates.textContent = viewModel.downloadCandidates;
  elements.loginForms.textContent = viewModel.loginFormsDetected;
  elements.lastScan.textContent = viewModel.lastScanText;
  elements.lastSubmitted.textContent = viewModel.lastSubmittedText;
  elements.dataSource.textContent = viewModel.dataSourceText;
  elements.siteSafetyPanel.hidden = false;
  elements.siteSafetyStatus.textContent = "Checking...";
  elements.siteSafetyStatus.dataset.status = "Unknown";
  elements.siteSafetySummary.textContent = "HIP is checking page safety signals.";
  elements.malwareRisk.textContent = "Checking...";
  elements.phishingRisk.textContent = "Checking...";
  elements.redirectRisk.textContent = "Checking...";
  elements.downloadRisk.textContent = "Checking...";
  elements.scriptRisk.textContent = "Checking...";
}

/**
 * Renders a content-script scan summary after one is available.
 */
function renderSummary(summary = {}) {
  const viewModel = buildPopupViewModel(activeLookup, summary, settings, activeTabUrl);
  elements.scanPanel.hidden = false;
  elements.apiStatus.textContent = viewModel.apiStatus;
  elements.linksScanned.textContent = viewModel.linksScanned;
  elements.riskyLinks.textContent = viewModel.riskyLinks;
  elements.unknownLinks.textContent = viewModel.unknownLinks;
  elements.downloadCandidates.textContent = viewModel.downloadCandidates;
  elements.loginForms.textContent = viewModel.loginFormsDetected;
  elements.lastScan.textContent = viewModel.lastScanText;
  elements.lastSubmitted.textContent = viewModel.lastSubmittedText;
  elements.dataSource.textContent = viewModel.dataSourceText;
}

/**
 * Polls briefly for a fresh content-script scan summary so users do not need to manually refresh.
 */
async function waitForScanSummary() {
  for (let attempt = 0; attempt < summaryPollAttempts; attempt++) {
    const summary = await getScanSummary();
    if (isUsefulSummary(summary)) {
      renderSummary(summary);
      return summary;
    }

    renderLoadingSummary(attempt === 0 ? "Scanning page" : "Still scanning");
    await delay(summaryPollDelayMs);
  }

  const fallback = await getScanSummary();
  renderSummary(fallback);
  return fallback;
}

/**
 * Retrieves the latest summary cached by the background worker.
 */
async function getScanSummary() {
  if (!activeTabId) {
    return {};
  }

  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_SCAN_SUMMARY", tabId: activeTabId });
  return response?.result || {};
}

/**
 * Determines whether a summary has enough data to replace loading indicators.
 */
function isUsefulSummary(summary = {}) {
  return Boolean(summary.updatedAt) ||
    summary.apiStatus === "Available" ||
    summary.apiStatus === "Unavailable" ||
    (summary.linksScanned ?? 0) > 0 ||
    summary.scanResultSubmission === "Success" ||
    summary.scanResultSubmission === "Failure" ||
    summary.scanResultSubmission === "Disabled";
}

/**
 * Runs HIP Site Safety Scan for the active tab using only privacy-safe content-script facts.
 * The scan never receives page text, script contents, form values, passwords, or private messages.
 */
async function renderSiteSafety(summary = {}) {
  if (!activeTabUrl) {
    return null;
  }

  const request = client.buildSiteSafetyRequest(activeTabUrl, summary);
  const result = await client.scanSiteSafety(request);
  activeSiteSafety = result;
  elements.siteSafetyPanel.hidden = false;
  elements.siteSafetyStatus.textContent = result.status || "Unknown";
  elements.siteSafetyStatus.dataset.status = result.status || "Unknown";
  elements.siteSafetySummary.textContent = result.summary || "HIP has limited site safety data for this page.";
  elements.malwareRisk.textContent = riskLabel(result.malwareRiskScore);
  elements.phishingRisk.textContent = riskLabel(result.phishingRiskScore);
  elements.redirectRisk.textContent = riskLabel(result.redirectRiskScore);
  elements.downloadRisk.textContent = riskLabel(result.downloadRiskScore);
  elements.scriptRisk.textContent = riskLabel(result.scriptRiskScore);
  return result;
}

/**
 * Requests a fresh content-script scan without disrupting normal page behavior on failure.
 */
async function refreshScan() {
  if (!activeTabId) {
    return;
  }

  elements.refreshScan.disabled = true;
  renderLoadingSummary("Refreshing scan");
  try {
    await chrome.tabs.sendMessage(activeTabId, { type: "HIP_REFRESH_SCAN" });
    const summary = await waitForScanSummary();
    await renderSiteSafety(summary).catch(error => console.warn("HIP Site Safety Scan unavailable after refresh.", error));
    if (activeLookup) {
      renderLookup(activeLookup, summary);
    }
  } catch (error) {
    console.warn("HIP scan refresh unavailable.", error);
  } finally {
    elements.refreshScan.disabled = false;
  }
}

/**
 * Waits without blocking popup rendering.
 */
function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

/**
 * Displays a safe unavailable state when the HIP API or extension messaging fails.
 */
function showUnavailable(error) {
  console.warn("HIP popup unavailable.", error);
  elements.state.textContent = unavailableMessage();
  elements.state.className = "state unavailable";
}

/**
 * Loads the extension version from the background worker so the popup reflects manifest.json.
 */
async function loadPluginVersion() {
  const response = await chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" });
  return response?.ok ? response.result : "HIP Plugin vunknown-dev";
}

/**
 * Converts a numeric risk score into a compact popup label.
 * Labels intentionally describe safety risk, not overall HIP trust.
 */
function riskLabel(score) {
  if (typeof score !== "number") {
    return "Unknown";
  }

  if (score <= 0) {
    return "None found";
  }

  if (score <= 20) {
    return "Low";
  }

  if (score <= 40) {
    return "Medium";
  }

  if (score <= 65) {
    return "Elevated";
  }

  return "High";
}
