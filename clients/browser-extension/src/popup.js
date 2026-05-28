import { HipApiClient, HIP_CONFIG, normalizeHost } from "./hipApiClient.js";

const client = new HipApiClient(HIP_CONFIG);

const elements = {
  domain: document.getElementById("domain"),
  state: document.getElementById("state"),
  scorePanel: document.getElementById("scorePanel"),
  reasonsPanel: document.getElementById("reasonsPanel"),
  score: document.getElementById("score"),
  status: document.getElementById("status"),
  verified: document.getElementById("verified"),
  lastChecked: document.getElementById("lastChecked"),
  reasons: document.getElementById("reasons"),
  lookupLink: document.getElementById("lookupLink")
};

initialize().catch(error => showUnavailable(error));

async function initialize() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
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
}

function renderLookup(lookup) {
  elements.state.hidden = true;
  elements.scorePanel.hidden = false;
  elements.reasonsPanel.hidden = false;

  elements.score.textContent = `${lookup.finalHipScore}/100`;
  elements.status.textContent = lookup.status;
  elements.status.dataset.status = lookup.status;
  elements.verified.textContent = lookup.verificationStatus === "Verified" ? "Yes" : "No";
  elements.lastChecked.textContent = new Date(lookup.lastCheckedUtc).toLocaleString();

  const reasons = lookup.knownRisks?.length ? lookup.knownRisks : lookup.explanations || [];
  elements.reasons.replaceChildren(...reasons.slice(0, 5).map(reason => {
    const item = document.createElement("li");
    item.textContent = reason;
    return item;
  }));

  elements.lookupLink.href = `${HIP_CONFIG.webBaseUrl}/lookup/domain/${encodeURIComponent(lookup.domain)}`;
  elements.lookupLink.hidden = false;
}

function showUnavailable(error) {
  console.warn("HIP popup unavailable.", error);
  elements.state.textContent = "HIP unavailable";
  elements.state.className = "state unavailable";
}
