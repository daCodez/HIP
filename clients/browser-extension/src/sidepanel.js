import { createActiveTabCoordinator, pickInspectableTab, statusPresentation, storagePresentation } from "./sidePanelState.js";
import { isTrustedEmbeddedMessage } from "./embeddedPanelBridge.js";

const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = new Map(tabs.map(tab => [tab.id, document.getElementById(tab.getAttribute("aria-controls"))]));
const page = {
  domain: document.getElementById("activeDomain"), empty: document.getElementById("pageEmpty"), message: document.getElementById("pageMessage"),
  start: document.getElementById("startXray"), results: document.getElementById("pageResults"), status: document.getElementById("pageStatus"),
  score: document.getElementById("pageScore"), scoreBar: document.getElementById("scoreBar"), progress: document.getElementById("scanProgress"),
  findingCount: document.getElementById("findingCount"), visibleCount: document.getElementById("visibleFindingCount"), inspectedCount: document.getElementById("inspectedCount"),
  truncation: document.getElementById("truncationNote"), storage: document.getElementById("pageStorage"), lastSubmitted: document.getElementById("lastSubmitted"),
  rescan: document.getElementById("rescan"), markers: document.getElementById("markerToggle"), severity: document.getElementById("severityFilter"),
  category: document.getElementById("categoryFilter"), kind: document.getElementById("kindFilter"), findings: document.getElementById("findings"),
  inventory: document.getElementById("inventory"), inventorySummary: document.getElementById("inventorySummary"), loadMore: document.getElementById("loadMoreInventory"), loadMoreFindings: document.getElementById("loadMoreFindings"),
  announcer: document.getElementById("announcer"), siteFrame: document.getElementById("siteFrame")
};
let currentState = null;
let inventoryOffset = 0;
let findingOffset = 0;

const coordinator = createActiveTabCoordinator({
  clear: state => clearForTab(state),
  load: tab => loadTabState(tab),
  commit: state => renderTabState(state)
});

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab, true));
  tab.addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    activateTab(tabs[next], true);
  });
});

for (const filter of [page.severity, page.category, page.kind]) filter.addEventListener("change", renderFindings);
page.start.addEventListener("click", () => command({ type: "HIP_XRAY_START" }, true));
page.rescan.addEventListener("click", () => command({ type: "HIP_XRAY_RESCAN" }, true));
page.markers.addEventListener("click", async () => {
  const visible = page.markers.getAttribute("aria-pressed") !== "true";
  await command({ type: "HIP_XRAY_SET_MARKERS", visible }, false);
});
page.loadMore.addEventListener("click", () => loadMoreInventory());
page.loadMoreFindings.addEventListener("click", () => loadMoreFindings());

chrome.tabs.onActivated.addListener(() => refreshActiveTab());
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tabId === coordinator.current().tabId && (changeInfo.status === "loading" || changeInfo.url)) coordinator.activate(tab);
});
chrome.tabs.onRemoved.addListener(tabId => { if (tabId === coordinator.current().tabId) coordinator.invalidate(); });
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type === "HIP_OPEN_SIDE_PANEL" && sender?.tab?.id === coordinator.current().tabId) {
    activateTab(document.getElementById("pageTab"), true);
    void refreshActiveTab();
  }
});
window.addEventListener("message", event => {
  if (!isTrustedEmbeddedMessage(event, page.siteFrame.contentWindow)) return;
  if (event.data.action === "page") activateTab(document.getElementById("pageTab"), true);
  if (event.data.action === "settings") activateTab(document.getElementById("settingsTab"), true);
});

void restoreSelectedTab().then(refreshActiveTab);

async function restoreSelectedTab() {
  const stored = await chrome.storage.local.get({ hipSidePanelTab: "pageTab" });
  activateTab(document.getElementById(stored.hipSidePanelTab) || tabs[0], false);
}

function activateTab(next, focus) {
  for (const tab of tabs) {
    const selected = tab === next;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    panels.get(tab.id).hidden = !selected;
  }
  if (focus) next.focus();
  void chrome.storage.local.set({ hipSidePanelTab: next.id });
}

async function refreshActiveTab() {
  const tab = pickInspectableTab(await chrome.tabs.query({}));
  await coordinator.activate(tab || {});
}

function clearForTab({ tabId, supported }) {
  currentState = null;
  inventoryOffset = 0;
  findingOffset = 0;
  page.domain.textContent = supported ? "Loading current page..." : "Unsupported browser page";
  page.message.textContent = supported ? "Checking the latest browser-side X-ray state..." : "HIP can inspect only HTTP and HTTPS pages. No previous-tab data is shown.";
  page.start.hidden = false;
  page.start.disabled = !supported;
  page.empty.hidden = false;
  page.results.hidden = true;
  page.findings.replaceChildren();
  page.inventory.replaceChildren();
}

async function loadTabState(tab) {
  const hostname = new URL(tab.url).hostname;
  let response;
  try {
    response = await chrome.tabs.sendMessage(tab.id, { type: "HIP_XRAY_GET_STATE", inventoryOffset: 0, inventoryLimit: 50, findingOffset: 0, findingLimit: 50 });
  } catch {
    response = null;
  }
  return { tabId: tab.id, hostname, xray: response?.ok ? response.result : null };
}

function renderTabState(state) {
  page.domain.textContent = state.hostname;
  page.siteFrame.src = `popup.html?embedded=1&tab=${state.tabId}&generation=${Date.now()}`;
  if (state.error) {
    page.message.textContent = state.error;
    return;
  }
  if (!state.xray?.active) {
    page.message.textContent = "X-ray is ready. Scanning stays browser-side and does not read form values or private messages.";
    page.start.hidden = false;
    page.start.disabled = false;
    return;
  }
  currentState = state.xray;
  inventoryOffset = currentState.inventory?.nextOffset ?? null;
  findingOffset = currentState.nextFindingOffset ?? null;
  page.empty.hidden = true;
  page.results.hidden = false;
  renderPageSummary();
  populateFilters();
  renderFindings();
  page.loadMoreFindings.hidden = findingOffset === null;
  page.inventory.replaceChildren();
  appendInventory(currentState.inventory?.items || []);
  renderInventoryControls();
}

function renderPageSummary() {
  const presentation = statusPresentation(currentState.statusSeverity || "Info");
  page.status.textContent = currentState.status || presentation.label;
  page.status.style.color = presentation.color;
  page.score.textContent = Number.isFinite(currentState.score) ? String(currentState.score) : "--";
  page.scoreBar.style.width = `${Math.max(0, Math.min(100, Number(currentState.score) || 0))}%`;
  page.progress.textContent = currentState.scanState === "scanning" ? "Scanning this page..." : `Scan completed ${currentState.scanTimestamp ? new Date(currentState.scanTimestamp).toLocaleTimeString() : ""}`;
  page.findingCount.textContent = String(currentState.findingCount || 0);
  page.inspectedCount.textContent = String(currentState.coverage?.inspectedElementCount || 0);
  page.truncation.hidden = currentState.coverage?.truncated !== true;
  const storage = storagePresentation(currentState.submissionState);
  page.storage.textContent = storage.label;
  page.lastSubmitted.textContent = currentState.lastSubmittedUtc ? ` · ${new Date(currentState.lastSubmittedUtc).toLocaleString()}` : "";
  page.markers.setAttribute("aria-pressed", String(currentState.markersVisible !== false));
  page.markers.textContent = currentState.markersVisible === false ? "Markers off" : "Markers on";
}

function populateFilters() {
  replaceOptions(page.category, [...new Set((currentState.findings || []).map(item => item.category).filter(Boolean))]);
  replaceOptions(page.kind, [...new Set((currentState.findings || []).map(item => item.elementKind).filter(Boolean))]);
}

function replaceOptions(select, values) {
  const selected = select.value;
  select.replaceChildren(option("all", "All"), ...values.sort().map(value => option(value, value)));
  if ([...select.options].some(item => item.value === selected)) select.value = selected;
}

function option(value, label) {
  const node = document.createElement("option");
  node.value = value;
  node.textContent = label;
  return node;
}

function renderFindings() {
  if (!currentState) return;
  const visible = (currentState.findings || []).filter(item =>
    (page.severity.value === "all" || item.severity === page.severity.value) &&
    (page.category.value === "all" || item.category === page.category.value) &&
    (page.kind.value === "all" || item.elementKind === page.kind.value));
  page.findings.replaceChildren(...visible.map((finding, index) => findingCard(finding, index)));
  page.visibleCount.textContent = `${visible.length} loaded of ${currentState.findingCount || 0}`;
  if (!visible.length) {
    const empty = document.createElement("li");
    empty.className = "muted";
    empty.textContent = "No findings match these filters.";
    page.findings.append(empty);
  }
}

function findingCard(finding, index) {
  const item = document.createElement("li");
  const button = document.createElement("button");
  const presentation = statusPresentation(finding.severity);
  button.type = "button";
  button.className = "finding-card";
  button.dataset.findingId = finding.findingId;
  button.style.setProperty("--tone", presentation.color);
  button.setAttribute("aria-pressed", String(finding.findingId === currentState.selectedFindingId));
  const title = document.createElement("span");
  title.className = "finding-title";
  const number = document.createElement("span");
  number.className = "finding-number";
  number.textContent = String(index + 1).padStart(2, "0");
  const strong = document.createElement("strong");
  strong.textContent = `${presentation.label} · ${finding.title}`;
  title.append(number, strong);
  const copy = document.createElement("span");
  copy.className = "finding-copy";
  copy.textContent = finding.plainExplanation;
  button.append(title, copy);
  if (finding.findingId === currentState.selectedFindingId) {
    const details = document.createElement("span");
    details.className = "finding-details";
    details.textContent = `Evidence: ${finding.evidence || "No additional evidence."} What to do: ${finding.remediation || "Review this element."}`;
    button.append(details);
  }
  button.addEventListener("click", () => selectFinding(finding.findingId));
  item.append(button);
  return item;
}

async function selectFinding(findingId) {
  const response = await command({ type: "HIP_XRAY_SELECT_FINDING", findingId }, false);
  const result = response?.result;
  page.announcer.textContent = result?.status === "selected" ? "Finding selected on the page." : "Element no longer available.";
}

async function command(message, refresh) {
  const tabId = coordinator.current().tabId;
  if (!tabId) return null;
  page.progress.textContent = message.type.includes("RESCAN") || message.type.includes("START") ? "Scanning this page..." : page.progress.textContent;
  try {
    const response = await chrome.tabs.sendMessage(tabId, message);
    if (refresh || response?.ok) await refreshActiveTab();
    return response;
  } catch {
    page.announcer.textContent = "HIP X-ray is unavailable on this page.";
    return null;
  }
}

async function loadMoreInventory() {
  const tabId = coordinator.current().tabId;
  if (!tabId || inventoryOffset === null) return;
  const response = await chrome.tabs.sendMessage(tabId, { type: "HIP_XRAY_GET_STATE", inventoryOffset, inventoryLimit: 50 });
  if (!response?.ok) return;
  appendInventory(response.result.inventory?.items || []);
  inventoryOffset = response.result.inventory?.nextOffset ?? null;
  renderInventoryControls();
}

async function loadMoreFindings() {
  const tabId = coordinator.current().tabId;
  if (!tabId || findingOffset === null) return;
  const response = await chrome.tabs.sendMessage(tabId, { type: "HIP_XRAY_GET_STATE", inventoryOffset: 0, inventoryLimit: 1, findingOffset, findingLimit: 50 });
  if (!response?.ok) return;
  currentState.findings.push(...(response.result.findings || []));
  findingOffset = response.result.nextFindingOffset ?? null;
  page.loadMoreFindings.hidden = findingOffset === null;
  populateFilters();
  renderFindings();
}

function appendInventory(items) {
  page.inventory.append(...items.map(item => {
    const node = document.createElement("li");
    node.className = "inventory-item";
    const kind = document.createElement("span");
    kind.textContent = item.elementKind;
    const status = document.createElement("span");
    status.textContent = item.status || "No issue observed";
    node.append(kind, status);
    return node;
  }));
}

function renderInventoryControls() {
  page.inventorySummary.textContent = `(${currentState.coverage?.inspectedElementCount || 0})`;
  page.loadMore.hidden = inventoryOffset === null;
}
