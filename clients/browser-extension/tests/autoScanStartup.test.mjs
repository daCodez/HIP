import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fetchWithTimeout, HIP_FETCH_TIMEOUT_MS } from "../src/hipApiClient.js";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
const browserPrivacyGuardsSource = await readFile(new URL("../src/browserPrivacyGuards.js", import.meta.url), "utf8");
const browserScanAssessmentSource = await readFile(new URL("../src/browserScanAssessment.js", import.meta.url), "utf8");
const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const apiClientSource = await readFile(new URL("../src/hipApiClient.js", import.meta.url), "utf8");
const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const manifestSource = await readFile(new URL("../manifest.json", import.meta.url), "utf8");
const workerWrapperSource = await readFile(new URL("../background.js", import.meta.url), "utf8");
const formalScoringSource = await readFile(new URL("../src/formalScoring.js", import.meta.url), "utf8");

test("content script publishes scan progress before site scoring", () => {
  const startupIndex = contentSource.indexOf('markScanStage("Starting")');
  const publishIndex = contentSource.indexOf("publishSummary();", startupIndex);
  const scoreIndex = contentSource.indexOf("const currentLookup = await scoreSite");

  assert.equal(startupIndex > -1, true);
  assert.equal(publishIndex > startupIndex, true);
  assert.equal(scoreIndex > publishIndex, true);
});

test("content script publishes safe failure summary when initialization fails", () => {
  assert.equal(contentSource.includes("runScan().catch(handleInitializationError);"), true);
  assert.equal(contentSource.includes('markScanStage("Failed")'), true);
  assert.equal(contentSource.includes('lastSummary.apiStatus = "Unavailable"'), true);
  assert.equal(contentSource.includes("publishSummary();"), true);
});

test("content script summary includes scan stage and update timestamps", () => {
  assert.equal(contentSource.includes('scanStage: "Pending"'), true);
  assert.equal(contentSource.includes("lastScanUtc: null"), true);
  assert.equal(contentSource.includes("updatedAt: null"), true);
  assert.equal(contentSource.includes("lastSummary.updatedAt = new Date().toISOString();"), true);
});

test("content script runs Site Safety during automatic page scan", () => {
  const collectIndex = contentSource.indexOf('markScanStage("CollectingPageSignals")');
  const siteSafetyIndex = contentSource.indexOf('markScanStage("CheckingSiteSafety")');
  const mergeIndex = contentSource.indexOf("mergeSiteSafetyAssessment(currentLookup, siteSafety)");
  const persistIndex = contentSource.indexOf("await persistScanResult(finalLookup)");

  assert.equal(siteSafetyIndex > collectIndex, true);
  assert.equal(mergeIndex > siteSafetyIndex, true);
  assert.equal(persistIndex > mergeIndex, true);
  assert.equal(contentSource.includes('type: "HIP_SCAN_SITE_SAFETY"'), true);
  assert.equal(contentSource.includes("buildSiteSafetyRequest()"), true);
});

test("content script publishes compact Site Safety results for the popup", () => {
  assert.equal(contentSource.includes("lastSummary.siteSafety = compactResult;"), true);
  assert.equal(contentSource.includes("function compactSiteSafetyResult"), true);
  assert.equal(contentSource.includes("function safeProviderEvidence"), true);
  assert.equal(contentSource.includes("errors:"), false);
});

test("formal scoring helper loads before content and controls persisted score direction", () => {
  const manifest = JSON.parse(manifestSource);
  const scripts = manifest.content_scripts[0].js;

  assert.equal(scripts.includes("src/formalScoring.js"), true);
  assert.equal(scripts.indexOf("src/formalScoring.js") < scripts.indexOf("src/content.js"), true);
  assert.equal(formalScoringSource.includes("projectSiteSafetyScores"), true);
  assert.equal(contentSource.includes("globalThis.HipFormalScoring"), true);
  assert.equal(contentSource.includes("const compactResult = compactSiteSafetyResult(response.result);"), true);
  assert.equal(contentSource.includes("const scoreProjection = formalScoring.projectSiteSafetyScores(response.result);"), true);
  assert.equal(contentSource.includes("lastSummary.contentRiskScore = scoreProjection?.contentRiskScore ?? null;"), true);
});

test("content script skips private and HIP owned URLs before Site Safety", () => {
  assert.equal(contentSource.includes("isSiteSafetyEligibleUrl(window.location.href, settings)"), true);
  assert.equal(contentSource.includes("filterSafePublicUrls(lastSummary.downloadLinks, settings)"), true);
  assert.equal(browserPrivacyGuardsSource.includes("function isSiteSafetyEligibleUrl"), true);
  assert.equal(browserPrivacyGuardsSource.includes("!isHipOwnedPage(pageUrl, currentSettings)"), true);
  assert.equal(browserPrivacyGuardsSource.includes("!isInternalHost(url.hostname)"), true);
  assert.equal(browserPrivacyGuardsSource.includes("function filterSafePublicUrls"), true);
});

test("content script preserves layered Site Safety scores in stored scan metadata", () => {
  assert.equal(contentSource.includes("siteSafetyDataSource: lastSummary.siteSafetyDataSource"), true);
  assert.equal(contentSource.includes("domainTrustScore: String(lastSummary.domainTrustScore"), true);
  assert.equal(contentSource.includes("pageTrustScore: String(lastSummary.pageTrustScore"), true);
  assert.equal(contentSource.includes("contentRiskScore: String(lastSummary.contentRiskScore"), true);
  assert.equal(contentSource.includes("finalHipScore: String(lastSummary.finalHipScore"), true);
  assert.equal(contentSource.includes("browserScanAssessment(currentLookup, lastSummary)"), true);
  assert.equal(browserScanAssessmentSource.includes("function mapSiteSafetyStatus"), true);
});

test("content script is guarded against duplicate dev-time injection", () => {
  assert.equal(contentSource.includes("window.__hipContentScriptLoaded"), true);
  assert.equal(contentSource.includes("return;"), true);
});

test("background worker handles automatic Site Safety requests without noisy warnings", () => {
  assert.equal(backgroundSource.includes('message?.type === "HIP_SCAN_SITE_SAFETY"'), true);
  assert.equal(backgroundSource.includes("function safeSiteSafetyError"), true);
  assert.equal(backgroundSource.includes('console.warn("HIP Site Safety'), false);
});

test("manifest uses root service worker wrapper for reliable unpacked reloads", () => {
  const manifest = JSON.parse(manifestSource);

  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.background.type, "module");
  assert.equal(workerWrapperSource.includes('import "./src/background.js";'), true);
});

test("popup starts scanner once when no cached page-load summary exists", () => {
  assert.equal(popupSource.includes("startContentScanIfNeeded"), true);
  assert.equal(popupSource.includes("popupStartedContentScan"), true);
  assert.equal(popupSource.includes("chrome.scripting.executeScript"), true);
  assert.equal(popupSource.includes('"src/content.js"'), true);
});

test("popup probes badge markup directly when an already-open tab has no content summary", () => {
  assert.equal(popupSource.includes("function observeHipBadgeInActiveTab"), true);
  assert.equal(popupSource.includes('querySelectorAll("[data-hip-badge], .hip-trust-badge[data-domain]")'), true);
  assert.equal(popupSource.includes("hipBadgeObserved: badges.length > 0"), true);
  assert.equal(popupSource.includes("hipBadgeDomainMatch: matchesPage"), true);
});

test("popup reads the content summary directly when the service worker cache is empty", () => {
  assert.equal(popupSource.includes("function getContentScriptSummary"), true);
  assert.equal(popupSource.includes('type: "HIP_GET_CONTENT_SUMMARY"'), true);
  assert.equal(popupSource.includes("const summary = contentSummary || response?.result || {}"), true);
});

test("popup verifies refresh responses and retries injection safely", () => {
  assert.equal(popupSource.includes("if (response?.ok)"), true);
  assert.equal(popupSource.includes("return response?.ok === true"), true);
  assert.equal(popupSource.includes('console.warn("HIP content scanner startup unavailable."'), false);
});

test("popup renders completed content-script Site Safety before duplicate API scan", () => {
  const summaryIndex = popupSource.indexOf("const summarySiteSafety = siteSafetyResultFromSummary(summary);");
  const renderIndex = popupSource.indexOf("return renderSiteSafetyResult(summarySiteSafety);", summaryIndex);
  const apiScanIndex = popupSource.indexOf("const result = await client.scanSiteSafety(request);", renderIndex);

  assert.equal(summaryIndex > -1, true);
  assert.equal(renderIndex > summaryIndex, true);
  assert.equal(apiScanIndex > renderIndex, true);
  assert.equal(popupSource.includes("function isCompleteSiteSafetySummary"), true);
});

test("popup fallback injection includes every content script dependency", () => {
  const rendererIndex = popupSource.indexOf('"src/riskBadgeRenderer.js"');
  const routerIndex = popupSource.indexOf('"src/safetyPageRouter.js"');
  const privacyIndex = popupSource.indexOf('"src/browserPrivacyGuards.js"');
  const assessmentIndex = popupSource.indexOf('"src/browserScanAssessment.js"');
  const contentIndex = popupSource.indexOf('"src/content.js"');

  assert.equal(rendererIndex > -1, true);
  assert.equal(routerIndex > rendererIndex, true);
  assert.equal(privacyIndex > routerIndex, true);
  assert.equal(assessmentIndex > privacyIndex, true);
  assert.equal(contentIndex > assessmentIndex, true);
  assert.equal(popupSource.includes("HIP content scanner not attached yet; attempting one-time injection."), false);
});

test("popup skips site safety scan for ineligible local HIP pages", () => {
  assert.equal(popupSource.includes("isSiteSafetyScanEligibleUrl"), true);
  assert.equal(popupSource.includes("!activeTabUrl || !isSiteSafetyScanEligibleUrl(activeTabUrl, settings)"), true);
  assert.equal(popupSource.includes("renderSiteSafetyNotRun"), true);
  assert.equal(popupSource.includes('elements.siteSafetyStatus.textContent = "Not run"'), true);
});

test("popup handles optional site safety failures without extension warning noise", () => {
  assert.equal(popupSource.includes("handleSiteSafetyUnavailable"), true);
  assert.equal(popupSource.includes("console.warn(\"HIP Site Safety Scan unavailable."), false);
});

test("popup renders completed lookup fields before waiting for optional site safety", () => {
  const lookupReadyIndex = popupSource.indexOf("activeLookup = lookup;");
  const initialLookupIndex = popupSource.indexOf("renderLookup(lookup, {});", lookupReadyIndex);
  const summaryIndex = popupSource.indexOf("activeSummary = summary;", initialLookupIndex);
  const safetyIndex = popupSource.indexOf("await renderSiteSafety(summary)", summaryIndex);

  assert.equal(initialLookupIndex > lookupReadyIndex, true);
  assert.equal(summaryIndex > initialLookupIndex, true);
  assert.equal(safetyIndex > summaryIndex, true);
});

test("popup starts Site Safety independently and never overwrites its terminal state with loading copy", () => {
  const safetyPromiseIndex = popupSource.indexOf("const safetyPromise = renderSiteSafety({}).catch(handleSiteSafetyUnavailable);");
  const summaryWaitIndex = popupSource.indexOf("const summary = await waitForScanSummary();", safetyPromiseIndex);

  assert.equal(safetyPromiseIndex > -1, true);
  assert.equal(summaryWaitIndex > safetyPromiseIndex, true);
  assert.equal(popupSource.includes("if (!siteSafetyTerminal)"), true);
  assert.equal(popupSource.match(/siteSafetyTerminal = true;/g).length >= 3, true);
});

test("HIP API client uses a shared fetch timeout wrapper", () => {
  assert.equal(HIP_FETCH_TIMEOUT_MS, 8000);
  assert.equal(apiClientSource.includes("export async function fetchWithTimeout"), true);
  assert.equal(apiClientSource.match(/await fetchWithTimeout/g).length >= 8, true);
});

test("popup scan messaging has deadlines and terminalizes pending results", () => {
  assert.match(popupSource, /withDeadline\(getScanSummary\(\), extensionMessageDeadlineMs, \{\}\)/);
  assert.match(popupSource, /withDeadline\(startContentScanIfNeeded\(\), extensionMessageDeadlineMs, false\)/);
  assert.match(popupSource, /function settlePendingResults\(\)/);
  assert.match(popupSource, /if \(\/checking\|scanning\/i\.test/);
  assert.match(popupSource, /settlePendingResults\(\);/);
  const loadingRenderer = popupSource.slice(popupSource.indexOf("function renderLoadingSummary"), popupSource.indexOf("function renderSummary"));
  assert.match(loadingRenderer, /if \(!siteSafetyTerminal\)[\s\S]*malwareRisk\.textContent = "Checking\.\.\."/);
  assert.doesNotMatch(loadingRenderer, /}\s*elements\.malwareRisk\.textContent = "Checking\.\.\."/);
});

test("fetch timeout wrapper aborts slow API calls", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      reject(error);
    });
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout("http://localhost:5099/api/v1/browser/score-site", {}, 1),
      /HIP request timed out/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
