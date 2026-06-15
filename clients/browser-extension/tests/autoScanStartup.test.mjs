import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fetchWithTimeout, HIP_FETCH_TIMEOUT_MS } from "../src/hipApiClient.js";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const apiClientSource = await readFile(new URL("../src/hipApiClient.js", import.meta.url), "utf8");
const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const manifestSource = await readFile(new URL("../manifest.json", import.meta.url), "utf8");
const workerWrapperSource = await readFile(new URL("../background.js", import.meta.url), "utf8");

test("content script publishes scan progress before site scoring", () => {
  const startupIndex = contentSource.indexOf('markScanStage("Starting")');
  const publishIndex = contentSource.indexOf("publishSummary();", startupIndex);
  const scoreIndex = contentSource.indexOf("const currentLookup = await scoreSite");

  assert.equal(startupIndex > -1, true);
  assert.equal(publishIndex > startupIndex, true);
  assert.equal(scoreIndex > publishIndex, true);
});

test("content script publishes safe failure summary when initialization fails", () => {
  assert.equal(contentSource.includes("initialize().catch(handleInitializationError);"), true);
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
  const persistIndex = contentSource.indexOf("await persistScanResult(currentLookup)");

  assert.equal(siteSafetyIndex > collectIndex, true);
  assert.equal(persistIndex > siteSafetyIndex, true);
  assert.equal(contentSource.includes('type: "HIP_SCAN_SITE_SAFETY"'), true);
  assert.equal(contentSource.includes("buildSiteSafetyRequest()"), true);
});

test("content script skips private and HIP owned URLs before Site Safety", () => {
  assert.equal(contentSource.includes("function isSiteSafetyEligibleUrl"), true);
  assert.equal(contentSource.includes("!isHipOwnedPage(pageUrl, settings)"), true);
  assert.equal(contentSource.includes("!isInternalHost(url.hostname)"), true);
  assert.equal(contentSource.includes("function filterSafePublicUrls"), true);
});

test("content script preserves layered Site Safety scores in stored scan metadata", () => {
  assert.equal(contentSource.includes("siteSafetyDataSource: lastSummary.siteSafetyDataSource"), true);
  assert.equal(contentSource.includes("domainTrustScore: String(lastSummary.domainTrustScore"), true);
  assert.equal(contentSource.includes("pageTrustScore: String(lastSummary.pageTrustScore"), true);
  assert.equal(contentSource.includes("contentRiskScore: String(lastSummary.contentRiskScore"), true);
  assert.equal(contentSource.includes("finalHipScore: String(lastSummary.finalHipScore"), true);
  assert.equal(contentSource.includes("function mapSiteSafetyStatus"), true);
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

test("popup skips site safety scan for ineligible local HIP pages", () => {
  assert.equal(popupSource.includes("isSiteSafetyScanEligibleUrl"), true);
  assert.equal(popupSource.includes("!activeTabUrl || !isSiteSafetyScanEligibleUrl(activeTabUrl, settings)"), true);
});

test("popup handles optional site safety failures without extension warning noise", () => {
  assert.equal(popupSource.includes("handleSiteSafetyUnavailable"), true);
  assert.equal(popupSource.includes("console.warn(\"HIP Site Safety Scan unavailable."), false);
});

test("HIP API client uses a shared fetch timeout wrapper", () => {
  assert.equal(HIP_FETCH_TIMEOUT_MS, 8000);
  assert.equal(apiClientSource.includes("export async function fetchWithTimeout"), true);
  assert.equal(apiClientSource.match(/await fetchWithTimeout/g).length >= 8, true);
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
