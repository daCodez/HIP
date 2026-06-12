import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fetchWithTimeout, HIP_FETCH_TIMEOUT_MS } from "../src/hipApiClient.js";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const apiClientSource = await readFile(new URL("../src/hipApiClient.js", import.meta.url), "utf8");

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

test("content script is guarded against duplicate dev-time injection", () => {
  assert.equal(contentSource.includes("window.__hipContentScriptLoaded"), true);
  assert.equal(contentSource.includes("return;"), true);
});

test("popup starts scanner once when no cached page-load summary exists", () => {
  assert.equal(popupSource.includes("startContentScanIfNeeded"), true);
  assert.equal(popupSource.includes("popupStartedContentScan"), true);
  assert.equal(popupSource.includes("chrome.scripting.executeScript"), true);
  assert.equal(popupSource.includes('"src/content.js"'), true);
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
