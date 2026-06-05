import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const rendererSource = readFileSync(new URL("../src/riskBadgeRenderer.js", import.meta.url), "utf8");
const backgroundSource = readFileSync(new URL("../src/background.js", import.meta.url), "utf8");
const contentSource = readFileSync(new URL("../src/content.js", import.meta.url), "utf8");
const optionsSource = readFileSync(new URL("../src/options.html", import.meta.url), "utf8");

test("trust banner dismissal uses extension storage instead of page localStorage", () => {
  assert.equal(rendererSource.includes("localStorage"), false);
  assert.equal(backgroundSource.includes("chrome.storage.local"), true);
  assert.equal(backgroundSource.includes("HIP_SET_BANNER_DISMISSED"), true);
  assert.equal(backgroundSource.includes("HIP_GET_BANNER_DISMISSED"), true);
});

test("trust banner dismissal is scoped to current page hash", () => {
  assert.equal(contentSource.includes("pageKey = await sha256(window.location.href)"), true);
  assert.equal(contentSource.includes("pageKey"), true);
  assert.equal(backgroundSource.includes("pageKey || \"domain\""), true);
});

test("trust banner renders safe and suspicious feedback buttons", () => {
  assert.equal(rendererSource.includes("Looks Safe"), true);
  assert.equal(rendererSource.includes("Looks Suspicious"), true);
  assert.equal(rendererSource.includes("data-hip-feedback=\"LooksSafe\""), true);
  assert.equal(rendererSource.includes("data-hip-feedback=\"LooksSuspicious\""), true);
});

test("trust banner labels feedback instead of voting", () => {
  assert.equal(rendererSource.includes("trust feedback"), true);
  assert.equal(rendererSource.toLowerCase().includes("vote"), false);
});

test("trust banner renders readable status labels and plain-English fallback reason", () => {
  assert.equal(rendererSource.includes("Mostly Trusted"), true);
  assert.equal(rendererSource.includes("HIP does not have enough verified trust history for this website yet."), true);
  assert.equal(rendererSource.includes("HIP has not found a stronger public trust signal"), false);
});

test("trust banner supports notice warning and dangerous copy", () => {
  assert.equal(rendererSource.includes("HIP Warning: Dangerous Site"), true);
  assert.equal(rendererSource.includes("HIP Warning: This page may be risky."), true);
  assert.equal(contentSource.includes("This page has limited trust data and contains login fields."), true);
  assert.equal(contentSource.includes("This page has limited trust data and links to an executable download."), true);
});

test("banner runtime does not collect private page data", () => {
  assert.equal(contentSource.includes("document.body.innerText"), false);
  assert.equal(contentSource.includes("input.value"), false);
  assert.equal(contentSource.includes("textarea.value"), false);
  assert.equal(contentSource.includes("formData"), false);
  assert.equal(contentSource.includes("localStorage"), false);
  assert.equal(contentSource.includes("passwordFieldsDetected"), true);
});

test("options page exposes banner display mode foundation", () => {
  assert.equal(optionsSource.includes("bannerDisplayMode"), true);
  assert.equal(optionsSource.includes("WarningsOnly"), true);
  assert.equal(optionsSource.includes("DangerousOnly"), true);
  assert.equal(optionsSource.includes("AlwaysShow"), true);
  assert.equal(optionsSource.includes("NeverShow"), true);
});
