import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const rendererSource = readFileSync(new URL("../src/riskBadgeRenderer.js", import.meta.url), "utf8");
const backgroundSource = readFileSync(new URL("../src/background.js", import.meta.url), "utf8");
const optionsSource = readFileSync(new URL("../src/options.html", import.meta.url), "utf8");

test("trust banner dismissal uses extension storage instead of page localStorage", () => {
  assert.equal(rendererSource.includes("localStorage"), false);
  assert.equal(backgroundSource.includes("chrome.storage.local"), true);
  assert.equal(backgroundSource.includes("HIP_SET_BANNER_DISMISSED"), true);
  assert.equal(backgroundSource.includes("HIP_GET_BANNER_DISMISSED"), true);
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

test("options page exposes banner display mode foundation", () => {
  assert.equal(optionsSource.includes("bannerDisplayMode"), true);
  assert.equal(optionsSource.includes("WarningsOnly"), true);
  assert.equal(optionsSource.includes("DangerousOnly"), true);
  assert.equal(optionsSource.includes("AlwaysShow"), true);
  assert.equal(optionsSource.includes("NeverShow"), true);
});
