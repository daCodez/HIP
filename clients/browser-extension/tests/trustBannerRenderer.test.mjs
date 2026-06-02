import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const rendererSource = readFileSync(new URL("../src/riskBadgeRenderer.js", import.meta.url), "utf8");

test("trust banner saves dismissed state in localStorage", () => {
  assert.equal(rendererSource.includes("window.localStorage.setItem"), true);
  assert.equal(rendererSource.includes("hip:trust-banner-dismissed:"), true);
  assert.equal(rendererSource.includes("isBannerDismissed"), true);
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
