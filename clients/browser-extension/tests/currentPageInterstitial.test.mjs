import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const routerSource = readFileSync(new URL("../src/safetyPageRouter.js", import.meta.url), "utf8");

function loadRouter() {
  const window = {};
  vm.runInNewContext(routerSource, { window, document: {} });
  return window.HipSafetyPageRouter;
}

test("current-page interstitial requires completed high-confidence critical evidence", () => {
  const router = loadRouter();
  const high = { status: "Critical", confidenceLevel: "High", finalHipScore: 4 };

  assert.equal(router.shouldBlockCurrentPage({}, high, {}), true);
  assert.equal(router.shouldBlockCurrentPage({}, { ...high, confidenceLevel: "Medium" }, {}), false);
  assert.equal(router.shouldBlockCurrentPage({}, { ...high, finalHipScore: null }, {}), false);
  assert.equal(router.shouldBlockCurrentPage({}, { ...high, status: "Suspicious" }, {}), false);
  assert.equal(router.shouldBlockCurrentPage({}, { ...high, status: "HighRisk" }, {}), false);
  assert.equal(router.shouldBlockCurrentPage({ ...high }, null, {}), false);
});

test("explicit server blocking disposition is honored without exposing detection thresholds", () => {
  const router = loadRouter();
  const result = {
    status: "Dangerous",
    confidenceLevel: "High",
    finalHipScore: 8,
    blockingDisposition: "Block"
  };

  assert.equal(router.shouldBlockCurrentPage({}, result, {}), true);
  assert.equal(router.shouldBlockCurrentPage({}, result, { enableSafetyPageRouting: false }), false);
});

test("interstitial uses isolated styling and explicit accessible controls", () => {
  assert.equal(routerSource.includes('attachShadow({ mode: "open" })'), true);
  assert.equal(routerSource.includes('role", "alertdialog"'), true);
  assert.equal(routerSource.includes("trapDialogFocus"), true);
  assert.equal(routerSource.includes('proceed.textContent = "Continue anyway"'), true);
  assert.equal(routerSource.includes('leave.textContent = "Leave this page"'), true);
  assert.equal(routerSource.includes("page body"), false);
  assert.equal(routerSource.includes("form.value"), false);
  assert.equal(routerSource.includes("input.value"), false);
});
