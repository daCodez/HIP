import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const [rendererSource, controllerSource, rulesSource, sidePanelSource, sidePanelHtml] = await Promise.all([
  readFile(new URL("../src/xrayRenderer.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayController.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayRules.js", import.meta.url), "utf8"),
  readFile(new URL("../src/sidepanel.js", import.meta.url), "utf8"),
  readFile(new URL("../src/sidepanel.html", import.meta.url), "utf8")
]);
const sandbox = { globalThis: {} };
vm.runInNewContext(rendererSource, sandbox, { filename: "xrayRenderer.js" });
const renderer = sandbox.globalThis.HipXrayRenderer;

test("side-panel rows and page markers share stable finding IDs", () => {
  assert.match(sidePanelSource, /button\.dataset\.findingId = finding\.findingId/);
  assert.match(rendererSource, /marker\.dataset\.findingId = finding\.id/);
  assert.match(rulesSource, /id:\s*`\$\{ruleId\}:\$\{element\.refKey\}`/);
});

test("marker lifecycle replaces stale overlays and retains located findings", () => {
  assert.match(rendererSource, /markerLayer\?\.replaceChildren\(\)/);
  assert.match(rendererSource, /findings\.forEach\(\(finding, index\)/);
  assert.match(rendererSource, /markerNodes = \[\]/);
  assert.match(rendererSource, /host\?\.remove\(\)/);
});

test("side-panel findings navigate to page targets with one bounded retry", () => {
  assert.match(sidePanelSource, /HIP_XRAY_SELECT_FINDING/);
  assert.match(rendererSource, /target\.scrollIntoView\?\.\(/);
  assert.match(rendererSource, /emphasizeMarker\(finding\.id\)/);
  assert.match(controllerSource, /if \(result\.status === "missing"\)[\s\S]*runScan\(false\)[\s\S]*selectFinding/);
  assert.match(rendererSource, /Element no longer available/);
});

test("results, filters, inventory, and marker controls live only in the side panel", () => {
  for (const value of ["severityFilter", "categoryFilter", "kindFilter", "loadMoreInventory", "markerToggle"]) assert.match(sidePanelHtml, new RegExp(value));
  assert.doesNotMatch(rendererSource, /className = "hud"|results-pill|collapsePanel|buildFindingRows/);
  assert.doesNotMatch(rendererSource, /X-ray this page/);
});

test("dynamic layout support is bounded and cleans navigation state", () => {
  assert.match(rendererSource, /ResizeObserver/);
  assert.match(controllerSource, /requestAnimationFrame/);
  assert.match(controllerSource, /MAX_AUTOMATIC_RESCANS\s*=\s*12/);
  assert.match(controllerSource, /popstate/);
  assert.match(controllerSource, /hashchange/);
  assert.match(controllerSource, /ROUTE_POLL_MS/);
  assert.match(rendererSource, /reference\?\.selector/);
  assert.match(rendererSource, /target\?\.isConnected/);
});

test("accessibility and reduced-motion behavior remain explicit", () => {
  assert.match(rendererSource, /marker\.type = "button"/);
  assert.match(rendererSource, /ariaLabel/);
  assert.match(rendererSource, /ariaLive = "polite"/);
  assert.match(rendererSource, /prefers-reduced-motion:reduce/);
  assert.match(rendererSource, /prefersReducedMotion\(\) \? "auto" : "smooth"/);
  assert.match(rendererSource, /outline:4px double/);
});

test("only explicit HIP markers accept pointer input", () => {
  assert.match(rendererSource, /\.marker-layer\{pointer-events:none/);
  assert.match(rendererSource, /\.marker-frame\{[^}]*pointer-events:none/);
  assert.match(rendererSource, /\.marker\{[^}]*pointer-events:auto/);
  assert.match(rendererSource, /\.scrim[^}]*pointer-events:none/);
});

test("host forms and editable content remain isolated from HIP controls", () => {
  const combined = `${rulesSource}\n${rendererSource}\n${controllerSource}`;
  assert.match(rulesSource, /PRIVATE_CONTENT_SELECTOR/);
  assert.doesNotMatch(combined, /\.value\b|inputValue|FormData|console\.(?:log|info|debug)/);
  assert.doesNotMatch(rendererSource, /target\.append|target\.prepend|insertAdjacent/);
  assert.doesNotMatch(controllerSource, /capture:\s*true/);
});

test("media labels preserve provenance uncertainty", () => {
  assert.equal(renderer.markerSummary({ category: "Media provenance", title: "Unknown origin", severity: "Low" }), "Media · Origin unknown");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Unverified image", severity: "Medium" }), "Media · Origin unknown");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Image", evidence: "No provenance evidence", severity: "High" }), "Media · Unverified");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Confirmed AI disclosure", severity: "Low" }), "Media · Confirmed AI");
});

test("long marker labels are bounded and narrow layouts stay within the viewport", () => {
  assert.equal(renderer.markerSummary({ category: "x".repeat(100), severity: "High" }).length, 62);
  assert.match(rendererSource, /max-width:240px/);
  assert.match(rendererSource, /text-overflow:ellipsis/);
  assert.match(rendererSource, /@media\(max-width:620px\)/);
});
