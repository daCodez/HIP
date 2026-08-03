import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const [rendererSource, controllerSource, rulesSource] = await Promise.all([
  readFile(new URL("../src/xrayRenderer.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayController.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayRules.js", import.meta.url), "utf8")
]);
const sandbox = { globalThis: {} };
vm.runInNewContext(rendererSource, sandbox, { filename: "xrayRenderer.js" });
const renderer = sandbox.globalThis.HipXrayRenderer;

test("result rows and markers share stable finding IDs", () => {
  assert.match(rendererSource, /item\.dataset\.findingId = finding\.id/);
  assert.match(rendererSource, /row\.dataset\.findingId = finding\.id/);
  assert.match(rendererSource, /marker\.dataset\.findingId = finding\.id/);
  assert.match(rulesSource, /id:\s*`\$\{ruleId\}:\$\{element\.refKey\}`/);
});

test("marker lifecycle replaces old overlays and retains every located finding", () => {
  assert.match(rendererSource, /replaceChildren\(markerLayer\)/);
  assert.match(rendererSource, /findings\.forEach\(\(finding, index\)/);
  assert.match(rendererSource, /markerNodes = \[\]/);
  assert.match(rendererSource, /theatre\?\.remove\(\)/);
});

test("results and markers navigate in both directions", () => {
  assert.match(rendererSource, /target\.scrollIntoView\?\.\(/);
  assert.match(rendererSource, /emphasizeMarker\(finding\.id\)/);
  assert.match(rendererSource, /function activateMarker\(finding\)[\s\S]*focusRow: true, fromMarker: true[\s\S]*expandPanel\(false\)/);
  assert.match(rendererSource, /Element no longer available/);
});

test("panel supports collapse, reopen, filters, and marker visibility", () => {
  for (const pattern of [/collapsePanel/, /expandPanel/, /results-pill/, /data-severity-filter/, /category-filter/, /markersHidden/]) {
    assert.match(rendererSource, pattern);
  }
  assert.match(rendererSource, /ariaPressed = String\(!markersHidden\)/);
});

test("collision placement avoids the selected target before marker density", () => {
  const result = renderer.choosePanelPlacement(
    { width: 1000, height: 700 },
    { width: 300, height: 260 },
    [{ left: 680, top: 20, right: 980, bottom: 280, width: 300, height: 260 }],
    { left: 20, top: 20, right: 320, bottom: 280, width: 300, height: 260 }
  );
  assert.equal(result.selectedOverlap, 0);
  assert.equal(result.obstacleOverlap, 0);
  assert.match(result.dock, /^bottom-/);
});

test("placement stays in narrow and zoomed-style viewports", () => {
  const result = renderer.choosePanelPlacement({ width: 320, height: 480 }, { width: 600, height: 700 }, [], null, 8);
  assert.ok(result.rect.left >= 8);
  assert.ok(result.rect.top >= 8);
  assert.ok(result.rect.right <= 312);
  assert.ok(result.rect.bottom <= 472);
});

test("dynamic layout support is bounded and cleans navigation state", () => {
  assert.match(rendererSource, /ResizeObserver/);
  assert.match(controllerSource, /requestAnimationFrame/);
  assert.match(controllerSource, /MAX_AUTOMATIC_RESCANS\s*=\s*12/);
  assert.match(controllerSource, /popstate/);
  assert.match(controllerSource, /hashchange/);
  assert.match(controllerSource, /ROUTE_POLL_MS/);
  assert.match(controllerSource, /resetForNavigation/);
  assert.match(controllerSource, /!renderer\.isMounted\(\)/);
  assert.match(rendererSource, /reference\?\.selector/);
  assert.match(rendererSource, /target\?\.isConnected/);
});

test("accessibility and reduced-motion behavior remain explicit", () => {
  assert.match(rendererSource, /type = "button"/);
  assert.match(rendererSource, /ariaLabel/);
  assert.match(rendererSource, /ariaPressed/);
  assert.match(rendererSource, /prefers-reduced-motion:reduce/);
  assert.match(rendererSource, /behavior: prefersReducedMotion\(\) \? "auto" : "smooth"/);
  assert.match(rendererSource, /outline:4px double/);
});

test("only explicit HIP markers accept pointer input", () => {
  assert.match(rendererSource, /\.marker-layer\{[^}]*pointer-events:none/);
  assert.match(rendererSource, /\.marker-frame\{pointer-events:none/);
  assert.match(rendererSource, /\.marker\{pointer-events:auto/);
  assert.match(rendererSource, /\.scrim\{pointer-events:none/);
});

test("host forms and editable content remain isolated from HIP controls", () => {
  const combined = `${rulesSource}\n${rendererSource}\n${controllerSource}`;
  assert.match(rulesSource, /PRIVATE_CONTENT_SELECTOR/);
  assert.doesNotMatch(combined, /\.value\b|inputValue|FormData|contentDocument\?\.body|console\.(?:log|info|debug)/);
  assert.doesNotMatch(rendererSource, /appendChild\([^)]*target|target\.append|target\.prepend|insertAdjacent/);
  assert.doesNotMatch(controllerSource, /capture:\s*true/);
});

test("media labels preserve provenance uncertainty", () => {
  assert.equal(renderer.markerSummary({ category: "Media provenance", title: "Unknown origin", severity: "Low" }), "Media · Origin unknown");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Unverified image", severity: "Medium" }), "Media · Origin unknown");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Image", evidence: "No provenance evidence", severity: "High" }), "Media · Unverified");
  assert.equal(renderer.markerSummary({ category: "Media", title: "Confirmed AI disclosure", severity: "Low" }), "Media · Confirmed AI");
});

test("long marker labels are bounded and mobile layouts stay within the viewport", () => {
  assert.equal(renderer.markerSummary({ category: "x".repeat(100), severity: "High" }).length, 62);
  assert.match(rendererSource, /max-width:240px/);
  assert.match(rendererSource, /text-overflow:ellipsis/);
  assert.match(rendererSource, /@media\(max-width:620px\)/);
});
