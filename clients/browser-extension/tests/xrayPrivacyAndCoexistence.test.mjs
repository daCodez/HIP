import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [rules, renderer, controller, content, sidePanel, manifestText] = await Promise.all([
  readFile(new URL("../src/xrayRules.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayRenderer.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayController.js", import.meta.url), "utf8"),
  readFile(new URL("../src/content.js", import.meta.url), "utf8"),
  readFile(new URL("../src/sidepanel.js", import.meta.url), "utf8"),
  readFile(new URL("../manifest.json", import.meta.url), "utf8")
]);

test("X-ray never reads entered values or private browser data", () => {
  const scanner = `${rules}\n${renderer}\n${controller}`;
  assert.doesNotMatch(scanner, /\.value\b|getSelection|clipboard|cookie|localStorage|sessionStorage|outerHTML|innerHTML/);
  assert.doesNotMatch(sidePanel, /pageText|formValue|inputValue|cookieValue|authToken|privateMessage/);
  assert.doesNotMatch(`${rules}\n${renderer}\n${controller}`, /crypto\.subtle|fetch\s*\(|sendMessage\s*\(/);
  assert.match(rules, /PRIVATE_CONTENT_SELECTOR/);
});

test("X-ray owns one isolated shadow marker root and does not alter host forms", () => {
  assert.match(renderer, /attachShadow\(\{ mode: "open" \}\)/);
  assert.match(renderer, /pointer-events:none/);
  assert.doesNotMatch(renderer, /insertBefore|removeAttribute\(|autofocus|autocomplete|target\.focus/);
  assert.doesNotMatch(controller, /document\.addEventListener/);
});

test("marker layer exposes announcements and honors reduced motion", () => {
  assert.match(renderer, /ariaLive = "polite"/);
  assert.match(renderer, /prefers-reduced-motion:reduce/);
  assert.match(renderer, /prefersReducedMotion\(\) \? "auto" : "smooth"/);
});

test("X-ray remains explicit and automatic Site Safety stays independent", () => {
  assert.ok(content.indexOf('message?.type === "HIP_XRAY_START"') > -1);
  assert.ok(content.indexOf("runScan().catch(handleInitializationError)") > -1);
  assert.doesNotMatch(content, /createXraySession\(\)\.start\(\)/);
});

test("the page keeps only scan sweep, markers, highlights, and announcements", () => {
  assert.match(renderer, /SCAN_ANIMATION_MS\s*=\s*2600/);
  assert.match(renderer, /linear-gradient\(90deg, transparent, #14b8a6, transparent\)/i);
  assert.match(renderer, /marker-frame/);
  assert.match(renderer, /marker-label/);
  assert.match(renderer, /ariaLive/);
  assert.doesNotMatch(renderer, /results-pill|finding-row|className = "hud"|X-ray this page/);
});

test("manifest adds only the reviewed persistent side-panel runtime permissions", () => {
  const manifest = JSON.parse(manifestText);
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "storage", "sidePanel", "tabs"]);
  assert.equal(manifest.permissions.includes("debugger"), false);
});

test("collection and mutation work are capped", () => {
  assert.match(rules, /MAX_SCANNED_ELEMENTS\s*=\s*2500/);
  assert.match(rules, /MAX_TEXT_SIGNAL_ELEMENTS\s*=\s*400/);
  assert.match(controller, /MAX_AUTOMATIC_RESCANS\s*=\s*12/);
});
