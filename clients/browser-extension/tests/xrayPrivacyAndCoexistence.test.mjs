import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [rules, renderer, controller, content, manifestText] = await Promise.all([
  readFile(new URL("../src/xrayRules.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayRenderer.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayController.js", import.meta.url), "utf8"),
  readFile(new URL("../src/content.js", import.meta.url), "utf8"),
  readFile(new URL("../manifest.json", import.meta.url), "utf8")
]);

test("X-ray never reads entered values or private browser data", () => {
  const combined = `${rules}\n${renderer}\n${controller}`;
  assert.doesNotMatch(combined, /\.value\b|getSelection|clipboard|cookie|localStorage|sessionStorage|outerHTML|innerHTML/);
  assert.doesNotMatch(combined, /crypto\.subtle|fetch\s*\(|sendMessage\s*\(/);
  assert.match(rules, /PRIVATE_CONTENT_SELECTOR/);
});

test("X-ray owns one isolated shadow root and does not alter host forms", () => {
  assert.match(renderer, /attachShadow\(\{ mode: "open" \}\)/);
  assert.match(renderer, /pointer-events:\s*none/);
  assert.doesNotMatch(renderer, /insertBefore|setAttribute\(|removeAttribute\(|autofocus|autocomplete/);
  assert.doesNotMatch(renderer, /\.focus\s*\(/);
  assert.doesNotMatch(controller, /document\.addEventListener/);
});

test("panel exposes accessibility semantics and honors reduced motion", () => {
  assert.match(renderer, /ariaLabel = "HIP X-ray findings"/);
  assert.match(renderer, /ariaLive = "polite"/);
  assert.match(renderer, /role = "toolbar"/);
  assert.match(renderer, /prefers-reduced-motion: reduce/);
  assert.match(renderer, /prefersReducedMotion\(\) \? "auto" : "smooth"/);
});

test("X-ray is explicit and does not run during automatic content startup", () => {
  const startHandler = content.indexOf('message?.type === "HIP_XRAY_START"');
  const automaticScan = content.indexOf("runScan().catch(handleInitializationError)");
  assert.ok(startHandler > -1);
  assert.ok(automaticScan > -1);
  assert.doesNotMatch(content, /installXrayLauncher\(\)\.start\(\)/);
  assert.match(content, /installLauncher\(\)/);
});

test("page trigger and scan theatre match the marketing-site interaction language", () => {
  assert.match(renderer, /X-ray this page/);
  assert.match(renderer, /HIP · SCANNING THIS PAGE/);
  assert.match(renderer, /SCAN_ANIMATION_MS\s*=\s*2600/);
  assert.match(renderer, /linear-gradient\(90deg, transparent, #14b8a6, transparent\)/i);
  assert.match(renderer, /Satoshi/);
  assert.match(renderer, /JetBrains Mono/);
  assert.match(renderer, /finding-row/);
  assert.match(renderer, /targetOffsets/);
});

test("scan theatre transitions into the marketing-style trust result", () => {
  assert.match(renderer, /className = "scan-view"|"scan-view"/);
  assert.match(renderer, /className = "result-view"|"result-view"/);
  assert.match(renderer, /scanning this page/i);
  assert.match(renderer, /Reading page structure/);
  assert.match(renderer, /Applying local HIP rules/);
  assert.match(renderer, /hip · trust result/i);
  assert.match(renderer, /result-score/);
  assert.match(renderer, /result-progress-fill/);
  assert.match(renderer, /Every score comes with its reasons\. Nothing is hidden\./);
});

test("manifest permissions remain unchanged and X-ray dependencies load before content", () => {
  const manifest = JSON.parse(manifestText);
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "storage"]);
  assert.equal(manifest.permissions.includes("debugger"), false);
  const scripts = manifest.content_scripts[0].js;
  for (const file of ["src/xrayRules.js", "src/xrayRenderer.js", "src/xrayController.js"]) {
    assert.ok(scripts.indexOf(file) > -1);
    assert.ok(scripts.indexOf(file) < scripts.indexOf("src/content.js"));
  }
});

test("collection and mutation work are capped", () => {
  assert.match(rules, /MAX_SCANNED_ELEMENTS\s*=\s*2500/);
  assert.match(rules, /MAX_TEXT_SIGNAL_ELEMENTS\s*=\s*400/);
  assert.match(controller, /MAX_AUTOMATIC_RESCANS\s*=\s*12/);
});
