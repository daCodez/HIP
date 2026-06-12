import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const extensionRoot = fileURLToPath(new URL("../", import.meta.url));

test("trust banner displays plugin version in dev MVP mode", () => {
  const renderer = read("src/riskBadgeRenderer.js");

  assert.match(renderer, /renderTrustBanner/);
  assert.match(renderer, /hip-trust-version/);
  assert.match(renderer, /pluginVersion/);
});

test("trust banner includes status badge and close control", () => {
  const renderer = read("src/riskBadgeRenderer.js");

  assert.match(renderer, /hip-trust-status-badge/);
  assert.match(renderer, /hip-trust-close/);
});

test("popup displays plugin version in dev MVP mode", () => {
  const popupHtml = read("src/popup.html");
  const popupScript = read("src/popup.js");

  assert.match(popupHtml, /id="pluginVersion"/);
  assert.match(popupScript, /HIP_GET_PLUGIN_VERSION/);
});

test("version comes from manifest through background and shared formatter", () => {
  const manifest = JSON.parse(read("manifest.json"));
  const background = read("src/background.js");
  const client = read("src/hipApiClient.js");

  assert.equal(manifest.version, "0.1.1");
  assert.match(background, /chrome\.runtime\.getManifest\(\)\.version/);
  assert.match(background, /formatPluginVersion/);
  assert.match(client, /formatPluginVersion/);
});

test("version is not duplicated as hardcoded display text across UI files", () => {
  const files = [
    "src/background.js",
    "src/content.js",
    "src/options.js",
    "src/popup.js",
    "src/riskBadgeRenderer.js",
    "src/hipApiClient.js"
  ];
  const hardcodedDisplayCount = files
    .map(read)
    .reduce((count, content) => count + (content.match(/HIP Plugin v0\.1\.0-dev/g) || []).length, 0);

  assert.equal(hardcodedDisplayCount, 0);
});

test("content summary cannot read plugin version before initialization", () => {
  const content = read("src/content.js");
  const versionDeclaration = content.indexOf('let pluginVersion = "HIP Plugin vunknown-dev";');
  const summaryDeclaration = content.indexOf("let lastSummary = emptySummary();");

  assert.notEqual(versionDeclaration, -1);
  assert.notEqual(summaryDeclaration, -1);
  assert.ok(versionDeclaration < summaryDeclaration);
});

function read(relativePath) {
  return readFileSync(join(extensionRoot, relativePath), "utf8");
}
