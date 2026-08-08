import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(extensionRoot, "manifest.json"), "utf8"));
const packageDocument = JSON.parse(await readFile(path.join(extensionRoot, "package.json"), "utf8"));

test("manifest uses only reviewed runtime permissions", () => {
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "storage", "sidePanel"]);
  assert.deepEqual(manifest.host_permissions, [
    "https://api.guardwithhip.com/*",
    "https://guardwithhip.com/*",
    "http://localhost/*",
    "http://127.0.0.1/*"
  ]);
  assert.deepEqual(manifest.optional_host_permissions, ["https://*/*"]);

  assert.equal("externally_connectable" in manifest, false);
  assert.equal("web_accessible_resources" in manifest, false);
  assert.equal("commands" in manifest, false);
});

test("broad page access is confined to the isolated declarative content script", () => {
  assert.equal(manifest.content_scripts.length, 1);
  assert.deepEqual(manifest.content_scripts[0].matches, ["http://*/*", "https://*/*"]);
  assert.notEqual(manifest.content_scripts[0].world, "MAIN");
  assert.equal(manifest.host_permissions.includes("http://*/*"), false);
  assert.equal(manifest.host_permissions.includes("https://*/*"), false);
});

test("extension CSP permits local code only and excludes unsafe execution", () => {
  const policy = manifest.content_security_policy.extension_pages;
  assert.match(policy, /script-src 'self'/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /connect-src 'self' http:\/\/localhost:\* http:\/\/127\.0\.0\.1:\* https:/);
  assert.doesNotMatch(policy, /unsafe-inline|unsafe-eval|wasm-unsafe-eval|data:|blob:/);
  assert.doesNotMatch(policy, /script-src[^;]*https?:/);
});

test("all declared executable files are packaged local files", async () => {
  const scripts = [
    manifest.background.service_worker,
    ...manifest.content_scripts.flatMap(contentScript => contentScript.js),
    "src/popup.js",
    "src/sidepanel.js",
    "src/sidePanelState.js",
    "src/embeddedPanelBridge.js",
    "src/options.js"
  ];

  for (const script of scripts) {
    assert.doesNotMatch(script, /^(?:https?:)?\/\//);
    await assert.doesNotReject(() => readFile(path.join(extensionRoot, script)));
  }
});

test("manifest and package versions remain aligned", () => {
  assert.equal(manifest.version, packageDocument.version);
});
