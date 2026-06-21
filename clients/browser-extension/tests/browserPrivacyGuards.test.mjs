import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const extensionRoot = fileURLToPath(new URL("../", import.meta.url));

test("browser privacy guard helper is loaded before content script", () => {
  const manifest = JSON.parse(read("manifest.json"));
  const scripts = manifest.content_scripts[0].js;

  assert.ok(scripts.indexOf("src/browserPrivacyGuards.js") > -1);
  assert.ok(scripts.indexOf("src/browserPrivacyGuards.js") < scripts.indexOf("src/content.js"));
});

test("browser privacy guards strip private URL pieces", () => {
  const guards = loadGuards();

  assert.equal(guards.stripQueryAndFragment("https://example.com/path?token=secret#fragment"), "https://example.com/path");
  assert.equal(guards.stripQueryAndFragment("javascript:alert(1)"), null);
  assert.equal(guards.stripQueryAndFragment("not a url"), null);
});

test("browser privacy guards block HIP owned and internal Site Safety URLs", () => {
  const guards = loadGuards();
  const settings = {
    apiBaseUrl: "http://localhost:5099",
    webBaseUrl: "http://localhost:5123"
  };

  assert.equal(guards.isHipOwnedPage("http://localhost:5123/lookup/example.com", settings), true);
  assert.equal(guards.isSiteSafetyEligibleUrl("http://localhost:5123/admin", settings), false);
  assert.equal(guards.isSiteSafetyEligibleUrl("http://192.168.1.4/page", settings), false);
  assert.equal(guards.isSiteSafetyEligibleUrl("https://example.com/page", settings), true);
});

test("browser privacy guards filter evidence URL lists to public URLs only", () => {
  const guards = loadGuards();
  const settings = { webBaseUrl: "http://localhost:5123" };
  const values = [
    "https://example.com/file.zip",
    "http://localhost:5123/admin",
    "http://10.0.0.5/internal",
    "not a url",
    null
  ];

  assert.deepEqual(guards.filterSafePublicUrls(values, settings), ["https://example.com/file.zip"]);
});

function loadGuards() {
  const sandbox = { URL };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(read("src/browserPrivacyGuards.js"), sandbox);
  return sandbox.globalThis.HipBrowserPrivacyGuards;
}

function read(relativePath) {
  return readFileSync(join(extensionRoot, relativePath), "utf8");
}
