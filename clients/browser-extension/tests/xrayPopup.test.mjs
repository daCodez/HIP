import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [html, script, contracts, content] = await Promise.all([
  readFile(new URL("../src/sidepanel.html", import.meta.url), "utf8"),
  readFile(new URL("../src/sidepanel.js", import.meta.url), "utf8"),
  readFile(new URL("../src/contentMessageContracts.js", import.meta.url), "utf8"),
  readFile(new URL("../src/content.js", import.meta.url), "utf8")
]);

test("side panel provides explicit accessible X-ray actions and status", () => {
  assert.match(html, /id="startXray"[^>]*>Scan this page</);
  assert.match(html, /id="scanProgress"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(script, /HIP_XRAY_START/);
  assert.match(script, /HIP_XRAY_GET_STATE/);
  assert.match(script, /HIP_XRAY_RESCAN/);
});

test("content script no longer installs a page-level launcher", () => {
  assert.doesNotMatch(content, /installXrayLauncher/);
  assert.doesNotMatch(content, /\.installLauncher\(\)/);
});

test("content message contract allow-lists bounded X-ray commands", () => {
  for (const type of ["HIP_XRAY_START", "HIP_XRAY_GET_STATE", "HIP_XRAY_RESCAN", "HIP_XRAY_SELECT_FINDING", "HIP_XRAY_SET_MARKERS"]) assert.match(contracts, new RegExp(type));
  assert.match(contracts, /MAX_FINDING_ID_LENGTH/);
});
