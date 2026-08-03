import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [html, popup, contracts, content] = await Promise.all([
  readFile(new URL("../src/popup.html", import.meta.url), "utf8"),
  readFile(new URL("../src/popup.js", import.meta.url), "utf8"),
  readFile(new URL("../src/contentMessageContracts.js", import.meta.url), "utf8"),
  readFile(new URL("../src/content.js", import.meta.url), "utf8")
]);

test("popup provides an explicit accessible X-ray action and status", () => {
  assert.match(html, /id="xrayPage"[^>]*>X-ray this page</);
  assert.match(html, /id="xrayState"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(popup, /HIP_XRAY_START/);
  assert.match(popup, /startInjectedXray/);
  assert.match(popup, /controller\.getOrCreate/);
  assert.match(popup, /X-ray is unavailable on protected browser pages/);
});

test("content script installs a page-level trigger without starting a scan", () => {
  assert.match(content, /installXrayLauncher\(\)/);
  assert.doesNotMatch(content, /installXrayLauncher\(\)[\s\S]{0,80}\.start\(\)/);
});

test("content message contract allows only payload-free X-ray start", () => {
  assert.match(contracts, /HIP_XRAY_START/);
  assert.doesNotMatch(contracts, /HIP_XRAY_START[^\n]+pageText/);
});
