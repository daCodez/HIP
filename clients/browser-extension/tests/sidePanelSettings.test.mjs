import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { DEFAULT_HIP_SETTINGS, normalizeHipSettings } from "../src/hipApiClient.js";
import { embeddedTabIdFromLocation } from "../src/embeddedPanelBridge.js";

const [html, script] = await Promise.all([
  readFile(new URL("../src/options.html", import.meta.url), "utf8"),
  readFile(new URL("../src/options.js", import.meta.url), "utf8")
]);

test("embedded site view receives only a bounded numeric tab identifier", () => {
  assert.equal(embeddedTabIdFromLocation({ location: { search: "?embedded=1&tab=42" } }), 42);
  assert.equal(embeddedTabIdFromLocation({ location: { search: "?embedded=1&tab=-1" } }), null);
  assert.equal(embeddedTabIdFromLocation({ location: { search: "?embedded=1&tab=private" } }), null);
});

test("settings expose marker preference and warned raw-URL opt-in", () => {
  assert.equal(DEFAULT_HIP_SETTINGS.showXrayMarkers, true);
  assert.equal(DEFAULT_HIP_SETTINGS.allowRawPageUrlSubmission, false);
  assert.equal(normalizeHipSettings({ showXrayMarkers: false, allowRawPageUrlSubmission: true }).showXrayMarkers, false);
  assert.match(html, /id="showXrayMarkers"/);
  assert.match(html, /id="allowRawPageUrlSubmission"/);
  assert.match(html, /off by default/i);
});

test("settings report permission and provider synchronization failures honestly", () => {
  assert.match(script, /Settings not saved\. HIP service access was not granted/);
  assert.match(script, /Settings saved locally; provider settings were not synced/);
  assert.match(script, /HIP admin sync failed/);
  assert.match(script, /HIP_XRAY_SET_MARKERS/);
});
