import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/contentMessageContracts.js", import.meta.url), "utf8");
const context = vm.createContext({
  globalThis: {},
  JSON,
  Object,
  Set,
  Error
});
vm.runInContext(source, context);
const contracts = context.globalThis.HipContentMessageContracts;
const runtimeId = "hip-test-extension";
const popupSender = {
  id: runtimeId,
  url: `chrome-extension://${runtimeId}/src/popup.html`
};

test("accepts only the reviewed payload-free popup commands", () => {
  assert.equal(contracts.validate({ type: "HIP_REFRESH_SCAN" }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_GET_CONTENT_SUMMARY" }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_XRAY_START" }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_LOOKUP_DOMAIN" }, popupSender, runtimeId).ok, false);
  assert.equal(contracts.validate({ type: "HIP_REFRESH_SCAN", url: "https://attacker.example" }, popupSender, runtimeId).ok, false);
});

test("rejects page, unknown-extension, and malformed senders", () => {
  assert.equal(contracts.validate(
    { type: "HIP_REFRESH_SCAN" },
    { id: runtimeId, url: "https://example.com/" },
    runtimeId
  ).ok, false);
  assert.equal(contracts.validate(
    { type: "HIP_REFRESH_SCAN" },
    { ...popupSender, id: "another-extension" },
    runtimeId
  ).ok, false);
});

test("bounds summaries returned to popup pages", () => {
  assert.deepEqual(contracts.safeSummary({ status: "Safe", score: 90 }), { status: "Safe", score: 90 });
  assert.throws(() => contracts.safeSummary({ value: "x".repeat(129 * 1024) }), /size limit/);
});

test("accepts only bounded side-panel X-ray payloads", () => {
  assert.equal(contracts.validate({ type: "HIP_XRAY_GET_STATE", inventoryOffset: 50, inventoryLimit: 50 }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_XRAY_SELECT_FINDING", findingId: "rule:element" }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_XRAY_SET_MARKERS", visible: false }, popupSender, runtimeId).ok, true);
  assert.equal(contracts.validate({ type: "HIP_XRAY_SELECT_FINDING", findingId: "x".repeat(241) }, popupSender, runtimeId).ok, false);
  assert.equal(contracts.validate({ type: "HIP_XRAY_SET_MARKERS", visible: "yes" }, popupSender, runtimeId).ok, false);
  assert.equal(contracts.validate({ type: "HIP_XRAY_GET_STATE", inventoryLimit: 101 }, popupSender, runtimeId).ok, false);
  assert.equal(contracts.validate({ type: "HIP_XRAY_GET_STATE", pageText: "private" }, popupSender, runtimeId).ok, false);
});

test("accepts only supported website badge positions", () => {
  for (const position of ["bottom-left", "bottom-right", "top-left", "top-right"]) {
    const result = contracts.validate({ type: "HIP_SET_SITE_BADGE_POSITION", position }, popupSender, runtimeId);
    assert.equal(result.ok, true);
    assert.equal(result.message.position, position);
  }

  assert.equal(contracts.validate({ type: "HIP_SET_SITE_BADGE_POSITION", position: "center" }, popupSender, runtimeId).ok, false);
  assert.equal(contracts.validate({ type: "HIP_SET_SITE_BADGE_POSITION", position: "top-left", pageText: "private" }, popupSender, runtimeId).ok, false);
});
