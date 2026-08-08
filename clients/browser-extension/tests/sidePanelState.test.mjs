import assert from "node:assert/strict";
import test from "node:test";
import {
  createActiveTabCoordinator,
  inventoryPage,
  isSupportedPageUrl,
  pickInspectableTab,
  statusPresentation,
  storagePresentation
} from "../src/sidePanelState.js";

test("inspectable tab selection recovers the latest web page when an extension surface is active", () => {
  const selected = pickInspectableTab([
    { id: 30, active: true, lastAccessed: 300, url: "chrome-extension://hip/src/sidepanel.html" },
    { id: 20, active: false, lastAccessed: 200, url: "https://guardwithhip.com/methodology" },
    { id: 10, active: false, lastAccessed: 100, url: "https://older.example/" }
  ]);

  assert.equal(selected.id, 20);
});

test("active-tab coordinator clears immediately and rejects late generations", async () => {
  const events = [];
  let resolveFirst;
  const coordinator = createActiveTabCoordinator({
    clear: state => events.push(["clear", state.tabId]),
    load: tab => tab.id === 1
      ? new Promise(resolve => { resolveFirst = resolve; })
      : Promise.resolve({ tabId: tab.id, hostname: "new.example" }),
    commit: state => events.push(["commit", state.tabId])
  });

  const first = coordinator.activate({ id: 1, url: "https://old.example" });
  await coordinator.activate({ id: 2, url: "https://new.example" });
  resolveFirst({ tabId: 1, hostname: "old.example" });
  await first;

  assert.deepEqual(events, [["clear", 1], ["clear", 2], ["commit", 2]]);
});

test("unsupported pages are cleared and never loaded", async () => {
  let loads = 0;
  const cleared = [];
  const coordinator = createActiveTabCoordinator({
    clear: state => cleared.push(state),
    load: async () => { loads += 1; },
    commit: () => {}
  });
  await coordinator.activate({ id: 8, url: "chrome://settings" });
  assert.equal(loads, 0);
  assert.equal(cleared[0].supported, false);
  assert.equal(isSupportedPageUrl("https://example.test/a"), true);
  assert.equal(isSupportedPageUrl("file:///secret.txt"), false);
});

test("inventory is delivered in bounded batches with honest truncation", () => {
  const items = Array.from({ length: 2500 }, (_, index) => ({ id: `element-${index}` }));
  const page = inventoryPage(items, 100, 50, { inspectedElementCount: 2500, truncated: true });
  assert.equal(page.items.length, 50);
  assert.equal(page.nextOffset, 150);
  assert.equal(page.inspectedCount, 2500);
  assert.equal(page.truncated, true);
});

test("status and storage presentations use text as well as color", () => {
  assert.deepEqual(statusPresentation("High"), { key: "risky", label: "Risky", color: "#ef4444" });
  assert.equal(statusPresentation("Info").label, "Informational");
  assert.equal(storagePresentation("Success").label, "Summary recorded");
  assert.equal(storagePresentation("DuplicateSuppressed").label, "Summary recorded");
  assert.equal(storagePresentation("Skipped").label, "Local only");
  assert.equal(storagePresentation("Failed").label, "Not stored");
});
