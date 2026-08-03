import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/xrayController.js", import.meta.url), "utf8");

function createHarness() {
  const calls = [];
  let observerCallback;
  const observer = { observe: () => calls.push("observe"), disconnect: () => calls.push("disconnect") };
  const renderer = {
    mountLauncher: () => calls.push("mount-launcher"),
    open: () => calls.push("open"),
    showLauncher: () => calls.push("show-launcher"),
    render: findings => calls.push(`render:${findings.length}`),
    setProgress: message => calls.push(`progress:${message}`),
    focus: () => calls.push("focus"),
    updateMarkerPositions: () => calls.push("position"),
    destroy: () => calls.push("destroy")
  };
  const windowObject = {
    addEventListener: type => calls.push(`add:${type}`),
    removeEventListener: type => calls.push(`remove:${type}`),
    requestAnimationFrame: callback => { callback(); return 1; },
    cancelAnimationFrame: () => calls.push("cancel-frame")
  };
  const documentObject = { documentElement: {} };
  const sandbox = {
    globalThis: {},
    MutationObserver: class { constructor(callback) { observerCallback = callback; } observe(...args) { observer.observe(...args); } disconnect() { observer.disconnect(); } },
    setTimeout: callback => { callback(); return 1; },
    clearTimeout: () => calls.push("clear-timeout")
  };
  vm.runInNewContext(source, sandbox, { filename: "xrayController.js" });
  const controller = sandbox.globalThis.HipXrayController.create({
    document: documentObject,
    window: windowObject,
    scan: ({ newElements }) => ({ findings: [{ id: "one" }], references: new Map(), coverage: {}, newElements }),
    createRenderer: controls => ({ ...renderer, controls }),
    mutationObserverFactory: callback => { observerCallback = callback; return observer; },
    schedule: callback => { callback(); return 1; },
    cancelScheduled: () => calls.push("clear-timeout")
  });
  return { calls, controller, mutate: records => observerCallback(records) };
}

test("start is idempotent and reports real scan progress", () => {
  const harness = createHarness();
  harness.controller.installLauncher();
  assert.equal(harness.calls.includes("render:1"), false);
  assert.equal(harness.controller.start().findingCount, 1);
  assert.equal(harness.controller.start().alreadyActive, true);
  assert.equal(harness.calls.filter(item => item === "mount-launcher").length, 1);
  assert.equal(harness.calls.filter(item => item === "open").length, 1);
  assert.ok(harness.calls.includes("progress:Scanning this page…"));
  assert.ok(harness.calls.includes("progress:1 finding"));
});

test("mutation rescans are bounded and ignore HIP-owned nodes", () => {
  const harness = createHarness();
  harness.controller.start();
  harness.mutate([{ addedNodes: [{ nodeType: 1, dataset: { hipXrayOwned: "true" } }, { nodeType: 1, tagName: "SCRIPT", dataset: {} }] }]);
  assert.equal(harness.calls.filter(item => item.startsWith("render:")).length, 2);
});

test("exit removes scan observers, listeners, timers, and references while restoring the page trigger", () => {
  const harness = createHarness();
  harness.controller.start();
  harness.controller.stop();
  assert.ok(harness.calls.includes("disconnect"));
  assert.ok(harness.calls.includes("remove:scroll"));
  assert.ok(harness.calls.includes("remove:resize"));
  assert.ok(harness.calls.includes("show-launcher"));
  assert.equal(harness.calls.includes("destroy"), false);
  assert.equal(harness.controller.getState().active, false);
  assert.equal(harness.controller.getState().referenceCount, 0);
});

test("destroy removes the persistent page trigger on navigation teardown", () => {
  const harness = createHarness();
  harness.controller.installLauncher();
  harness.controller.destroy();
  assert.ok(harness.calls.includes("destroy"));
});
