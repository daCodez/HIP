import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/xrayController.js", import.meta.url), "utf8");

function createController(selectResults = ["selected"]) {
  let scans = 0;
  let selection = 0;
  let markerVisibility = true;
  const renderer = {
    open() {}, render() {}, setProgress() {}, updateMarkerPositions() {}, resetForNavigation() {}, showLauncher() {}, destroy() {},
    isMounted: () => true,
    selectFinding: findingId => ({ status: selectResults[Math.min(selection++, selectResults.length - 1)], findingId }),
    setMarkersVisible: visible => { markerVisibility = visible; }
  };
  const sandbox = { globalThis: {}, MutationObserver: class {}, setTimeout, clearTimeout, setInterval, clearInterval };
  vm.runInNewContext(source, sandbox, { filename: "xrayController.js" });
  const controller = sandbox.globalThis.HipXrayController.create({
    document: { documentElement: {} },
    window: {
      location: { href: "https://example.test" }, addEventListener() {}, removeEventListener() {},
      requestAnimationFrame: callback => { callback(); return 1; }, cancelAnimationFrame() {}
    },
    createRenderer: () => renderer,
    mutationObserverFactory: () => ({ observe() {}, disconnect() {} }),
    startInterval: () => 1,
    cancelInterval() {},
    scan: () => {
      scans += 1;
      return {
        findings: [{ id: "rule:ref", ruleId: "rule", severity: "High", title: "Risk", plainExplanation: "Review this.", evidence: "Bounded evidence", remediation: "Avoid it.", elementRefKey: "private-ref" }],
        references: new Map([["private-ref", { element: {} }]]),
        inventory: [{ id: "element:private-ref", elementRefKey: "private-ref", elementKind: "link", status: "No issue observed", privateValue: "never" }],
        coverage: { inspectedElementCount: 1, truncated: false }
      };
    }
  });
  return { controller, scans: () => scans, markerVisibility: () => markerVisibility };
}

test("missing SPA target triggers one bounded rescan and retry", () => {
  const harness = createController(["missing", "selected"]);
  harness.controller.start();
  const result = harness.controller.selectFinding("rule:ref");
  assert.equal(result.status, "selected");
  assert.equal(harness.scans(), 2);
});

test("serialized Page state excludes DOM references and private inventory fields", () => {
  const harness = createController();
  harness.controller.start();
  const state = harness.controller.getState({ inventoryOffset: 0, inventoryLimit: 50 });
  assert.equal(state.findings[0].findingId, "rule:ref");
  assert.equal(state.findings[0].scoreImpact, -18);
  assert.equal("elementRefKey" in state.findings[0], false);
  assert.deepEqual(Object.keys(state.inventory.items[0]), ["id", "elementKind", "status"]);
  assert.equal(JSON.stringify(state).includes("privateValue"), false);
});

test("marker visibility is controlled without restarting the scan", () => {
  const harness = createController();
  harness.controller.start();
  const scanCount = harness.scans();
  harness.controller.setMarkersVisible(false);
  assert.equal(harness.markerVisibility(), false);
  assert.equal(harness.controller.getState().markersVisible, false);
  assert.equal(harness.scans(), scanCount);
});
