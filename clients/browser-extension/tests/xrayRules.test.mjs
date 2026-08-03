import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/xrayRules.js", import.meta.url), "utf8");
const sandbox = { URL, globalThis: {} };
vm.runInNewContext(source, sandbox, { filename: "xrayRules.js" });
const rules = sandbox.globalThis.HipXrayRules;

function scan(elements, page = {}) {
  return rules.scanSnapshot({
    pageUrl: "https://shop.example/checkout",
    pageOrigin: "https://shop.example",
    pageProtocol: "https:",
    elements,
    coverage: { inaccessibleFrameCount: 0, closedShadowRoots: "Not observable" },
    ...page
  });
}

function collectStableLink() {
  const documentElement = { nodeType: 1, tagName: "HTML" };
  const anchor = {
    nodeType: 1,
    tagName: "A",
    id: "stable-link",
    dataset: {},
    textContent: "https://expected.example/",
    parentElement: documentElement,
    closest: () => null,
    getAttribute: name => name === "href" ? "https://destination.example/" : null
  };
  const documentObject = {
    documentElement,
    querySelectorAll: selector => selector === "a[href]" ? [anchor] : []
  };
  return rules.collectPageSnapshot(documentObject, { href: "https://shop.example/" });
}

test("publishes a stable versioned finding schema", () => {
  const [finding] = scan([{ refKey: "e1", kind: "form", hasPassword: true, actionUrl: "http://shop.example/login", actionOrigin: "http://shop.example" }]).findings;
  assert.equal(rules.RULESET_VERSION, "hip-xray-local-1");
  assert.deepEqual(Object.keys(finding), [
    "id", "ruleId", "ruleVersion", "category", "severity", "title",
    "plainExplanation", "technicalExplanation", "evidence", "remediation",
    "source", "elementRefKey"
  ]);
  assert.equal(rules.validateFinding(finding), true);
  assert.equal(finding.source, "Local");
});

test("uses deterministic private reference keys that survive equivalent rescans", () => {
  const first = collectStableLink();
  const second = collectStableLink();
  const firstKey = first.snapshot.elements[0].refKey;
  assert.equal(second.snapshot.elements[0].refKey, firstKey);
  assert.match(firstKey, /^xray-[a-z0-9]+$/);
  assert.equal(first.references.get(firstKey).selector, "#stable-link");
  assert.equal(first.references.get(firstKey).tagName, "a");
});

test("detects insecure password, authentication, payment, and form action transport", () => {
  const result = scan([
    { refKey: "password", kind: "form", hasPassword: true, actionUrl: "http://shop.example/login", actionOrigin: "http://shop.example" },
    { refKey: "auth", kind: "form", hasAuthFields: true, actionUrl: "https://shop.example/session", actionOrigin: "https://shop.example" },
    { refKey: "payment", kind: "form", hasPaymentFields: true, actionUrl: "https://pay.example/charge", actionOrigin: "https://pay.example" }
  ], { pageUrl: "http://shop.example/checkout", pageOrigin: "http://shop.example", pageProtocol: "http:" });
  const ids = result.findings.map(item => item.ruleId);
  assert.ok(ids.includes("form.password-on-insecure-page"));
  assert.ok(ids.includes("form.auth-on-insecure-page"));
  assert.ok(ids.includes("form.payment-on-insecure-page"));
  assert.ok(ids.includes("form.unencrypted-action"));
  const crossOrigin = result.findings.find(item => item.ruleId === "form.cross-origin-action");
  assert.equal(crossOrigin.severity, "Info");
  assert.match(crossOrigin.plainExplanation, /context/i);
});

test("detects mixed content without claiming certificate or reputation facts", () => {
  const result = scan([{ refKey: "asset", kind: "resource", url: "http://cdn.example/app.js", resourceType: "script" }]);
  assert.equal(result.findings[0].ruleId, "transport.mixed-content");
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /domain age|certificate owner|DNS reputation|mail reputation/i);
});

test("detects suspicious link patterns with cautious evidence", () => {
  const result = scan([
    { refKey: "misleading", kind: "link", url: "https://evil.example/", visibleText: "https://accounts.example/sign-in" },
    { refKey: "redirect", kind: "link", url: "https://go.example/?redirect=https%3A%2F%2Fevil.example" },
    { refKey: "unusual", kind: "link", url: "https://a-b-c-d-e-f.long-host-name-with-many-labels.example/" },
    { refKey: "idn", kind: "link", url: "https://xn--pple-43d.example/" },
    { refKey: "lookalike", kind: "link", url: "https://paypa1.example/" }
  ]);
  const ids = new Set(result.findings.map(item => item.ruleId));
  for (const id of ["link.misleading-text", "link.encoded-redirect", "link.unusual-hostname", "link.idn-hostname", "link.brand-lookalike"]) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  assert.match(result.findings.find(item => item.ruleId === "link.brand-lookalike").technicalExplanation, /resembles|similar/i);
});

test("inventories third-party and newly added scripts and frames", () => {
  const result = scan([
    { refKey: "script", kind: "script", url: "https://cdn.vendor.example/app.js", origin: "https://cdn.vendor.example", isNew: true },
    { refKey: "frame", kind: "frame", url: "https://widgets.example/embed", origin: "https://widgets.example", isNew: true, accessible: false }
  ]);
  const ids = new Set(result.findings.map(item => item.ruleId));
  assert.ok(ids.has("third-party.script"));
  assert.ok(ids.has("third-party.frame"));
  assert.ok(ids.has("dynamic.script-added"));
  assert.ok(ids.has("dynamic.frame-added"));
  assert.equal(result.coverage.inaccessibleFrameCount, 1);
});

test("uses versioned HIP wording rules without copying observed page text", () => {
  const result = scan([{ refKey: "copy", kind: "visible-signal", matchedSignals: ["urgency", "impersonation", "credential-request"] }]);
  const ids = new Set(result.findings.map(item => item.ruleId));
  assert.ok(ids.has("content.urgent-credential-request"));
  assert.ok(ids.has("content.impersonation-language"));
  assert.doesNotMatch(JSON.stringify(result.findings), /actual private message/i);
  assert.equal(rules.CONTENT_RULES_VERSION, "hip-content-signals-1");
});

test("caps large snapshots and keeps HIP backend evidence behind a validated adapter seam", () => {
  const elements = Array.from({ length: 3000 }, (_, index) => ({
    refKey: `resource-${index}`,
    kind: "resource",
    url: `http://cdn${index}.example/file.js`,
    resourceType: "script"
  }));
  const local = scan(elements);
  assert.equal(local.findings.length, 2500);
  assert.equal(local.backend.available, false);
  assert.equal(local.backend.message, "Full domain scan unavailable.");

  const hipFinding = { ...local.findings[0], id: "hip:one", source: "HIP", elementRefKey: "domain" };
  const merged = rules.mergeHipFindings(local, [hipFinding, { source: "HIP", title: "invalid" }]);
  assert.equal(merged.backend.available, true);
  assert.equal(merged.findings.at(-1).source, "HIP");
});
