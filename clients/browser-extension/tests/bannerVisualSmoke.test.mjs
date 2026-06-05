import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import {
  shouldShowTrustBanner
} from "../src/hipApiClient.js";

const rendererSource = readFileSync(new URL("../src/riskBadgeRenderer.js", import.meta.url), "utf8");

test("visual smoke renders suspicious warning banner with controls", () => {
  const harness = createRendererHarness();

  harness.renderer.renderTrustBanner({
    status: "Suspicious",
    finalHipScore: 34,
    publicLookupUrl: "https://hip.test/lookup/example.com",
    bannerReason: "HIP found suspicious redirect behavior."
  }, "HIP Plugin v0.1.0-dev");

  const banner = harness.document.getElementById("hip-trust-banner");
  const style = harness.document.getElementById("hip-link-risk-badge-style");

  assert.ok(banner);
  assert.equal(banner.className, "hip-trust-banner-suspicious");
  assert.match(banner.innerHTML, /HIP Notice: This page has suspicious signals\./);
  assert.match(banner.innerHTML, /HIP Trust Score: 34\/100/);
  assert.match(banner.innerHTML, /Looks Safe/);
  assert.match(banner.innerHTML, /Looks Suspicious/);
  assert.match(banner.innerHTML, /Details/);
  assert.match(banner.innerHTML, /HIP Plugin v0\.1\.0-dev/);
  assert.match(style.textContent, /#hip-trust-banner/);
  assert.match(style.textContent, /hip-trust-actions/);
});

test("visual smoke renders dangerous banner as strong warning", () => {
  const harness = createRendererHarness();

  harness.renderer.renderTrustBanner({
    status: "Dangerous",
    finalHipScore: 6,
    publicLookupUrl: "https://hip.test/lookup/phishing.test"
  }, "HIP Plugin v0.1.0-dev");

  const banner = harness.document.getElementById("hip-trust-banner");

  assert.ok(banner);
  assert.equal(banner.className, "hip-trust-banner-dangerous");
  assert.match(banner.innerHTML, /HIP Warning: Dangerous Site/);
  assert.match(banner.innerHTML, /Dangerous/);
  assert.match(banner.innerHTML, /6\/100/);
});

test("visual smoke confirms banner modes hide normal pages and show warnings", () => {
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, {}, { bannerDisplayMode: "WarningsOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "MostlyTrusted" }, {}, { bannerDisplayMode: "WarningsOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Unknown" }, {}, { bannerDisplayMode: "WarningsOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Suspicious" }, {}, { bannerDisplayMode: "WarningsOnly" }), true);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, { bannerDisplayMode: "DangerousOnly" }), true);
  assert.equal(shouldShowTrustBanner({ status: "Suspicious" }, {}, { bannerDisplayMode: "DangerousOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, {}, { bannerDisplayMode: "AlwaysShow" }), true);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, { bannerDisplayMode: "NeverShow" }), false);
});

test("visual smoke renders limited trust login warning only when structural risk exists", () => {
  assert.equal(
    shouldShowTrustBanner({ status: "LimitedTrustData" }, {}, { bannerDisplayMode: "WarningsOnly" }),
    false
  );
  assert.equal(
    shouldShowTrustBanner({ status: "LimitedTrustData" }, { loginFormsDetected: 1 }, { bannerDisplayMode: "WarningsOnly" }),
    true
  );

  const harness = createRendererHarness();
  harness.renderer.renderTrustBanner({
    status: "LimitedTrustData",
    finalHipScore: 55,
    bannerTitle: "HIP Notice: This page has limited trust data and contains login fields.",
    bannerReason: "This page has limited trust data and contains login fields.",
    publicLookupUrl: "https://hip.test/lookup/login.test"
  }, "HIP Plugin v0.1.0-dev");

  const banner = harness.document.getElementById("hip-trust-banner");

  assert.ok(banner);
  assert.equal(banner.className, "hip-trust-banner-limitedtrustdata");
  assert.match(banner.innerHTML, /Limited Trust Data/);
  assert.match(banner.innerHTML, /contains login fields/);
});

/**
 * Executes the real injected banner renderer against a tiny DOM harness.
 * This is a visual smoke test for markup, CSS hooks, and banner-mode output without adding a browser dependency.
 */
function createRendererHarness() {
  const document = new FakeDocument();
  const sandbox = {
    console,
    document,
    window: {
      location: {
        origin: "https://current-page.test"
      }
    },
    URL
  };

  sandbox.window.window = sandbox.window;
  sandbox.window.document = document;
  vm.runInNewContext(rendererSource, sandbox, { filename: "riskBadgeRenderer.js" });

  return {
    document,
    renderer: sandbox.window.HipRiskBadgeRenderer
  };
}

/**
 * Minimal document facade that supports the renderer operations used by the injected HIP banner.
 */
class FakeDocument {
  /**
   * Creates a fake document with addressable head and documentElement containers.
   */
  constructor() {
    this.elementsById = new Map();
    this.head = new FakeElement("head", this);
    this.documentElement = new FakeElement("html", this);
  }

  /**
   * Returns an element by id so duplicate style and banner guards behave like a browser.
   */
  getElementById(id) {
    return this.elementsById.get(id) || null;
  }

  /**
   * Creates fake elements with enough behavior for the banner renderer smoke tests.
   */
  createElement(tagName) {
    return new FakeElement(tagName, this);
  }

  /**
   * Registers element ids whenever renderer code assigns one.
   */
  registerElement(element) {
    if (element.id) {
      this.elementsById.set(element.id, element);
    }
  }
}

/**
 * Minimal element facade that preserves visible banner HTML and key query selectors.
 */
class FakeElement {
  /**
   * Creates a fake DOM element for the visual smoke harness.
   */
  constructor(tagName, ownerDocument) {
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.dataset = {};
    this.className = "";
    this.textContent = "";
    this.attributes = new Map();
    this.listeners = new Map();
    this._id = "";
    this._innerHTML = "";
  }

  /**
   * Tracks ids in the owning document so renderer duplicate guards are testable.
   */
  set id(value) {
    this._id = value;
    this.ownerDocument.registerElement(this);
  }

  /**
   * Returns the element id.
   */
  get id() {
    return this._id;
  }

  /**
   * Stores rendered HTML and creates lightweight child nodes for controls the renderer wires events to.
   */
  set innerHTML(value) {
    this._innerHTML = value;
    this.children = [
      new FakeElement("button", this.ownerDocument),
      new FakeElement("button", this.ownerDocument),
      new FakeElement("button", this.ownerDocument)
    ];
    this.children[0].className = "hip-trust-close";
    this.children[1].dataset.hipFeedback = "LooksSafe";
    this.children[2].dataset.hipFeedback = "LooksSuspicious";
  }

  /**
   * Returns the stored rendered HTML so tests can assert visible text and controls.
   */
  get innerHTML() {
    return this._innerHTML;
  }

  /**
   * Appends children and registers addressable ids.
   */
  appendChild(child) {
    this.children.push(child);
    this.ownerDocument.registerElement(child);
    return child;
  }

  /**
   * Prepends children and registers addressable ids.
   */
  prepend(child) {
    this.children.unshift(child);
    this.ownerDocument.registerElement(child);
    return child;
  }

  /**
   * Records event listeners because the renderer wires close and feedback handlers.
   */
  addEventListener(eventName, handler) {
    this.listeners.set(eventName, handler);
  }

  /**
   * Supports the selector shapes used by renderTrustBanner.
   */
  querySelector(selector) {
    if (selector === ".hip-trust-close") {
      return this.children.find(child => child.className === "hip-trust-close") || null;
    }

    return null;
  }

  /**
   * Supports the feedback-button selector used by renderTrustBanner.
   */
  querySelectorAll(selector) {
    if (selector === "[data-hip-feedback]") {
      return this.children.filter(child => child.dataset.hipFeedback);
    }

    return [];
  }

  /**
   * Stores attributes that are visible or relevant to injected UI behavior.
   */
  setAttribute(name, value) {
    this.attributes.set(name, value);
  }
}
