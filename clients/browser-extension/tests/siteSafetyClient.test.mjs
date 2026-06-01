import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { HipApiClient } from "../src/hipApiClient.js";

test("site safety request includes privacy-safe scan facts", () => {
  const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
  const request = client.buildSiteSafetyRequest("https://example.com/login", {
    downloadLinks: ["https://example.com/setup.exe"],
    loginFormsDetected: 1,
    inlineScriptCount: 4,
    externalScriptUrls: ["https://cdn.example.com/app.js"],
    suspiciousScriptPatternCount: 0,
    pageText: "private page body",
    formValues: "password=secret"
  });

  assert.equal(request.url, "https://example.com/login");
  assert.deepEqual(request.observedSignals.downloadLinks, ["https://example.com/setup.exe"]);
  assert.equal(request.observedSignals.hasLoginForm, true);
  assert.equal(request.observedSignals.hasPasswordField, true);
  assert.equal(request.observedSignals.inlineScriptCount, 4);
  assert.deepEqual(request.observedSignals.externalScriptUrls, ["https://cdn.example.com/app.js"]);
  assert.equal("pageText" in request.observedSignals, false);
  assert.equal("formValues" in request.observedSignals, false);
});

test("scan site safety calls versioned API route", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ status: "LimitedData" })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await client.scanSiteSafety(client.buildSiteSafetyRequest("https://example.com", {}));
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/site-safety/scan");
  assert.equal(calls[0].options.method, "POST");
});

test("popup contains site safety display fields", async () => {
  const html = await readFile(new URL("../src/popup.html", import.meta.url), "utf8");
  const script = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");

  assert.match(html, /id="siteSafetyPanel"/);
  assert.match(html, /id="malwareRisk"/);
  assert.match(html, /id="phishingRisk"/);
  assert.match(script, /renderSiteSafety/);
  assert.match(script, /scanSiteSafety/);
});
