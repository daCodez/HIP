import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { HipApiClient, isSiteSafetyScanEligibleUrl, normalizeHipSettings } from "../src/hipApiClient.js";

test("site safety request includes privacy-safe scan facts", () => {
  const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123" });
  const request = client.buildSiteSafetyRequest("https://example.com/login", {
    downloadLinks: ["https://example.com/setup.exe"],
    loginFormsDetected: 1,
    inlineScriptCount: 4,
    externalScriptUrls: ["https://cdn.example.com/app.js"],
    suspiciousScriptPatternCount: 0,
    pluginVersion: "HIP Plugin v0.1.0-dev",
    pageText: "private page body",
    formValues: "password=secret"
  });

  assert.equal(request.url, "https://example.com/login");
  assert.equal(request.pluginVersion, "HIP Plugin v0.1.0-dev");
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
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123", instanceId: "test-instance" });
    await client.scanSiteSafety(client.buildSiteSafetyRequest("https://example.com", { pluginVersion: "HIP Plugin v0.1.0-dev" }));
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/site-safety/scan");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["X-HIP-Instance-Id"], "test-instance");
  assert.equal(JSON.parse(calls[0].options.body).pluginVersion, "HIP Plugin v0.1.0-dev");
});

test("site safety scan eligibility skips HIP owned and internal URLs", () => {
  const settings = {
    apiBaseUrl: "http://localhost:5099",
    webBaseUrl: "http://localhost:5123"
  };

  assert.equal(isSiteSafetyScanEligibleUrl("http://localhost:5123/admin", settings), false);
  assert.equal(isSiteSafetyScanEligibleUrl("http://127.0.0.1:5123/admin", settings), false);
  assert.equal(isSiteSafetyScanEligibleUrl("http://192.168.1.10/page", settings), false);
  assert.equal(isSiteSafetyScanEligibleUrl("chrome://extensions", settings), false);
  assert.equal(isSiteSafetyScanEligibleUrl("https://example.com/page", settings), true);
});

test("site feedback calls public feedback route with instance header", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ currentScore: 74 })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123", instanceId: "feedback-instance" });
    await client.submitSiteFeedback({
      // ASP.NET's current minimal API binding accepts enum ordinals for this endpoint.
      targetType: 5,
      targetId: "example.com",
      eventType: 0,
      severity: 0,
      reporterTrustLevel: 0,
      reason: "Browser plugin feedback: user reported the site looks safe.",
      platform: "Web",
      urlHash: "sha256:test"
    });
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/public/feedback");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["X-HIP-Instance-Id"], "feedback-instance");
  assert.equal(JSON.parse(calls[0].options.body).reporterTrustLevel, 0);
});

test("site feedback treats duplicate suppression as accepted", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 409,
    json: async () => ({ error: "Duplicate feedback submission ignored." })
  });

  let result;
  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123" });
    result = await client.submitSiteFeedback({
      targetType: 5,
      targetId: "example.com",
      eventType: 2,
      severity: 1,
      reporterTrustLevel: 0,
      reason: "Browser plugin feedback: user reported the site looks suspicious.",
      platform: "Web",
      urlHash: "sha256:test"
    });
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(result.accepted, true);
  assert.equal(result.duplicateSuppressed, true);
});

test("scan site safety falls back to web host when API host route is missing", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url === "http://localhost:5099/api/v1/site-safety/scan") {
      return {
        ok: false,
        status: 404,
        json: async () => ({ error: "missing" })
      };
    }

    return {
      ok: true,
      status: 200,
      json: async () => ({ status: "LimitedData", source: "web-fallback" })
    };
  };

  let result;
  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123" });
    result = await client.scanSiteSafety(client.buildSiteSafetyRequest("https://example.com", {}));
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/site-safety/scan");
  assert.equal(calls[1].url, "http://localhost:5123/api/v1/site-safety/scan");
  assert.equal(result.source, "web-fallback");
});

test("provider toggles default to SSL Labs enabled only", () => {
  const settings = normalizeHipSettings({});

  assert.equal(settings.externalProvidersEnabled, true);
  assert.equal(settings.sslLabsEnabled, true);
  assert.equal(settings.googleWebRiskEnabled, false);
  assert.equal(settings.virusTotalEnabled, false);
});

test("external provider settings lookup uses instance-scoped API route with instance header", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ externalProvidersEnabled: true })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123", instanceId: "provider-instance" });
    await client.getExternalProviderSettings();
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/site-safety/external-providers");
  assert.equal(calls[0].options.method, "GET");
  assert.equal("credentials" in calls[0].options, false);
  assert.equal(calls[0].options.headers["X-HIP-Instance-Id"], "provider-instance");
});

test("external provider settings update posts complete safe config", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => JSON.parse(options.body)
    };
  };

  const request = {
    externalProvidersEnabled: true,
    allowFullUrlChecks: false,
    providerTimeout: "00:00:10",
    defaultCacheDuration: "06:00:00",
    sslLabs: { enabled: true, endpoint: "https://api.ssllabs.com/api/v3/analyze", apiKey: null, allowFullUrl: false, cacheDuration: null },
    googleWebRisk: { enabled: false, endpoint: null, apiKey: null, allowFullUrl: false, cacheDuration: null },
    virusTotal: { enabled: false, endpoint: null, apiKey: null, allowFullUrl: false, cacheDuration: null }
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123", instanceId: "provider-instance" });
    await client.updateExternalProviderSettings(request);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/site-safety/external-providers");
  assert.equal(calls[0].options.method, "POST");
  assert.equal("credentials" in calls[0].options, false);
  assert.equal(calls[0].options.headers["X-HIP-Instance-Id"], "provider-instance");
  assert.equal(JSON.parse(calls[0].options.body).sslLabs.enabled, true);
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
