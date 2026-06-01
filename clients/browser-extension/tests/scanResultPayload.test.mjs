import assert from "node:assert/strict";
import test from "node:test";
import {
  buildScanResultPayload,
  HipApiClient,
  normalizeHipSettings
} from "../src/hipApiClient.js";

test("plugin creates privacy-safe scan result payload", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/page",
    lookup: {
      finalHipScore: 84,
      status: "Trusted",
      reasons: ["No risky links found"]
    },
    summary: {
      linksScanned: 42,
      riskyLinks: 2,
      suspiciousLinks: 2,
      dangerousLinks: 0,
      apiStatus: "Available"
    },
    settings: {
      scanMode: "Normal"
    },
    submittedAtUtc: "2026-06-01T00:00:00Z"
  });

  assert.equal(payload.domain, "example.com");
  assert.equal(payload.score, 84);
  assert.equal(payload.status, "Trusted");
  assert.deepEqual(payload.reasons, ["No risky links found"]);
  assert.equal(payload.linksScanned, 42);
  assert.equal(payload.riskyLinksFound, 2);
  assert.equal(payload.suspiciousLinksFound, 2);
  assert.equal(payload.dangerousLinksFound, 0);
  assert.equal(payload.privacySafeMetadata.scanTimestampUtc, "2026-06-01T00:00:00Z");
});

test("scan result payload excludes page text and form values", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/page",
    lookup: { status: "Caution", score: 52 },
    summary: {
      pageText: "private body text",
      formValues: "password=secret"
    }
  });

  assert.equal("pageText" in payload, false);
  assert.equal("formValues" in payload, false);
  assert.equal("password" in payload.privacySafeMetadata, false);
});

test("plugin calls scan-results endpoint", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ saved: true })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await client.saveScanResult(buildScanResultPayload({
      domain: "example.com",
      pageUrl: "https://example.com/page",
      lookup: { status: "Trusted", score: 84 },
      summary: {}
    }));
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/browser/scan-results");
  assert.equal(calls[0].options.method, "POST");
});

test("submission failure rejects without requiring popup failure", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 500,
    json: async () => ({})
  });

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await assert.rejects(
      () => client.saveScanResult(buildScanResultPayload({
        domain: "example.com",
        pageUrl: "https://example.com/page",
        lookup: { status: "Trusted", score: 84 },
        summary: {}
      })),
      /scan result persistence failed/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("submitScanResults false is preserved in settings", () => {
  const settings = normalizeHipSettings({
    apiBaseUrl: "http://localhost:5099",
    submitScanResults: false
  });

  assert.equal(settings.submitScanResults, false);
});

test("invalid API base URL is handled safely", async () => {
  const client = new HipApiClient({ apiBaseUrl: "not a url", webBaseUrl: "http://localhost:5260" });

  await assert.rejects(
    () => client.saveScanResult(buildScanResultPayload({
      domain: "example.com",
      pageUrl: "https://example.com/page",
      lookup: { status: "Trusted", score: 84 },
      summary: {}
    })),
    /Invalid HIP API base URL/
  );
});
