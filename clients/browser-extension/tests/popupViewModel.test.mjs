import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPopupViewModel,
  buildPublicLookupUrl,
  statusFromScore,
  unavailableMessage
} from "../src/popupViewModel.js";

test("score band maps to correct status", () => {
  assert.equal(statusFromScore(91), "Trusted");
  assert.equal(statusFromScore(75), "ProbablySafe");
  assert.equal(statusFromScore(50), "Caution");
  assert.equal(statusFromScore(30), "HighRisk");
  assert.equal(statusFromScore(12), "Dangerous");
  assert.equal(statusFromScore(undefined), "Unknown");
});

test("popup view model renders score domain and reasons", () => {
  const viewModel = buildPopupViewModel({
    domain: "example.com",
    score: 84,
    status: "Trusted",
    verificationStatus: "Verified",
    signedIdentityStatus: "Valid",
    lastCheckedUtc: "2026-05-30T10:15:00Z",
    reasons: ["No known scam reports", "No suspicious redirects found"]
  }, {
    linksScanned: 42,
    riskyLinks: 2,
    updatedAt: "2026-05-30T10:16:00Z"
  }, {
    webBaseUrl: "https://hip.local"
  }, "https://example.com");

  assert.equal(viewModel.domain, "example.com");
  assert.equal(viewModel.scoreText, "84/100");
  assert.equal(viewModel.statusLabel, "Trusted");
  assert.deepEqual(viewModel.reasons, ["No known scam reports", "No suspicious redirects found"]);
  assert.equal(viewModel.linksScanned, 42);
  assert.equal(viewModel.riskyLinks, 2);
});

test("api unavailable state uses clear MVP message", () => {
  assert.equal(unavailableMessage(), "HIP API unavailable. Unable to score this site right now.");
});

test("public lookup URL is generated from configured base URL", () => {
  assert.equal(
    buildPublicLookupUrl("https://hip.local", "example.com", null),
    "https://hip.local/lookup/domain/example.com"
  );
});

test("unknown status renders safely", () => {
  const viewModel = buildPopupViewModel({
    domain: "unknown.example",
    score: null,
    status: "Unknown",
    reasons: []
  }, {}, { webBaseUrl: "https://hip.local" }, "https://unknown.example");

  assert.equal(viewModel.statusLabel, "Unknown");
  assert.equal(viewModel.scoreText, "--/100");
  assert.equal(viewModel.reasons[0], "HIP returned a trust score without inspecting private page content.");
});

test("popup request model does not include page text or form contents", () => {
  const request = { url: "https://example.com", domain: "example.com" };
  assert.deepEqual(Object.keys(request), ["url", "domain"]);
  assert.equal("pageText" in request, false);
  assert.equal("formContents" in request, false);
});
