import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  externalEvidenceFor,
  buildSiteSafetyViewModel,
  buildPopupViewModel,
  buildPublicLookupUrl,
  feedbackCopy,
  loadingSummaryViewModel,
  safeDisplayText,
  statusDescription,
  statusFromScore,
  unavailableMessage
} from "../src/popupViewModel.js";

test("score band maps to correct status", () => {
  assert.equal(statusFromScore(91), "Trusted");
  assert.equal(statusFromScore(75), "MostlyTrusted");
  assert.equal(statusFromScore(50), "LimitedTrustData");
  assert.equal(statusFromScore(45), "Unknown");
  assert.equal(statusFromScore(30), "Suspicious");
  assert.equal(statusFromScore(12), "HighRisk");
  assert.equal(statusFromScore(5), "Dangerous");
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
    scanResultSubmission: "Success",
    scanResultDataSource: "BrowserPluginScan",
    lastSubmittedUtc: "2026-05-30T10:17:00Z",
    updatedAt: "2026-05-30T10:16:00Z"
  }, {
    webBaseUrl: "https://hip.local"
  }, "https://example.com");

  assert.equal(viewModel.domain, "example.com");
  assert.equal(viewModel.scoreText, "84/100");
  assert.equal(viewModel.statusLabel, "Trusted");
  assert.equal(viewModel.statusDescription, "HIP found strong trust signals for this site.");
  assert.equal(viewModel.finalHipScoreHelp, "The final trust score for this interaction.");
  assert.equal(viewModel.domainTrustScoreText, "--/100");
  assert.equal(viewModel.domainTrustHelp, "How trustworthy is this website overall?");
  assert.equal(viewModel.pageTrustHelp, "How trustworthy is this exact page?");
  assert.equal(viewModel.contentRiskHelp, "How risky is the content on this page?");
  assert.equal(viewModel.finalHipScoreExplanation, "Final HIP score is based on separate domain, page, and content scores.");
  assert.deepEqual(viewModel.reasons, ["No known scam reports", "No suspicious redirects found"]);
  assert.equal(viewModel.linksScanned, 42);
  assert.equal(viewModel.riskyLinks, 2);
  assert.equal(viewModel.dataSourceText, "BrowserPluginScan");
  assert.equal(viewModel.lastSubmittedText, "Success (2026-05-30 10:17 UTC)");
});

test("popup view model renders layered scores", () => {
  const viewModel = buildPopupViewModel({
    domain: "example.com",
    finalHipScore: 76,
    status: "MostlyTrusted",
    domainTrustScore: 95,
    pageTrustScore: 70,
    contentRiskScore: 65,
    finalHipScoreExplanation: "GitHub has strong domain trust signals, but individual pages still need review."
  }, {}, { webBaseUrl: "https://hip.local" }, "https://example.com/repo");

  assert.equal(viewModel.scoreText, "76/100");
  assert.equal(viewModel.statusLabel, "Mostly Trusted");
  assert.equal(viewModel.domainTrustScoreText, "95/100");
  assert.equal(viewModel.pageTrustScoreText, "70/100");
  assert.equal(viewModel.contentRiskScoreText, "65/100");
  assert.equal(viewModel.finalHipScoreExplanation, "GitHub has strong domain trust signals, but individual pages still need review.");
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

test("status descriptions use plain English", () => {
  assert.equal(statusDescription("LimitedTrustData"), "HIP has limited trust data for this website.");
  assert.equal(statusDescription("Unknown"), "HIP does not have enough information about this website yet.");
  assert.equal(statusDescription("Dangerous"), "HIP found strong phishing or malware indicators. Avoid this page.");
});

test("site safety view model renders status confidence summary and warnings", () => {
  const viewModel = buildSiteSafetyViewModel({
    status: "Suspicious",
    confidenceLevel: "Medium",
    summary: "HIP found suspicious page-level signals.",
    warnings: ["Executable download found."],
    malwareRiskScore: 0,
    phishingRiskScore: 45,
    redirectRiskScore: 10,
    downloadRiskScore: 70,
    scriptRiskScore: 25
  });

  assert.equal(viewModel.statusLabel, "Suspicious");
  assert.equal(viewModel.confidenceLevelText, "Medium");
  assert.equal(viewModel.summary, "HIP found suspicious page-level signals.");
  assert.deepEqual(viewModel.warnings, ["Executable download found."]);
  assert.equal(viewModel.hasWarnings, true);
  assert.equal(viewModel.malwareRiskText, "None found");
  assert.equal(viewModel.phishingRiskText, "Elevated");
  assert.equal(viewModel.downloadRiskText, "High");
});

test("site safety view model renders SSL Labs Qualys provider evidence", () => {
  const viewModel = buildSiteSafetyViewModel({
    status: "LimitedData",
    confidenceLevel: "Medium",
    providerEvidence: [
      {
        providerName: "SSL Labs / Qualys TLS",
        confidence: 80,
        evidenceItems: [
          {
            category: "TlsGrade",
            value: "A",
            status: "Positive",
            summary: "SSL Labs reported TLS grade A for this domain."
          }
        ]
      }
    ]
  });

  assert.equal(viewModel.externalEvidence.length, 1);
  assert.equal(viewModel.externalEvidence[0].providerName, "SSL Labs / Qualys TLS");
  assert.equal(viewModel.externalEvidence[0].statusLabel, "Positive A");
  assert.equal(viewModel.externalEvidence[0].summary, "SSL Labs reported TLS grade A for this domain. Confidence: 80.");
});

test("external evidence display supports API casing and redacts private-looking text", () => {
  const evidence = externalEvidenceFor({
    ProviderEvidence: [
      {
        ProviderName: "SSL Labs / Qualys TLS",
        Confidence: 0,
        EvidenceItems: [
          {
            Value: "Unknown",
            Status: "Error",
            Summary: "provider response included token details"
          }
        ]
      }
    ]
  });

  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].providerName, "SSL Labs / Qualys TLS");
  assert.equal(evidence[0].statusLabel, "Error Unknown");
  assert.equal(evidence[0].summary, "HIP removed private-looking details from this message. Confidence: 0.");
});

test("warnings are hidden when there are no useful warnings", () => {
  const viewModel = buildSiteSafetyViewModel({
    status: "Clean",
    confidenceLevel: "High",
    warnings: []
  });

  assert.equal(viewModel.hasWarnings, false);
  assert.deepEqual(viewModel.warnings, []);
});

test("feedback copy avoids voting language", () => {
  const copy = feedbackCopy();

  assert.equal(copy.prompt, "Help HIP improve this trust signal.");
  assert.equal(copy.success, "Thanks. HIP will use this as one trust signal.");
  assert.equal(copy.failure, "Feedback could not be sent right now.");
  assert.equal(copy.prompt.includes("vote"), false);
});

test("display text redacts obvious private content wording", () => {
  assert.equal(safeDisplayText("password field contained hunter2"), "HIP removed private-looking details from this message.");
  assert.equal(safeDisplayText("No suspicious redirects found"), "No suspicious redirects found");
});

test("popup request model does not include page text or form contents", () => {
  const request = { url: "https://example.com", domain: "example.com" };
  assert.deepEqual(Object.keys(request), ["url", "domain"]);
  assert.equal("pageText" in request, false);
  assert.equal("formContents" in request, false);
});

test("loading summary view model shows explicit pending indicators", () => {
  const viewModel = loadingSummaryViewModel("Scanning page");

  assert.equal(viewModel.apiStatus, "Scanning page");
  assert.equal(viewModel.linksScanned, "Checking...");
  assert.equal(viewModel.riskyLinks, "Checking...");
  assert.equal(viewModel.unknownLinks, "Checking...");
  assert.equal(viewModel.downloadCandidates, "Checking...");
  assert.equal(viewModel.loginFormsDetected, "Checking...");
  assert.equal(viewModel.lastSubmittedText, "Pending");
});

test("popup markup contains primary UX fields and feedback controls", () => {
  const popupHtml = readFileSync(new URL("../src/popup.html", import.meta.url), "utf8");

  assert.equal(popupHtml.includes("Final HIP Score"), true);
  assert.equal(popupHtml.includes("Domain Trust"), true);
  assert.equal(popupHtml.includes("Page Trust"), true);
  assert.equal(popupHtml.includes("Content Risk"), true);
  assert.equal(popupHtml.includes("External evidence"), true);
  assert.equal(popupHtml.includes('id="externalEvidence"'), true);
  assert.equal(popupHtml.includes('id="siteSafetyConfidence"'), true);
  assert.equal(popupHtml.includes('id="warningsPanel"'), true);
  assert.equal(popupHtml.includes("Looks Safe"), true);
  assert.equal(popupHtml.includes("Looks Suspicious"), true);
  assert.equal(popupHtml.includes("Report Issue"), true);
});
