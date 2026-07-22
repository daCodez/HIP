import assert from "node:assert/strict";
import test from "node:test";

await import("../src/formalScoring.js");

const { normalizeFormalScoring, projectSiteSafetyScores } = globalThis.HipFormalScoring;

function validFormalScoring(overrides = {}) {
  return {
    modelVersion: "hip-0301-v1",
    domainTrustScore: 82,
    pageTrustScore: 71,
    contentRiskScore: 24,
    finalHipScore: 77,
    finalStatus: "MostlyTrusted",
    presentationStatus: "LimitedTrustData",
    confidence: "Medium",
    evidenceFreshness: "Mixed",
    trustAssertionDisposition: "WithheldInsufficientEvidence",
    canAssertPositiveTrust: false,
    finalScoreHigherMeansMoreTrust: true,
    contentRiskScoreHigherMeansMoreRisk: true,
    reasons: ["Domain evidence is positive."],
    warnings: ["Some evidence is older than the preferred window."],
    reasonEntries: [{
      code: "score-cap:executable-weak-identity",
      explanation: "Executable risk limits the final score.",
      warningCode: "warning:executable-weak-identity",
      warning: "The executable lacks sufficiently strong identity evidence.",
      impact: { kind: "MaximumFinalScore", value: 39 },
      evidenceSourceCode: "site-safety:executable-download",
      evidenceObservedAtUtc: "2026-07-20T12:30:00+00:00",
      privacyClassification: "PublicMetadata"
    }],
    ...overrides
  };
}

test("normalizes a direction-explicit formal HIP score", () => {
  const scoring = normalizeFormalScoring(validFormalScoring());

  assert.equal(scoring?.isFormal, true);
  assert.equal(scoring?.modelVersion, "hip-0301-v1");
  assert.equal(scoring?.contentRiskScore, 24);
  assert.equal(scoring?.presentationStatus, "LimitedTrustData");
  assert.equal(scoring?.evidenceFreshness, "Mixed");
  assert.deepEqual(scoring?.reasons, ["Domain evidence is positive."]);
  assert.deepEqual(scoring?.reasonEntries, [{
    code: "score-cap:executable-weak-identity",
    explanation: "Executable risk limits the final score.",
    warningCode: "warning:executable-weak-identity",
    warning: "The executable lacks sufficiently strong identity evidence.",
    impact: { kind: "MaximumFinalScore", value: 39 },
    evidenceSourceCode: "site-safety:executable-download",
    evidenceObservedAtUtc: "2026-07-20T12:30:00+00:00",
    privacyClassification: "PublicMetadata"
  }]);
  assert.equal(Object.isFrozen(scoring?.reasonEntries), true);
  assert.equal(Object.isFrozen(scoring?.reasonEntries[0]), true);
});

test("ignores malformed optional catalog entries without discarding a valid formal score", () => {
  const scoring = normalizeFormalScoring(validFormalScoring({
    reasonEntries: [{
      code: "Not Canonical",
      explanation: "Untrusted entry.",
      warningCode: null,
      warning: null,
      impact: { kind: "MaximumFinalScore", value: 39 },
      evidenceSourceCode: "raw private value",
      evidenceObservedAtUtc: null,
      privacyClassification: "PublicMetadata"
    }]
  }));

  assert.equal(scoring?.isFormal, true);
  assert.deepEqual(scoring?.reasonEntries, []);
});

test("prefers nested formal scoring over conflicting legacy Site Safety scores", () => {
  const scoring = projectSiteSafetyScores({
    status: "Clean",
    contentRiskScore: 96,
    finalHipScore: 96,
    scoring: validFormalScoring()
  });

  assert.equal(scoring?.isFormal, true);
  assert.equal(scoring?.contentRiskScore, 24);
  assert.equal(scoring?.finalHipScore, 77);
  assert.equal(scoring?.presentationStatus, "LimitedTrustData");
});

test("rejects ambiguous formal directions and explicitly inverts legacy content trust", () => {
  const scoring = projectSiteSafetyScores({
    status: "Clean",
    domainTrustScore: 90,
    pageTrustScore: 80,
    contentRiskScore: 85,
    finalHipScore: 88,
    scoring: validFormalScoring({ contentRiskScoreHigherMeansMoreRisk: false })
  });

  assert.equal(scoring?.isFormal, false);
  assert.equal(scoring?.domainTrustScore, 90);
  assert.equal(scoring?.contentRiskScore, 15);
  assert.equal(scoring?.finalHipScore, 88);
  assert.equal(scoring?.presentationStatus, "Clean");
  assert.deepEqual(scoring?.reasonEntries, []);
});

test("rejects out-of-range or internally inconsistent formal scores", () => {
  assert.equal(normalizeFormalScoring(validFormalScoring({ contentRiskScore: 101 })), null);
  assert.equal(normalizeFormalScoring(validFormalScoring({
    canAssertPositiveTrust: true,
    trustAssertionDisposition: "WithheldConflictingEvidence"
  })), null);
  assert.equal(normalizeFormalScoring(validFormalScoring({
    presentationStatus: "Trusted"
  })), null);
});
