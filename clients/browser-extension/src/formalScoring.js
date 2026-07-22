(function registerHipFormalScoring(globalScope) {
  const supportedModelVersions = new Set(["hip-0301-v1"]);
  const formalStatuses = new Set([
    "Unknown",
    "Trusted",
    "MostlyTrusted",
    "LimitedTrustData",
    "Suspicious",
    "ProbablySafe",
    "Caution",
    "HighRisk",
    "Dangerous",
    "Critical"
  ]);
  const confidenceLevels = new Set(["Low", "Medium", "High", "Conflicted"]);
  const freshnessLevels = new Set(["Missing", "Fresh", "Mixed", "Stale", "Invalid"]);
  const assertionDispositions = new Set([
    "Allowed",
    "WithheldInsufficientEvidence",
    "WithheldConflictingEvidence"
  ]);
  const impactKinds = new Set([
    "None",
    "MaximumFinalScore",
    "ScoreDelta",
    "RiskScoreIncrease",
    "TrustScoreDelta"
  ]);
  const privacyClassifications = new Set(["PublicMetadata", "DerivedMetadata"]);
  const emptyReasonEntries = Object.freeze([]);

  /**
   * Accepts only the versioned, direction-explicit formal scoring projection. Unknown models fail closed
   * so a future response cannot silently change score semantics in an older extension.
   */
  function normalizeFormalScoring(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }

    const modelVersion = safeText(read(value, "modelVersion", "ModelVersion"), 64);
    const domainTrustScore = score(read(value, "domainTrustScore", "DomainTrustScore"));
    const pageTrustValue = read(value, "pageTrustScore", "PageTrustScore");
    const pageTrustScore = pageTrustValue === null || pageTrustValue === undefined
      ? null
      : score(pageTrustValue);
    const contentRiskScore = score(read(value, "contentRiskScore", "ContentRiskScore"));
    const finalHipScore = score(read(value, "finalHipScore", "FinalHipScore"));
    const finalStatus = safeText(read(value, "finalStatus", "FinalStatus"), 64);
    const presentationStatus = safeText(read(value, "presentationStatus", "PresentationStatus"), 64);
    const confidence = safeText(read(value, "confidence", "Confidence"), 32);
    const evidenceFreshness = safeText(read(value, "evidenceFreshness", "EvidenceFreshness"), 32);
    const trustAssertionDisposition = safeText(
      read(value, "trustAssertionDisposition", "TrustAssertionDisposition"),
      64);
    const canAssertPositiveTrust = read(value, "canAssertPositiveTrust", "CanAssertPositiveTrust");
    const finalScoreHigherMeansMoreTrust = read(
      value,
      "finalScoreHigherMeansMoreTrust",
      "FinalScoreHigherMeansMoreTrust");
    const contentRiskScoreHigherMeansMoreRisk = read(
      value,
      "contentRiskScoreHigherMeansMoreRisk",
      "ContentRiskScoreHigherMeansMoreRisk");
    const reasons = safeTextList(read(value, "reasons", "Reasons"), 5);
    const warnings = safeTextList(read(value, "warnings", "Warnings"), 5);
    const reasonEntries = normalizeReasonEntries(read(value, "reasonEntries", "ReasonEntries"));

    if (!supportedModelVersions.has(modelVersion)
      || domainTrustScore === null
      || (pageTrustValue !== null && pageTrustValue !== undefined && pageTrustScore === null)
      || contentRiskScore === null
      || finalHipScore === null
      || !formalStatuses.has(finalStatus)
      || !formalStatuses.has(presentationStatus)
      || !confidenceLevels.has(confidence)
      || !freshnessLevels.has(evidenceFreshness)
      || !assertionDispositions.has(trustAssertionDisposition)
      || typeof canAssertPositiveTrust !== "boolean"
      || finalScoreHigherMeansMoreTrust !== true
      || contentRiskScoreHigherMeansMoreRisk !== true
      || reasons.length === 0
      || !hasConsistentPresentation(
        finalHipScore,
        finalStatus,
        presentationStatus,
        trustAssertionDisposition)) {
      return null;
    }

    const expectedPositiveTrustAssertion =
      trustAssertionDisposition === "Allowed" && finalHipScore >= 70;
    if (canAssertPositiveTrust !== expectedPositiveTrustAssertion) {
      return null;
    }

    return Object.freeze({
      isFormal: true,
      modelVersion,
      domainTrustScore,
      pageTrustScore,
      contentRiskScore,
      finalHipScore,
      finalStatus,
      presentationStatus,
      confidence,
      evidenceFreshness,
      trustAssertionDisposition,
      canAssertPositiveTrust,
      finalScoreHigherMeansMoreTrust: true,
      contentRiskScoreHigherMeansMoreRisk: true,
      reasons,
      warnings,
      reasonEntries
    });
  }

  /**
   * Prefers formal scoring. The legacy Site Safety ContentRiskScore field is actually a content-trust
   * score where higher is safer, so compatibility output explicitly inverts it before naming it risk.
   */
  function projectSiteSafetyScores(result) {
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      return null;
    }

    const formal = normalizeFormalScoring(read(result, "scoring", "Scoring"));
    if (formal) {
      return formal;
    }

    const domainTrustScore = score(read(result, "domainTrustScore", "DomainTrustScore"));
    const pageTrustScore = optionalScore(read(result, "pageTrustScore", "PageTrustScore"));
    const legacyContentTrustScore = score(read(result, "contentRiskScore", "ContentRiskScore"));
    const finalHipScore = score(read(result, "finalHipScore", "FinalHipScore"));
    const legacyStatus = safeText(read(result, "status", "Status"), 64) || "Unknown";
    const legacyConfidence = safeText(read(result, "confidenceLevel", "ConfidenceLevel"), 32) || "Unknown";

    if (domainTrustScore === null
      && pageTrustScore === null
      && legacyContentTrustScore === null
      && finalHipScore === null) {
      return null;
    }

    return Object.freeze({
      isFormal: false,
      modelVersion: null,
      domainTrustScore,
      pageTrustScore,
      contentRiskScore: legacyContentTrustScore === null ? null : 100 - legacyContentTrustScore,
      finalHipScore,
      finalStatus: legacyStatus,
      presentationStatus: legacyStatus,
      confidence: legacyConfidence,
      evidenceFreshness: "Unknown",
      trustAssertionDisposition: "Unknown",
      canAssertPositiveTrust: false,
      finalScoreHigherMeansMoreTrust: true,
      contentRiskScoreHigherMeansMoreRisk: true,
      reasons: [],
      warnings: [],
      reasonEntries: emptyReasonEntries
    });
  }

  /**
   * Normalizes only the bounded public fields in optional HIP-0303 catalog entries. A malformed
   * entry is ignored without discarding an otherwise valid formal score or retaining extra fields.
   */
  function normalizeReasonEntries(value) {
    if (value === null || value === undefined) {
      return emptyReasonEntries;
    }

    if (!Array.isArray(value)) {
      return emptyReasonEntries;
    }

    return Object.freeze(value
      .slice(0, 32)
      .map(normalizeReasonEntry)
      .filter(Boolean));
  }

  function normalizeReasonEntry(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }

    const code = protocolToken(read(value, "code", "Code"), 128);
    const explanation = boundedText(read(value, "explanation", "Explanation"), 512);
    const warningCodeValue = read(value, "warningCode", "WarningCode");
    const warningValue = read(value, "warning", "Warning");
    const hasWarning = warningCodeValue !== null && warningCodeValue !== undefined
      && warningValue !== null && warningValue !== undefined;
    const warningCode = hasWarning ? protocolToken(warningCodeValue, 128) : null;
    const warning = hasWarning ? boundedText(warningValue, 512) : null;
    const impact = normalizeImpact(read(value, "impact", "Impact"));
    const evidenceSourceCode = protocolToken(
      read(value, "evidenceSourceCode", "EvidenceSourceCode"),
      128);
    const observedValue = read(value, "evidenceObservedAtUtc", "EvidenceObservedAtUtc");
    const evidenceObservedAtUtc = observedValue === null || observedValue === undefined
      ? null
      : validTimestamp(observedValue);
    const privacyClassification = safeText(
      read(value, "privacyClassification", "PrivacyClassification"),
      32);

    if (!code
      || !explanation
      || ((warningCodeValue === null || warningCodeValue === undefined)
        !== (warningValue === null || warningValue === undefined))
      || (hasWarning && (!warningCode || !warning))
      || !impact
      || !evidenceSourceCode
      || (observedValue !== null && observedValue !== undefined && !evidenceObservedAtUtc)
      || !privacyClassifications.has(privacyClassification)) {
      return null;
    }

    return Object.freeze({
      code,
      explanation,
      warningCode,
      warning,
      impact,
      evidenceSourceCode,
      evidenceObservedAtUtc,
      privacyClassification
    });
  }

  function normalizeImpact(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }

    const kind = safeText(read(value, "kind", "Kind"), 32);
    const impactValue = read(value, "value", "Value");
    const isValid = impactKinds.has(kind) && (
      (kind === "None" && (impactValue === null || impactValue === undefined))
      || (kind === "MaximumFinalScore" && score(impactValue) !== null)
      || (kind === "RiskScoreIncrease" && score(impactValue) !== null)
      || (kind === "TrustScoreDelta"
        && Number.isInteger(impactValue)
        && impactValue >= -100
        && impactValue <= 100)
      || (kind === "ScoreDelta"
        && Number.isInteger(impactValue)
        && impactValue >= -100
        && impactValue <= 100));
    return isValid
      ? Object.freeze({ kind, value: impactValue ?? null })
      : null;
  }

  function read(value, camelName, pascalName) {
    return value?.[camelName] ?? value?.[pascalName];
  }

  function hasConsistentPresentation(
    finalHipScore,
    finalStatus,
    presentationStatus,
    trustAssertionDisposition) {
    const expectedStatus = finalHipScore < 50
      ? finalStatus
      : trustAssertionDisposition === "Allowed"
        ? finalStatus
        : trustAssertionDisposition === "WithheldConflictingEvidence"
          ? "Unknown"
          : "LimitedTrustData";
    return presentationStatus === expectedStatus;
  }

  function score(value) {
    return Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;
  }

  function optionalScore(value) {
    return value === null || value === undefined ? null : score(value);
  }

  function safeText(value, maxLength) {
    return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
  }

  function boundedText(value, maxLength) {
    if (typeof value !== "string") {
      return "";
    }

    const trimmed = value.trim();
    return trimmed && trimmed.length <= maxLength && !/[\u0000-\u001f\u007f]/u.test(trimmed)
      ? trimmed
      : "";
  }

  function protocolToken(value, maxLength) {
    const token = boundedText(value, maxLength);
    return token && /^[a-z0-9:._-]+$/u.test(token) ? token : "";
  }

  function validTimestamp(value) {
    const timestamp = boundedText(value, 64);
    return timestamp && Number.isFinite(Date.parse(timestamp)) ? timestamp : "";
  }

  function safeTextList(value, maxItems) {
    return Array.isArray(value)
      ? value
        .slice(0, maxItems)
        .map(item => safeText(item, 500))
        .filter(Boolean)
      : [];
  }

  globalScope.HipFormalScoring = Object.freeze({
    normalizeFormalScoring,
    projectSiteSafetyScores
  });
})(globalThis);
