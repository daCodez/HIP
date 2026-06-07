export const SCORE_BANDS = Object.freeze([
  { min: 85, max: 100, status: "Trusted", label: "Trusted" },
  { min: 70, max: 84, status: "MostlyTrusted", label: "Mostly Trusted" },
  { min: 50, max: 69, status: "LimitedTrustData", label: "Limited Trust Data" },
  { min: 40, max: 49, status: "Unknown", label: "Unknown" },
  { min: 25, max: 39, status: "Suspicious", label: "Suspicious" },
  { min: 10, max: 24, status: "HighRisk", label: "High Risk" },
  { min: 0, max: 9, status: "Dangerous", label: "Dangerous" }
]);

const riskyStatuses = new Set(["Suspicious", "HighRisk", "Dangerous", "Critical"]);
const privateContentPatterns = [
  /page\s*text/i,
  /form\s*(value|content|field)/i,
  /password/i,
  /token/i,
  /cookie/i,
  /private\s*(message|chat)/i,
  /email\s*(body|content)/i
];

export const SCORE_HELP_TEXT = Object.freeze({
  finalHipScore: "The final trust score for this interaction.",
  domainTrust: "How trustworthy is this website overall?",
  pageTrust: "How trustworthy is this exact page?",
  contentRisk: "How risky is the content on this page?"
});

export const STATUS_DESCRIPTIONS = Object.freeze({
  Trusted: "HIP found strong trust signals for this site.",
  MostlyTrusted: "HIP found mostly positive trust signals, but you should still use normal caution.",
  LimitedTrustData: "HIP has limited trust data for this website.",
  Unknown: "HIP does not have enough information about this website yet.",
  Suspicious: "HIP found suspicious signals on this page.",
  HighRisk: "HIP found high-risk signals. Be careful.",
  Dangerous: "HIP found strong phishing or malware indicators. Avoid this page.",
  Critical: "HIP found strong phishing or malware indicators. Avoid this page.",
  Clean: "HIP did not find obvious page safety problems in this scan.",
  LimitedData: "HIP has limited site safety data for this page.",
  ScanFailed: "HIP could not complete the site safety scan right now."
});

export const FEEDBACK_COPY = Object.freeze({
  prompt: "Help HIP improve this trust signal.",
  success: "Thanks. HIP will use this as one trust signal.",
  failure: "Feedback could not be sent right now."
});

/**
 * Maps a numeric final HIP score to the MVP status band shown to users.
 */
export function statusFromScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) {
    return "Unknown";
  }

  const clamped = Math.max(0, Math.min(100, Math.round(numericScore)));
  return SCORE_BANDS.find(band => clamped >= band.min && clamped <= band.max)?.status || "Unknown";
}

/**
 * Chooses the explicit API status when present, otherwise derives one from the final score.
 */
export function displayStatus(status, score) {
  return status || statusFromScore(score);
}

/**
 * Converts protocol status values into spaced labels for compact popup pills.
 */
export function statusLabel(status) {
  return {
    Trusted: "Trusted",
    MostlyTrusted: "Mostly Trusted",
    LimitedTrustData: "Limited Trust Data",
    ProbablySafe: "Probably Safe",
    Caution: "Caution",
    Suspicious: "Suspicious",
    HighRisk: "High Risk",
    Dangerous: "Dangerous",
    Critical: "Critical",
    Unknown: "Unknown"
  }[status] || "Unknown";
}

/**
 * Converts protocol status values into CSS class names used by badges and pills.
 */
export function statusClass(status) {
  return {
    Trusted: "trusted",
    MostlyTrusted: "mostly-trusted",
    LimitedTrustData: "limited-trust-data",
    ProbablySafe: "probably-safe",
    Caution: "caution",
    Suspicious: "suspicious",
    HighRisk: "high-risk",
    Dangerous: "dangerous",
    Critical: "critical",
    Unknown: "unknown"
  }[status] || "unknown";
}

/**
 * Returns user-facing status copy that explains what HIP knows without overstating safety.
 */
export function statusDescription(status) {
  return STATUS_DESCRIPTIONS[status] || STATUS_DESCRIPTIONS.Unknown;
}

/**
 * Builds the public lookup URL with the configured HIP Web host.
 */
export function buildPublicLookupUrl(webBaseUrl, domain, publicLookupUrl) {
  if (publicLookupUrl?.startsWith("http")) {
    return publicLookupUrl;
  }

  const safeDomain = encodeURIComponent(domain || "");
  return new URL(`/lookup/domain/${safeDomain}`, webBaseUrl || "http://localhost:5123").toString();
}

/**
 * Builds a safety details URL only for statuses that need a safety-page route.
 */
export function buildSafetyDetailsUrl(webBaseUrl, currentUrl, status) {
  if (!riskyStatuses.has(status) || !currentUrl) {
    return null;
  }

  const url = new URL("/safety", webBaseUrl || "http://localhost:5123");
  url.searchParams.set("url", currentUrl);
  url.searchParams.set("source", "browser");
  url.searchParams.set("risk", status);
  return url.toString();
}

/**
 * Redacts obvious private-content wording from API messages before displaying them in the popup.
 * The extension should never request those fields, but this guard prevents accidental display if a server bug returns them.
 */
export function safeDisplayText(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }

  if (privateContentPatterns.some(pattern => pattern.test(text))) {
    return "HIP removed private-looking details from this message.";
  }

  return text;
}

/**
 * Selects plain-English reasons for the popup and keeps only display-safe summary text.
 */
export function reasonsFor(lookup) {
  const reasons = lookup?.reasons?.length
    ? lookup.reasons
    : lookup?.knownRisks?.length
      ? lookup.knownRisks
      : lookup?.explanations || [];

  return reasons.length
    ? reasons.slice(0, 5).map(safeDisplayText).filter(Boolean)
    : ["HIP returned a trust score without inspecting private page content."];
}

/**
 * Builds the primary popup model from public-safe lookup data and content-script scan counts.
 */
export function buildPopupViewModel(lookup, summary, settings, currentUrl) {
  const score = lookup?.score ?? lookup?.finalHipScore ?? null;
  const status = displayStatus(lookup?.status, score);
  const domainTrustScore = lookup?.domainTrustScore ?? componentScore(lookup, "DomainTrustScore");
  const pageTrustScore = lookup?.pageTrustScore ?? componentScore(lookup, "PageTrustScore");
  const contentRiskScore = lookup?.contentRiskScore ?? componentScore(lookup, "ContentRiskScore");

  return {
    domain: lookup?.domain || "Unknown domain",
    scoreText: score !== null && score !== undefined && Number.isFinite(Number(score)) ? `${score}/100` : "--/100",
    status,
    statusLabel: statusLabel(status),
    statusClass: statusClass(status),
    statusDescription: statusDescription(status),
    finalHipScoreHelp: SCORE_HELP_TEXT.finalHipScore,
    domainTrustHelp: SCORE_HELP_TEXT.domainTrust,
    pageTrustHelp: SCORE_HELP_TEXT.pageTrust,
    contentRiskHelp: SCORE_HELP_TEXT.contentRisk,
    domainTrustScoreText: scoreText(domainTrustScore),
    pageTrustScoreText: scoreText(pageTrustScore),
    contentRiskScoreText: scoreText(contentRiskScore),
    finalHipScoreExplanation: safeDisplayText(lookup?.finalHipScoreExplanation || "Final HIP score is based on separate domain, page, and content scores."),
    verifiedText: lookup?.verificationStatus === "Verified" ? "Yes" : "No",
    identityText: lookup?.identityVerificationStatus || lookup?.signedIdentityStatus || "Unknown",
    lastCheckedText: formatDate(lookup?.lastCheckedUtc),
    reasons: reasonsFor(lookup),
    linksScanned: summary?.linksScanned ?? 0,
    riskyLinks: summary?.riskyLinks ?? 0,
    unknownLinks: summary?.unknownLinks ?? 0,
    apiStatus: summary?.apiStatus || "Unknown",
    downloadCandidates: summary?.downloadCandidates ?? 0,
    loginFormsDetected: summary?.loginFormsDetected ?? 0,
    lastScanText: formatDate(summary?.updatedAt),
    lastSubmittedText: submissionText(summary),
    dataSourceText: summary?.scanResultDataSource || lookup?.dataSource || "Pending",
    lookupUrl: buildPublicLookupUrl(settings?.webBaseUrl, lookup?.domain, lookup?.publicLookupUrl),
    safetyDetailsUrl: buildSafetyDetailsUrl(settings?.webBaseUrl, currentUrl, status)
  };
}

/**
 * Builds explicit popup loading labels for asynchronous scan stages.
 */
export function loadingSummaryViewModel(stage = "Checking") {
  return {
    apiStatus: stage,
    linksScanned: "Checking...",
    riskyLinks: "Checking...",
    unknownLinks: "Checking...",
    downloadCandidates: "Checking...",
    loginFormsDetected: "Checking...",
    lastScanText: "Checking...",
    lastSubmittedText: "Pending",
    dataSourceText: "Pending"
  };
}

/**
 * Builds the Site Safety panel model from normalized scanner output.
 * Only score summaries, confidence, and warnings are displayed; raw page content is intentionally excluded.
 */
export function buildSiteSafetyViewModel(result = {}) {
  const status = result?.status || "Unknown";
  const warnings = warningsFor(result);
  return {
    status,
    statusLabel: statusLabel(status),
    statusDescription: statusDescription(status),
    confidenceLevelText: result?.confidenceLevel || "Unknown",
    summary: safeDisplayText(result?.summary || "HIP has limited site safety data for this page."),
    warnings,
    hasWarnings: warnings.length > 0,
    malwareRiskText: riskLabel(result?.malwareRiskScore),
    phishingRiskText: riskLabel(result?.phishingRiskScore),
    redirectRiskText: riskLabel(result?.redirectRiskScore),
    downloadRiskText: riskLabel(result?.downloadRiskScore),
    scriptRiskText: riskLabel(result?.scriptRiskScore),
    externalEvidence: externalEvidenceFor(result)
  };
}

/**
 * Builds compact display rows for normalized external safety evidence.
 * Provider evidence is intentionally summarized so the popup never displays raw scanner payloads or private page data.
 */
export function externalEvidenceFor(siteSafety = {}) {
  const evidence = Array.isArray(siteSafety?.providerEvidence)
    ? siteSafety.providerEvidence
    : Array.isArray(siteSafety?.ProviderEvidence)
      ? siteSafety.ProviderEvidence
      : [];

  return evidence
    .map(provider => externalEvidenceRow(provider))
    .filter(Boolean)
    .slice(0, 4);
}

/**
 * Converts a single provider result into a safe display row.
 */
function externalEvidenceRow(provider) {
  const providerName = safeDisplayText(provider?.providerName || provider?.ProviderName || "External provider");
  const confidence = provider?.confidence ?? provider?.Confidence ?? "Unknown";
  const items = Array.isArray(provider?.evidenceItems)
    ? provider.evidenceItems
    : Array.isArray(provider?.EvidenceItems)
      ? provider.EvidenceItems
      : [];
  const firstItem = items[0] || {};
  const status = firstItem.status || firstItem.Status || "Unknown";
  const value = firstItem.value || firstItem.Value || "";
  const summary = safeDisplayText(firstItem.summary || firstItem.Summary || provider?.errors?.[0] || provider?.Errors?.[0] || "Provider returned no displayable evidence yet.");
  const statusLabel = value
    ? `${statusLabelForProvider(status)} ${safeDisplayText(value)}`
    : statusLabelForProvider(status);

  return {
    providerName,
    statusLabel,
    summary: `${summary} Confidence: ${confidence}.`
  };
}

/**
 * Converts provider evidence statuses into concise popup labels.
 */
function statusLabelForProvider(status) {
  return {
    Positive: "Positive",
    Clean: "Clean",
    Weak: "Weak",
    Error: "Error",
    Dangerous: "Dangerous",
    HighRisk: "High Risk",
    Suspicious: "Suspicious",
    Unknown: "Unknown"
  }[status] || "Unknown";
}

/**
 * Returns useful warning text from Site Safety output while avoiding raw private content.
 */
export function warningsFor(siteSafety = {}) {
  const warnings = Array.isArray(siteSafety?.warnings) ? siteSafety.warnings : [];
  return warnings.slice(0, 5).map(safeDisplayText).filter(Boolean);
}

/**
 * Converts a numeric risk score into a compact popup label.
 * Labels intentionally describe safety risk, not overall HIP trust.
 */
export function riskLabel(score) {
  if (typeof score !== "number") {
    return "Unknown";
  }

  if (score <= 0) {
    return "None found";
  }

  if (score <= 20) {
    return "Low";
  }

  if (score <= 40) {
    return "Medium";
  }

  if (score <= 65) {
    return "Elevated";
  }

  return "High";
}

/**
 * Returns the standard popup feedback copy so wording stays consistent across tests and UI.
 */
export function feedbackCopy() {
  return FEEDBACK_COPY;
}

export function unavailableMessage() {
  return "HIP API unavailable. Unable to score this site right now.";
}

/**
 * Formats UTC timestamps for compact popup display without leaking local browsing context.
 */
function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/**
 * Formats optional layered scores for compact popup display.
 */
function scoreText(score) {
  return score !== null && score !== undefined && Number.isFinite(Number(score)) ? `${score}/100` : "--/100";
}

/**
 * Reads a named score component from API responses that only provide a breakdown array.
 */
function componentScore(lookup, category) {
  return lookup?.scoreBreakdown?.find(item => item.category === category)?.score ?? null;
}

/**
 * Formats scan-result submission state for the popup without exposing request payload details.
 */
function submissionText(summary) {
  const status = summary?.scanResultSubmission || "Pending";
  if (status === "Success" && summary?.lastSubmittedUtc) {
    return `Success (${formatDate(summary.lastSubmittedUtc)})`;
  }

  return status;
}
