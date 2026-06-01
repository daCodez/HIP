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

export function statusFromScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) {
    return "Unknown";
  }

  const clamped = Math.max(0, Math.min(100, Math.round(numericScore)));
  return SCORE_BANDS.find(band => clamped >= band.min && clamped <= band.max)?.status || "Unknown";
}

export function displayStatus(status, score) {
  return status || statusFromScore(score);
}

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

export function buildPublicLookupUrl(webBaseUrl, domain, publicLookupUrl) {
  if (publicLookupUrl?.startsWith("http")) {
    return publicLookupUrl;
  }

  const safeDomain = encodeURIComponent(domain || "");
  return new URL(`/lookup/domain/${safeDomain}`, webBaseUrl || "http://localhost:5260").toString();
}

export function buildSafetyDetailsUrl(webBaseUrl, currentUrl, status) {
  if (!riskyStatuses.has(status) || !currentUrl) {
    return null;
  }

  const url = new URL("/safety", webBaseUrl || "http://localhost:5260");
  url.searchParams.set("url", currentUrl);
  url.searchParams.set("source", "browser");
  url.searchParams.set("risk", status);
  return url.toString();
}

export function reasonsFor(lookup) {
  const reasons = lookup?.reasons?.length
    ? lookup.reasons
    : lookup?.knownRisks?.length
      ? lookup.knownRisks
      : lookup?.explanations || [];

  return reasons.length
    ? reasons.slice(0, 5)
    : ["HIP returned a trust score without inspecting private page content."];
}

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
    domainTrustScoreText: scoreText(domainTrustScore),
    pageTrustScoreText: scoreText(pageTrustScore),
    contentRiskScoreText: scoreText(contentRiskScore),
    finalHipScoreExplanation: lookup?.finalHipScoreExplanation || "Final HIP score is based on separate domain, page, and content scores.",
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

export function unavailableMessage() {
  return "HIP API unavailable. Unable to score this site right now.";
}

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
