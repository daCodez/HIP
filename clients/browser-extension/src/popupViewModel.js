export const SCORE_BANDS = Object.freeze([
  { min: 81, max: 100, status: "Trusted", label: "Trusted" },
  { min: 61, max: 80, status: "ProbablySafe", label: "Probably Safe" },
  { min: 41, max: 60, status: "Caution", label: "Unknown / Caution" },
  { min: 21, max: 40, status: "HighRisk", label: "High Risk" },
  { min: 0, max: 20, status: "Dangerous", label: "Dangerous" }
]);

const riskyStatuses = new Set(["HighRisk", "Dangerous", "Critical"]);

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
    ProbablySafe: "Probably Safe",
    Caution: "Caution",
    HighRisk: "High Risk",
    Dangerous: "Dangerous",
    Critical: "Critical",
    Unknown: "Unknown"
  }[status] || "Unknown";
}

export function statusClass(status) {
  return {
    Trusted: "trusted",
    ProbablySafe: "probably-safe",
    Caution: "caution",
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
  return new URL(`/lookup/domain/${safeDomain}`, webBaseUrl || "https://localhost:7053").toString();
}

export function buildSafetyDetailsUrl(webBaseUrl, currentUrl, status) {
  if (!riskyStatuses.has(status) || !currentUrl) {
    return null;
  }

  const url = new URL("/safety", webBaseUrl || "https://localhost:7053");
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

  return {
    domain: lookup?.domain || "Unknown domain",
    scoreText: score !== null && score !== undefined && Number.isFinite(Number(score)) ? `${score}/100` : "--/100",
    status,
    statusLabel: statusLabel(status),
    statusClass: statusClass(status),
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
