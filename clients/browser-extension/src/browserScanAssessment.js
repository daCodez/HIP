(function registerHipBrowserScanAssessment(globalScope) {
  "use strict";

  const riskyStatuses = new Set(["Suspicious", "HighRisk", "Dangerous", "Critical"]);

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Gives the content script one small helper box for turning safe scan counts into a site result.
   */
  function browserScanAssessment(lookup, summary = {}) {
    if (summary.siteSafetyDataSource === "SiteSafetyScan" && Number.isInteger(summary.finalHipScore)) {
      const status = mapSiteSafetyStatus(summary.siteSafetyStatus);
      return {
        score: summary.finalHipScore,
        status,
        reasons: siteSafetyScanReasons(summary)
      };
    }

    if (!isLookupNoDataState(lookup)) {
      const status = lookup?.status || "Unknown";
      return {
        score: lookup?.finalHipScore ?? lookup?.score ?? 0,
        status,
        reasons: safeReasons(lookup)
      };
    }

    const dangerousLinks = summary.dangerousLinks ?? 0;
    const suspiciousLinks = summary.suspiciousLinks ?? 0;
    const riskyLinks = summary.riskyLinks ?? 0;
    const unknownLinks = summary.unknownLinks ?? 0;
    const downloadCandidates = summary.downloadCandidates ?? 0;
    const linksScanned = summary.linksScanned ?? 0;
    const clientChatLinkCandidates = summary.clientChatLinkCandidates ?? 0;
    const score = Math.max(0, Math.min(100, 80 - dangerousLinks * 30 - suspiciousLinks * 18 - Math.max(0, riskyLinks - suspiciousLinks - dangerousLinks) * 12 - unknownLinks * 6 - downloadCandidates * 4));

    return {
      score,
      status: browserScanStatus(score, dangerousLinks, suspiciousLinks, riskyLinks, unknownLinks),
      reasons: browserScanReasons({ linksScanned, riskyLinks, suspiciousLinks, dangerousLinks, unknownLinks, downloadCandidates, clientChatLinkCandidates })
    };
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Picks safe explanation text from HIP data without looking at private page words.
   */
  function safeReasons(lookup) {
    const reasons = lookup?.knownRisks?.length ? lookup.knownRisks : lookup?.explanations || lookup?.reasons || [];
    return reasons.length > 0 ? reasons : ["No risky links found by the browser plugin scan."];
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Changes Site Safety labels into the labels the plugin saves for dashboards and lookup pages.
   */
  function mapSiteSafetyStatus(status) {
    if (status === "Clean") {
      return "MostlyTrusted";
    }

    if (status === "LimitedData") {
      return "LimitedTrustData";
    }

    return ["Unknown", "Suspicious", "HighRisk", "Dangerous"].includes(status)
      ? status
      : "Unknown";
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Explains that HIP used safe browser observations instead of private page content.
   */
  function siteSafetyScanReasons(summary = {}) {
    const reasons = ["HIP ran a privacy-safe Site Safety scan using structural browser observations."];
    if (summary.confidenceLevel) {
      reasons.push(`Site Safety confidence: ${summary.confidenceLevel}.`);
    }

    if ((summary.providerEvidenceCount ?? 0) > 0) {
      reasons.push(`${summary.providerEvidenceCount} evidence provider result${summary.providerEvidenceCount === 1 ? " was" : "s were"} included.`);
    }

    return reasons;
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Spots the temporary "we have not scanned this yet" response so a real browser scan can replace it.
   */
  function isLookupNoDataState(lookup) {
    const reasons = [...(lookup?.knownRisks || []), ...(lookup?.explanations || []), ...(lookup?.reasons || [])];
    return !lookup ||
      lookup.dataSource === "NoStoredData" ||
      reasons.some(reason => typeof reason === "string" && reason.includes("HIP has not scanned this domain yet"));
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Turns safe link counts into a cautious status without pretending unknown sites are fully trusted.
   */
  function browserScanStatus(score, dangerousLinks, suspiciousLinks, riskyLinks, unknownLinks) {
    if (dangerousLinks > 0) {
      return "Dangerous";
    }

    if (suspiciousLinks > 0 || riskyLinks > 0) {
      return "Suspicious";
    }

    if (unknownLinks > 0 || score <= 60) {
      return "LimitedTrustData";
    }

    return "MostlyTrusted";
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Builds plain reasons from counts, not from private messages or page text.
   */
  function browserScanReasons({ linksScanned, riskyLinks, suspiciousLinks, dangerousLinks, unknownLinks, downloadCandidates, clientChatLinkCandidates = 0 }) {
    const reasons = [`Browser plugin scanned ${linksScanned} external links on this page without sending page text or form values.`];

    if (riskyLinks === 0 && suspiciousLinks === 0 && dangerousLinks === 0) {
      reasons.push("No risky external links were found in this browser plugin scan.");
    }

    if (clientChatLinkCandidates > 0) {
      reasons.push(`HIP observed ${clientChatLinkCandidates} link${clientChatLinkCandidates === 1 ? "" : "s"} inside chat-like areas without sending message text.`);
    }

    if (suspiciousLinks > 0) {
      reasons.push(`${suspiciousLinks} suspicious external link${suspiciousLinks === 1 ? " was" : "s were"} found.`);
    }

    if (dangerousLinks > 0) {
      reasons.push(`${dangerousLinks} dangerous external link${dangerousLinks === 1 ? " was" : "s were"} found.`);
    }

    if (unknownLinks > 0) {
      reasons.push(`${unknownLinks} external link${unknownLinks === 1 ? " has" : "s have"} unknown HIP status.`);
    }

    if (downloadCandidates > 0) {
      reasons.push(`${downloadCandidates} download-like link${downloadCandidates === 1 ? " was" : "s were"} detected for caution.`);
    }

    return reasons;
  }

  /**
   * Status: New
   * Changed: 2026-06-20 16:32 America/Toronto
   * Developer: Codex
   * Description: Chooses the safe next action from the final status the user sees.
   */
  function recommendedSiteAction(status) {
    if (riskyStatuses.has(status)) {
      return "RouteToSafetyPage";
    }

    if (status === "Unknown" || status === "LimitedTrustData" || status === "Caution") {
      return "ShowLabel";
    }

    return "Allow";
  }

  globalScope.HipBrowserScanAssessment = Object.freeze({
    browserScanAssessment,
    recommendedSiteAction
  });
})(globalThis);
