/**
 * Status: Updated
 * Changed: 2026-06-21 02:02 UTC
 * Developer: HIP Development Team
 * Assisted by: Codex
 * Description: Keeps all browser scan URL checks in one place so HIP does not send private or local addresses by mistake.
 */
(function registerHipBrowserPrivacyGuards(globalScope) {
  "use strict";

  function normalizeHost(hostname) {
    return (hostname || "").replace(/^www\./i, "").toLowerCase();
  }

  // Raw page URLs are optional diagnostics, so remove query strings and fragments before anything can leave the browser.
  function stripQueryAndFragment(pageUrl) {
    try {
      const url = new URL(pageUrl);
      if (!["http:", "https:"].includes(url.protocol)) {
        return null;
      }

      url.search = "";
      url.hash = "";
      return url.toString();
    } catch {
      return null;
    }
  }

  // HIP pages already contain HIP UI and API calls, so scanning them creates loops instead of useful safety evidence.
  function isHipOwnedPage(pageUrl, currentSettings = {}) {
    try {
      const pageOrigin = new URL(pageUrl).origin;
      const hipOrigins = [currentSettings.apiBaseUrl, currentSettings.hipApiBaseUrl, currentSettings.webBaseUrl]
        .filter(Boolean)
        .map(value => new URL(value).origin);
      return hipOrigins.includes(pageOrigin);
    } catch {
      return false;
    }
  }

  // Internal hosts can expose local services or private networks, so they are never submitted for Site Safety scans.
  function isInternalHost(hostname) {
    const host = normalizeHost(hostname);
    if (!host ||
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host === "::1" ||
      host === "[::1]") {
      return true;
    }

    const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!ipv4) {
      return false;
    }

    const octets = ipv4.slice(1).map(Number);
    if (octets.some(octet => Number.isNaN(octet) || octet < 0 || octet > 255)) {
      return true;
    }

    return octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168);
  }

  function isSiteSafetyEligibleUrl(pageUrl, currentSettings = {}) {
    try {
      const url = new URL(pageUrl);
      return ["http:", "https:"].includes(url.protocol) &&
        !isHipOwnedPage(pageUrl, currentSettings) &&
        !isInternalHost(url.hostname);
    } catch {
      return false;
    }
  }

  // Evidence URLs are optional provider hints, not page content, so keep only public web URLs.
  function filterSafePublicUrls(values, currentSettings = {}) {
    if (!Array.isArray(values)) {
      return [];
    }

    return values
      .filter(value => typeof value === "string")
      .filter(value => isSiteSafetyEligibleUrl(value, currentSettings));
  }

  globalScope.HipBrowserPrivacyGuards = Object.freeze({
    filterSafePublicUrls,
    isHipOwnedPage,
    isInternalHost,
    isSiteSafetyEligibleUrl,
    normalizeHost,
    stripQueryAndFragment
  });
})(globalThis);
