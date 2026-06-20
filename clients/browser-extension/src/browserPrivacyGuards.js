/**
 * Status: New
 * Changed: 2026-06-20 21:05 UTC
 * Developer: Codex
 * Description: Adds one shared browser privacy helper so scan code can reuse the same safe URL rules.
 */
(function registerHipBrowserPrivacyGuards(globalScope) {
  "use strict";

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Cleans a host name so different parts of the extension compare domains the same way.
   */
  function normalizeHost(hostname) {
    return (hostname || "").replace(/^www\./i, "").toLowerCase();
  }

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Removes private URL pieces before optional raw URL diagnostics can be sent.
   */
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

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Spots HIP's own pages so the plugin does not scan itself and create noisy local errors.
   */
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

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Blocks localhost and private-network targets so HIP does not send local addresses to Site Safety.
   */
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

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Checks whether a page URL is safe for the Site Safety API before any scan request is made.
   */
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

  /**
   * Status: New
   * Changed: 2026-06-20 21:05 UTC
   * Developer: Codex
   * Description: Keeps optional evidence URL lists public-only before they leave the browser.
   */
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
