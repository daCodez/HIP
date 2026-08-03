(function registerHipContentMessageContracts(global) {
  "use strict";

  const allowedTypes = new Set(["HIP_REFRESH_SCAN", "HIP_GET_CONTENT_SUMMARY", "HIP_XRAY_START"]);

  /**
   * Accepts only payload-free commands sent by this extension's own pages.
   * Websites cannot call runtime messaging directly, but explicit validation
   * keeps this boundary closed if another extension context is compromised.
   */
  function validate(message, sender, runtimeId) {
    if (!runtimeId || sender?.id !== runtimeId) {
      return { ok: false, error: "Untrusted extension message sender." };
    }

    const expectedPrefix = `chrome-extension://${runtimeId}/`;
    if (typeof sender?.url !== "string" || !sender.url.startsWith(expectedPrefix)) {
      return { ok: false, error: "Content command must come from an extension page." };
    }

    if (!isPlainObject(message) || !allowedTypes.has(message.type)) {
      return { ok: false, error: "Unknown content-script message type." };
    }

    if (Object.keys(message).length !== 1 || Object.keys(message)[0] !== "type") {
      return { ok: false, error: "Content-script message contains unexpected data." };
    }

    return { ok: true, message: { type: message.type } };
  }

  function safeSummary(value) {
    const serialized = JSON.stringify(value);
    if (serialized.length > 128 * 1024) {
      throw new Error("Content summary exceeds the size limit.");
    }
    return JSON.parse(serialized);
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  }

  global.HipContentMessageContracts = Object.freeze({ validate, safeSummary });
})(globalThis);
