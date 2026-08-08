(function registerHipContentMessageContracts(global) {
  "use strict";

  const payloadFreeTypes = new Set([
    "HIP_REFRESH_SCAN", "HIP_GET_CONTENT_SUMMARY", "HIP_XRAY_START", "HIP_XRAY_RESCAN", "HIP_XRAY_STOP"
  ]);
  const allowedTypes = new Set([...payloadFreeTypes, "HIP_XRAY_GET_STATE", "HIP_XRAY_SELECT_FINDING", "HIP_XRAY_SET_MARKERS"]);
  const MAX_FINDING_ID_LENGTH = 240;

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

    const keys = Object.keys(message);
    if (payloadFreeTypes.has(message.type) && (keys.length !== 1 || keys[0] !== "type")) {
      return { ok: false, error: "Content-script message contains unexpected data." };
    }

    if (message.type === "HIP_XRAY_SELECT_FINDING") {
      if (!hasExactKeys(keys, ["type", "findingId"]) || typeof message.findingId !== "string" || !message.findingId.length || message.findingId.length > MAX_FINDING_ID_LENGTH) {
        return { ok: false, error: "X-ray finding selection is invalid." };
      }
      return { ok: true, message: { type: message.type, findingId: message.findingId } };
    }

    if (message.type === "HIP_XRAY_SET_MARKERS") {
      if (!hasExactKeys(keys, ["type", "visible"]) || typeof message.visible !== "boolean") {
        return { ok: false, error: "X-ray marker preference is invalid." };
      }
      return { ok: true, message: { type: message.type, visible: message.visible } };
    }

    if (message.type === "HIP_XRAY_GET_STATE") {
      if (!keys.every(key => ["type", "inventoryOffset", "inventoryLimit", "findingOffset", "findingLimit"].includes(key))) {
        return { ok: false, error: "X-ray state request contains unexpected data." };
      }
      const offset = boundedInteger(message.inventoryOffset, 0, 2500, 0);
      const limit = boundedInteger(message.inventoryLimit, 1, 100, 50);
      const findingOffset = boundedInteger(message.findingOffset, 0, 2500, 0);
      const findingLimit = boundedInteger(message.findingLimit, 1, 100, 50);
      if (("inventoryOffset" in message && offset === null) || ("inventoryLimit" in message && limit === null) ||
          ("findingOffset" in message && findingOffset === null) || ("findingLimit" in message && findingLimit === null)) {
        return { ok: false, error: "X-ray inventory request is invalid." };
      }
      return { ok: true, message: { type: message.type, inventoryOffset: offset ?? 0, inventoryLimit: limit ?? 50, findingOffset: findingOffset ?? 0, findingLimit: findingLimit ?? 50 } };
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

  function hasExactKeys(actual, expected) {
    return actual.length === expected.length && expected.every(key => actual.includes(key));
  }

  function boundedInteger(value, minimum, maximum, fallback) {
    if (value === undefined) return fallback;
    return Number.isInteger(value) && value >= minimum && value <= maximum ? value : null;
  }

  global.HipContentMessageContracts = Object.freeze({ validate, safeSummary });
})(globalThis);
