(function registerHipSiteBadgePlacement(global) {
  "use strict";

  const allowedPositions = new Set(["bottom-left", "bottom-right", "top-left", "top-right"]);
  const badgeSelector = "[data-hip-badge], .hip-trust-badge[data-domain]";

  function normalize(position) {
    return allowedPositions.has(position) ? position : "bottom-left";
  }

  /**
   * Applies the viewer's preferred corner to floating HIP website badges.
   * Publisher-owned inline badges remain in the document layout.
   */
  function apply(documentObject, position) {
    if (!documentObject?.querySelectorAll) return 0;

    const normalized = normalize(position);
    let updated = 0;
    for (const badge of documentObject.querySelectorAll(badgeSelector)) {
      if (badge?.getAttribute?.("data-position") === "inline") continue;
      badge?.setAttribute?.("data-position", normalized);
      badge?.style?.setProperty?.("--hip-overlap-shift", "0px");
      updated += 1;
    }
    return updated;
  }

  global.HipSiteBadgePlacement = Object.freeze({ apply, normalize, badgeSelector });
})(globalThis);
