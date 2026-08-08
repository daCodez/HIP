export function isEmbeddedPanel(windowObject = window) {
  return new URLSearchParams(windowObject.location.search).get("embedded") === "1" && windowObject.parent !== windowObject;
}

/** Returns the explicitly supplied browser tab without exposing its URL to an embedded view. */
export function embeddedTabIdFromLocation(windowObject = window) {
  const value = Number(new URLSearchParams(windowObject.location.search).get("tab"));
  return Number.isInteger(value) && value > 0 ? value : null;
}

export function notifyPanelHost(action, windowObject = window) {
  if (!isEmbeddedPanel(windowObject) || !["page", "settings"].includes(action)) return false;
  windowObject.parent.postMessage({ source: "hip-embedded", action }, windowObject.location.origin);
  return true;
}

export function isTrustedEmbeddedMessage(event, expectedSource) {
  return event?.source === expectedSource && event?.data?.source === "hip-embedded" && ["page", "settings"].includes(event.data.action);
}
