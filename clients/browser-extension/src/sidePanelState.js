export const STATUS_PRESENTATIONS = Object.freeze({
  Critical: Object.freeze({ key: "risky", label: "Risky", color: "#ef4444" }),
  High: Object.freeze({ key: "risky", label: "Risky", color: "#ef4444" }),
  Medium: Object.freeze({ key: "caution", label: "Caution", color: "#f97316" }),
  Low: Object.freeze({ key: "review", label: "Review", color: "#f59e0b" }),
  Info: Object.freeze({ key: "informational", label: "Informational", color: "#3882f6" }),
  Safe: Object.freeze({ key: "safe", label: "Safe in this scan", color: "#22c55e" })
});

export function statusPresentation(value) {
  return STATUS_PRESENTATIONS[value] || STATUS_PRESENTATIONS.Info;
}

export function storagePresentation(value) {
  if (value === "Success" || value === "DuplicateSuppressed") return { key: "recorded", label: "Summary recorded" };
  if (value === "Failed" || value === "Error") return { key: "failed", label: "Not stored" };
  return { key: "local", label: "Local only" };
}

export function isSupportedPageUrl(value) {
  try {
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

/** Selects the active web tab, or the most recently used web tab when an extension surface has focus. */
export function pickInspectableTab(tabs = []) {
  return [...tabs]
    .filter(tab => Number.isInteger(tab?.id) && isSupportedPageUrl(tab?.url))
    .sort((left, right) => Number(Boolean(right.active)) - Number(Boolean(left.active)) || (Number(right.lastAccessed) || 0) - (Number(left.lastAccessed) || 0))[0] || null;
}

export function inventoryPage(items, offset = 0, limit = 50, coverage = {}) {
  const source = Array.isArray(items) ? items.slice(0, 2500) : [];
  const safeOffset = Math.max(0, Math.min(Number(offset) || 0, source.length));
  const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 100));
  const nextOffset = Math.min(source.length, safeOffset + safeLimit);
  return {
    items: source.slice(safeOffset, nextOffset),
    nextOffset: nextOffset < source.length ? nextOffset : null,
    inspectedCount: Math.min(2500, Number(coverage.inspectedElementCount) || source.length),
    truncated: coverage.truncated === true
  };
}

export function createActiveTabCoordinator({ clear, load, commit }) {
  let generation = 0;
  let activeTabId = null;
  return Object.freeze({
    async activate(tab = {}) {
      const requestGeneration = ++generation;
      activeTabId = Number.isInteger(tab.id) ? tab.id : null;
      const supported = activeTabId !== null && isSupportedPageUrl(tab.url);
      clear({ tabId: activeTabId, generation: requestGeneration, supported });
      if (!supported) return { committed: false, reason: "unsupported" };
      try {
        const state = await load(tab, requestGeneration);
        if (requestGeneration !== generation || activeTabId !== tab.id) return { committed: false, reason: "stale" };
        commit(state, { tabId: tab.id, generation: requestGeneration });
        return { committed: true };
      } catch (error) {
        if (requestGeneration === generation && activeTabId === tab.id) {
          commit({ tabId: tab.id, error: error?.message || "HIP is unavailable on this page." }, { tabId: tab.id, generation: requestGeneration });
        }
        return { committed: false, reason: "error" };
      }
    },
    invalidate() {
      generation += 1;
      activeTabId = null;
      clear({ tabId: null, generation, supported: false });
    },
    current: () => ({ tabId: activeTabId, generation })
  });
}
