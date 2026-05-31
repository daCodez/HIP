(function attachSafetyPageRouter() {
  window.HipSafetyPageRouter = {
    routeClick
  };

  async function routeClick(event, anchor, lookup, sourceDomain) {
    if (!anchor?.href) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();

    if (lookup?.safetyPageUrl && /^https?:\/\//i.test(lookup.safetyPageUrl)) {
      window.location.assign(lookup.safetyPageUrl);
      return;
    }

    const response = await chrome.runtime.sendMessage({
      type: "HIP_SAFETY_URL",
      originalUrl: anchor.href,
      sourceDomain,
      riskStatus: lookup?.status
    });

    if (response?.ok && response.result) {
      window.location.assign(response.result);
      return;
    }

    window.location.assign(anchor.href);
  }
})();
