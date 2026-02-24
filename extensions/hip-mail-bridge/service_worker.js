const DEFAULTS = {
  baseUrl: 'http://100.67.76.107:5101',
  identityId: 'hip-system',
  keyId: 'hip-system'
};

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.sync.get(Object.keys(DEFAULTS));
  await chrome.storage.sync.set({ ...DEFAULTS, ...existing });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === 'hip:getConfig') {
        const cfg = await chrome.storage.sync.get(Object.keys(DEFAULTS));
        sendResponse({ ok: true, config: { ...DEFAULTS, ...cfg } });
        return;
      }

      if (msg?.type === 'hip:sign') {
        const cfg = await chrome.storage.sync.get(Object.keys(DEFAULTS));
        const config = { ...DEFAULTS, ...cfg };

        const res = await fetch(`${config.baseUrl}/api/messages/sign`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: config.identityId,
            to: msg.to || 'email-recipient',
            body: msg.body || '',
            keyId: config.keyId
          })
        });

        const payload = await res.json();
        sendResponse({ ok: res.ok, status: res.status, payload });
        return;
      }

      if (msg?.type === 'hip:verify') {
        const cfg = await chrome.storage.sync.get(Object.keys(DEFAULTS));
        const config = { ...DEFAULTS, ...cfg };

        const res = await fetch(`${config.baseUrl}/api/messages/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(msg.signedMessage)
        });

        const payload = await res.json();
        sendResponse({ ok: res.ok, status: res.status, payload });
        return;
      }

      sendResponse({ ok: false, error: 'unknown_message_type' });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();

  return true;
});
