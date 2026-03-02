const DEFAULTS = {
  baseUrl: 'http://100.67.76.107:5101',
  identityId: 'hip-system',
  keyId: 'hip-system'
};

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.sync.get(Object.keys(DEFAULTS));
  await chrome.storage.sync.set({ ...DEFAULTS, ...existing });
});

function b64urlUtf8(input) {
  const b64 = btoa(unescape(encodeURIComponent(input)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function getAuthToken(interactive = true) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(new Error(chrome.runtime.lastError?.message || 'no_token'));
        return;
      }
      resolve(token);
    });
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === 'hip:getConfig') {
        const cfg = await chrome.storage.sync.get(Object.keys(DEFAULTS));
        sendResponse({ ok: true, config: { ...DEFAULTS, ...cfg } });
        return;
      }

      if (msg?.type === 'hip:googleAuth') {
        try {
          const token = await getAuthToken(true);
          sendResponse({ ok: true, tokenPresent: !!token });
        } catch (e) {
          sendResponse({ ok: false, error: String(e) });
        }
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

        const res = await fetch(`${config.baseUrl}/api/messages/verify-readonly`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(msg.signedMessage)
        });

        const payload = await res.json();
        sendResponse({ ok: res.ok, status: res.status, payload });
        return;
      }

      if (msg?.type === 'hip:gmailSendHeaderSigned') {
        const cfg = await chrome.storage.sync.get(Object.keys(DEFAULTS));
        const config = { ...DEFAULTS, ...cfg };

        const signRes = await fetch(`${config.baseUrl}/api/messages/sign`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: config.identityId,
            to: msg.to || '',
            body: msg.body || '',
            keyId: config.keyId
          })
        });

        const signPayload = await signRes.json();
        if (!signRes.ok || !signPayload?.success || !signPayload?.message) {
          sendResponse({ ok: false, error: signPayload?.reason || 'hip_sign_failed', details: signPayload });
          return;
        }

        const signed = signPayload.message;
        const token = await getAuthToken(true);

        const mime = [
          `To: ${msg.to}`,
          `Subject: ${msg.subject || '(no subject)'}`,
          'Content-Type: text/plain; charset="UTF-8"',
          `X-HIP-Signature: ${signed.signatureBase64}`,
          `X-HIP-Identity: ${signed.from}`,
          `X-HIP-KeyId: ${signed.keyId || ''}`,
          `X-HIP-MessageId: ${signed.id}`,
          `X-HIP-IssuedAt: ${signed.createdAtUtc || ''}`,
          '',
          msg.body || ''
        ].join('\r\n');

        const gmailRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ raw: b64urlUtf8(mime) })
        });

        const gmailPayload = await gmailRes.json();
        sendResponse({ ok: gmailRes.ok, status: gmailRes.status, payload: gmailPayload, signedMessage: signed });
        return;
      }

      sendResponse({ ok: false, error: 'unknown_message_type' });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();

  return true;
});
