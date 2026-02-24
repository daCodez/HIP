(() => {
  const BTN_CLASS = 'hip-sign-btn-outlook';
  const BADGE_CLASS = 'hip-verify-badge-outlook';

  function findComposeBodies() {
    return Array.from(document.querySelectorAll('div[aria-label="Message body"], div[role="textbox"]'));
  }

  function findReadableBodies() {
    return Array.from(document.querySelectorAll('div[role="document"], div[data-app-section="MailReadCompose"] div[dir="ltr"]'));
  }

  function parseSignedMessage(text) {
    const marker = 'HIP-Signature:';
    const idx = text.indexOf(marker);
    if (idx < 0) return null;

    const after = text.slice(idx + marker.length).trim();
    const start = after.indexOf('{');
    const end = after.lastIndexOf('}');
    if (start < 0 || end < start) return null;

    const jsonText = after.slice(start, end + 1);
    try {
      return JSON.parse(jsonText);
    } catch {
      return null;
    }
  }

  function makeBadge(text, color) {
    const badge = document.createElement('div');
    badge.className = BADGE_CLASS;
    badge.textContent = text;
    badge.style.marginTop = '8px';
    badge.style.padding = '6px 10px';
    badge.style.borderRadius = '6px';
    badge.style.background = color;
    badge.style.color = '#fff';
    badge.style.fontSize = '12px';
    badge.style.display = 'inline-block';
    return badge;
  }

  async function verifyIfSigned(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipVerifyChecked === '1') return;
    const text = bodyEl.innerText || '';
    const signed = parseSignedMessage(text);
    if (!signed) {
      bodyEl.dataset.hipVerifyChecked = '1';
      return;
    }

    const res = await chrome.runtime.sendMessage({ type: 'hip:verify', signedMessage: signed });
    let badge;
    if (res?.ok && res?.payload?.isValid) {
      badge = makeBadge('HIP Signature: VALID', '#0a7b32');
    } else {
      const reason = res?.payload?.reason || res?.error || 'unknown';
      badge = makeBadge(`HIP Signature: INVALID (${reason})`, '#b32727');
    }

    bodyEl.appendChild(badge);
    bodyEl.dataset.hipVerifyChecked = '1';
  }

  function injectButton(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipButtonAttached === '1') return;

    const commandBar = bodyEl.closest('[role="dialog"]')?.querySelector('[role="toolbar"]');
    if (!commandBar) return;

    const btn = document.createElement('button');
    btn.textContent = 'Sign with HIP';
    btn.className = BTN_CLASS;
    btn.style.marginLeft = '8px';
    btn.style.padding = '6px 10px';
    btn.style.borderRadius = '6px';
    btn.style.border = '1px solid #ccc';
    btn.style.background = '#fff';
    btn.style.cursor = 'pointer';

    btn.addEventListener('click', async () => {
      const plainText = bodyEl.innerText || '';
      const response = await chrome.runtime.sendMessage({ type: 'hip:sign', body: plainText });
      if (!response?.ok || !response?.payload?.success || !response?.payload?.message) {
        alert(`HIP sign failed: ${response?.payload?.reason || response?.error || 'unknown'}`);
        return;
      }

      const signed = response.payload.message;
      const stamp = `\n\n---\nHIP-Signature:\n${JSON.stringify(signed, null, 2)}\n`;
      bodyEl.innerText = plainText + stamp;
      alert('HIP signature inserted.');
    });

    commandBar.appendChild(btn);
    bodyEl.dataset.hipButtonAttached = '1';
  }

  const observer = new MutationObserver(() => {
    findComposeBodies().forEach(injectButton);
    findReadableBodies().forEach(verifyIfSigned);
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
